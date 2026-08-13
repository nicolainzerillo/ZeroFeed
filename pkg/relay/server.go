package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
)

const MaxActiveConnections = 10000

// Server represents an in-memory zero-knowledge TCP relay node.
type Server struct {
	listenAddr  string
	listener    net.Listener
	sessions    map[[protocol.SessionIDSize]byte]*RelaySession
	rateLimiter *RateLimiter
	trustProxy  bool
	metrics     *Metrics
	activeConns atomic.Int64
	mu          sync.RWMutex
	ready       chan struct{}
	readyOnce   sync.Once
}

// NewServer initializes a Relay server.
func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr:  listenAddr,
		sessions:    make(map[[protocol.SessionIDSize]byte]*RelaySession),
		rateLimiter: NewRateLimiter(),
		ready:       make(chan struct{}),
		metrics:     NewMetrics(),
	}
}

// DisableRateLimiting disables IP rate limiting (useful for benchmarks/stress tests on localhost).
func (srv *Server) DisableRateLimiting() {
	srv.rateLimiter.SetEnabled(false)
}

// Metrics returns the zero-knowledge metrics collector instance.
func (srv *Server) Metrics() *Metrics {
	return srv.metrics
}

// StartMetricsServer launches an HTTP server exporting Prometheus metrics at /metrics until context cancellation.
func (srv *Server) StartMetricsServer(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", srv.metrics.Handler())

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		_ = server.ListenAndServe()
	}()

	return nil
}

// StartWebSocketServer launches a zero-dependency WebSocket HTTP/HTTPS listener bridging browser clients to the Relay session router.
func (srv *Server) StartWebSocketServer(ctx context.Context, listenAddr string) error {
	return srv.StartWebSocketTLSServer(ctx, listenAddr, "", "")
}

// StartWebSocketTLSServer launches a WebSocket listener with optional TLS (WSS) bridging browser clients to the Relay.
func (srv *Server) StartWebSocketTLSServer(ctx context.Context, listenAddr string, certFile, keyFile string) error {
	if listenAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := UpgradeWebSocket(w, r)
		if err != nil {
			if strings.Contains(err.Error(), "origin not allowed") {
				http.Error(w, "Forbidden: Invalid Origin", http.StatusForbidden)
			} else {
				http.Error(w, "WebSocket Upgrade Failed", http.StatusBadRequest)
			}
			return
		}

		if srv.activeConns.Load() >= MaxActiveConnections {
			_ = wsConn.Close()
			return
		}

		srv.activeConns.Add(1)
		srv.metrics.ActiveConnections.Add(1)
		defer srv.activeConns.Add(-1)
		defer srv.metrics.ActiveConnections.Add(-1)

		srv.handleConnection(wsConn)
	})

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if certFile != "" && keyFile != "" {
			_ = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			_ = server.ListenAndServe()
		}
	}()

	return nil
}

// Addr returns the bound TCP listening address.
func (srv *Server) Addr() string {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	if srv.listener != nil {
		return srv.listener.Addr().String()
	}
	return srv.listenAddr
}

// Ready returns a channel that is closed when the server has successfully bound to its port.
func (srv *Server) Ready() <-chan struct{} {
	return srv.ready
}

// SetRateLimiting enables or disables IP rate limiting.
func (srv *Server) SetRateLimiting(enabled bool) {
	srv.rateLimiter.SetEnabled(enabled)
}

// SetTrustProxy enables or disables PROXY Protocol v2 header parsing.
func (srv *Server) SetTrustProxy(trust bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.trustProxy = trust
}

// Start binds to the TCP port and serves requests until context cancellation.
func (srv *Server) Start(ctx context.Context) error {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", srv.listenAddr)
	if err != nil {
		return fmt.Errorf("zerofeed/relay: failed to bind listener on %s: %w", srv.listenAddr, err)
	}

	srv.mu.Lock()
	srv.listener = l
	srv.mu.Unlock()
	srv.readyOnce.Do(func() { close(srv.ready) })

	go func() {
		<-ctx.Done()
		_ = l.Close()
		srv.CloseAll()
	}()

	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				srv.rateLimiter.CleanupStale(15 * time.Minute)
				srv.reapStaleSessions()
			}
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				continue
			}
		}

		if srv.activeConns.Load() >= MaxActiveConnections {
			_ = conn.Close()
			continue
		}

		srv.activeConns.Add(1)
		srv.metrics.ActiveConnections.Add(1)
		go func(c net.Conn) {
			defer srv.activeConns.Add(-1)
			defer srv.metrics.ActiveConnections.Add(-1)
			srv.handleConnection(c)
		}(conn)
	}
}

func (srv *Server) handleConnection(conn net.Conn) {
	srv.mu.RLock()
	isTrustProxy := srv.trustProxy
	srv.mu.RUnlock()

	remoteAddr := conn.RemoteAddr().String()
	if isTrustProxy {
		var err error
		conn, remoteAddr, err = ParseProxyHeaderV2(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
	}

	if srv.rateLimiter.IsBanned(remoteAddr) {
		srv.metrics.RateLimitBansTotal.Add(1)
		_ = conn.Close()
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := protocol.DecodeWithMax(conn, protocol.MaxHandshakePayload)
	if err != nil {
		if errors.Is(err, protocol.ErrUnsupportedVer) {
			closeEnv := &protocol.Envelope{
				Version: protocol.Version,
				MsgType: protocol.MsgTypeClose,
				Payload: fmt.Appendf(nil, "zerofeed/relay: unsupported protocol version (minimum required: 0x%02X)", protocol.MinSupportedVersion),
			}
			_ = protocol.Encode(conn, closeEnv)
		} else if !errors.Is(err, io.EOF) {
			srv.rateLimiter.RecordFailure(remoteAddr)
			srv.metrics.MalformedPacketsDroppedTotal.Add(1)
		}
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Only a handshake frame may create a session. Creating one for any other
	// frame type lets an unauthenticated peer grow the session map at will by
	// replaying frames with random session IDs.
	switch env.MsgType {
	case protocol.MsgTypePAKEInitPub:
		session := srv.getOrCreateSession(env.SessionID)
		client := session.RegisterPublisher(conn, env)
		if client == nil {
			_ = conn.Close()
			return
		}

		session.mu.RLock()
		for _, sub := range session.subscribers {
			if sub.initialEnv != nil {
				_ = client.SendFrame(sub.initialEnv)
			}
		}
		session.mu.RUnlock()

		srv.loopPublisher(session, client)

	case protocol.MsgTypePAKEInitSub:
		session := srv.getOrCreateSession(env.SessionID)
		client, subAddr := session.RegisterSubscriber(conn, env)

		session.mu.RLock()
		pub := session.publisher
		session.mu.RUnlock()

		if pub != nil {
			_ = pub.SendFrame(env)
		}

		srv.loopSubscriber(session, client, subAddr)

	case protocol.MsgTypeSyncReq:
		defer conn.Close()
		session := srv.lookupSession(env.SessionID)
		if session == nil {
			srv.rateLimiter.RecordFailure(remoteAddr)
			return
		}

		session.mu.RLock()
		pub := session.publisher
		session.mu.RUnlock()

		if pub != nil && pub.netConn != conn {
			_ = session.ForwardToPublisher(env)
		}

	default:
		// Unregistered connection sending non-handshake frame — drop safely without touching active session loops.
		_ = conn.Close()
		srv.rateLimiter.RecordFailure(remoteAddr)
		srv.metrics.MalformedPacketsDroppedTotal.Add(1)
	}
}

func (srv *Server) loopPublisher(session *RelaySession, pubClient *ClientConn) {
	if pubClient == nil {
		session.mu.RLock()
		pubClient = session.publisher
		session.mu.RUnlock()
	}

	if pubClient == nil {
		return
	}

	for {
		_ = pubClient.netConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		env, err := protocol.Decode(pubClient.netConn)
		if err != nil {
			break
		}
		_ = pubClient.netConn.SetReadDeadline(time.Time{})

		if env.MsgType == protocol.MsgTypeHeartbeat {
			continue // Maintain keepalive
		}

		if env.MsgType == protocol.MsgTypeClose {
			session.ForwardFromPublisher(env)
			break
		}

		srv.metrics.MessagesRelayedTotal.Add(1)
		srv.metrics.BytesTransferredTotal.Add(uint64(len(env.Payload)))
		session.ForwardFromPublisher(env)
	}

	srv.removeSession(session.sessionID)
}

func (srv *Server) loopSubscriber(session *RelaySession, subClient *ClientConn, subAddr string) {
	for {
		_ = subClient.netConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		env, err := protocol.Decode(subClient.netConn)
		if err != nil {
			break
		}
		_ = subClient.netConn.SetReadDeadline(time.Time{})

		if env.MsgType == protocol.MsgTypeHeartbeat {
			continue // Maintain keepalive
		}

		if env.MsgType == protocol.MsgTypeSyncReq || env.MsgType == protocol.MsgTypeKeyConfirm || env.MsgType == protocol.MsgTypeChunkAck {
			_ = session.ForwardToPublisher(env)
		}
	}

	session.RemoveSubscriber(subAddr)
	session.mu.RLock()
	isEmpty := session.publisher == nil && len(session.subscribers) == 0
	session.mu.RUnlock()
	if isEmpty {
		srv.removeSession(session.sessionID)
	}
}

func (srv *Server) getOrCreateSession(sessionID [protocol.SessionIDSize]byte) *RelaySession {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	session, ok := srv.sessions[sessionID]
	if !ok {
		session = NewRelaySession(sessionID)
		srv.sessions[sessionID] = session
		srv.metrics.ActiveSessions.Add(1)
		srv.metrics.SessionsCreatedTotal.Add(1)
	}

	return session
}

// lookupSession returns the session for sessionID, or nil if none exists. Use
// this for frames that must not be able to create a session.
func (srv *Server) lookupSession(sessionID [protocol.SessionIDSize]byte) *RelaySession {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	return srv.sessions[sessionID]
}

func (srv *Server) removeSession(sessionID [protocol.SessionIDSize]byte) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if session, ok := srv.sessions[sessionID]; ok {
		session.Close()
		delete(srv.sessions, sessionID)
		srv.metrics.ActiveSessions.Add(-1)
	}
}

// Close terminates the TCP listener and closes all active relay sessions.
func (srv *Server) Close() error {
	srv.mu.Lock()
	if srv.listener != nil {
		_ = srv.listener.Close()
	}
	srv.mu.Unlock()

	srv.CloseAll()
	return nil
}

// CloseAll closes all active relay sessions and purges memory.
func (srv *Server) CloseAll() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	for sessionID, session := range srv.sessions {
		session.Close()
		delete(srv.sessions, sessionID)
	}
}

// SessionCount returns the current number of active relay sessions.
func (srv *Server) SessionCount() int {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	return len(srv.sessions)
}

// reapStaleSessions removes empty/orphaned sessions that have no active publisher or subscriber connections.
func (srv *Server) reapStaleSessions() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	for id, sess := range srv.sessions {
		if sess.IsReapable() {
			sess.Close()
			delete(srv.sessions, id)
			srv.metrics.ActiveSessions.Add(-1)
		}
	}
}
