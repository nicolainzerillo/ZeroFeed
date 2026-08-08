//go:build quic

package relay

import (
	"context"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

// StartQUIC binds to the UDP port and serves requests over QUIC transport until context cancellation.
func (srv *Server) StartQUIC(ctx context.Context) error {
	tlsConfig, err := transport.GenerateEphemeralTLSConfig()
	if err != nil {
		return fmt.Errorf("zerofeed/relay: failed to generate TLS config for QUIC: %w", err)
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 5 * time.Second,
	}

	quicListener, err := quic.ListenAddr(srv.listenAddr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("zerofeed/relay: failed to bind QUIC listener on %s: %w", srv.listenAddr, err)
	}

	srv.mu.Lock()
	srv.listenAddr = quicListener.Addr().String()
	srv.mu.Unlock()
	srv.readyOnce.Do(func() { close(srv.ready) })

	go func() {
		<-ctx.Done()
		_ = quicListener.Close()
	}()

	for {
		qConn, err := quicListener.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		go srv.handleQuicConn(ctx, qConn)
	}
}

func (srv *Server) handleQuicConn(ctx context.Context, qConn *quic.Conn) {
	for {
		stream, err := qConn.AcceptStream(ctx)
		if err != nil {
			return
		}

		if srv.activeConns.Load() >= MaxActiveConnections {
			_ = stream.Close()
			continue
		}

		srv.activeConns.Add(1)
		wrapper := transport.NewQuicStreamWrapper(stream, qConn)
		go func() {
			defer srv.activeConns.Add(-1)
			srv.handleConnection(wrapper)
		}()
	}
}
