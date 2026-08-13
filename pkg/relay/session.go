package relay

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
)

// subKeyCounter yields a process-unique suffix so subscriber map keys never
// collide even when several clients share one source address (e.g. all sitting
// behind the same reverse proxy under --trust-proxy).
var subKeyCounter atomic.Uint64

const (
	SubscriberQueueSize = 200
	HighWatermark       = 160 // 80% capacity trigger
	LowWatermark        = 80  // 40% capacity resume
)

// ClientConn wraps a relay peer connection with an asynchronous non-blocking send channel.
type ClientConn struct {
	netConn    net.Conn
	role       uint8 // 1 = Publisher, 2 = Subscriber
	initialEnv *protocol.Envelope
	sendCh     chan *protocol.Envelope
	closeOnce  sync.Once
	done       chan struct{}
	writeMu    sync.Mutex
}

// NewClientConn creates a ClientConn with a non-blocking queue.
func NewClientConn(conn net.Conn, role uint8, initialEnv *protocol.Envelope) *ClientConn {
	c := &ClientConn{
		netConn:    conn,
		role:       role,
		initialEnv: initialEnv,
		sendCh:     make(chan *protocol.Envelope, SubscriberQueueSize),
		done:       make(chan struct{}),
	}

	if role == 2 {
		go c.writeLoop()
	}

	return c
}

// IsClosed reports whether this connection has been closed. It reads only the
// done channel, so it is safe to call while another goroutine is reading the
// underlying socket.
func (c *ClientConn) IsClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// QueueLen returns the current number of buffered envelopes in subscriber send queue.
func (c *ClientConn) QueueLen() int {
	if c.role != 2 {
		return 0
	}
	return len(c.sendCh)
}

// IsHighWatermark returns true if subscriber queue is at or above HighWatermark.
func (c *ClientConn) IsHighWatermark() bool {
	return c.QueueLen() >= HighWatermark
}

// IsLowWatermark returns true if subscriber queue is at or below LowWatermark.
func (c *ClientConn) IsLowWatermark() bool {
	return c.QueueLen() <= LowWatermark
}

// WaitForDrain blocks until subscriber queue drains to LowWatermark or until timeout.
func (c *ClientConn) WaitForDrain(timeout time.Duration) {
	if c.role != 2 || c.IsLowWatermark() {
		return
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.IsLowWatermark() {
			return
		}
		select {
		case <-c.done:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (c *ClientConn) writeLoop() {
	for {
		select {
		case <-c.done:
			_ = c.netConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			for {
				select {
				case env := <-c.sendCh:
					_ = protocol.Encode(c.netConn, env)
				default:
					return
				}
			}
		case env, ok := <-c.sendCh:
			if !ok {
				return
			}
			_ = c.netConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := protocol.Encode(c.netConn, env); err != nil {
				c.Close()
				return
			}
			_ = c.netConn.SetWriteDeadline(time.Time{})
		}
	}
}

// SendFrame enqueues a frame for transmission. Applies backpressure with a 5-second timeout for subscribers.
func (c *ClientConn) SendFrame(env *protocol.Envelope) error {
	return c.SendFrameWithTimeout(env, 5*time.Second)
}

// SendFrameWithTimeout enqueues a frame for transmission with a specified backpressure timeout.
func (c *ClientConn) SendFrameWithTimeout(env *protocol.Envelope, timeout time.Duration) error {
	if c.role == 2 {
		if timeout == 0 {
			select {
			case c.sendCh <- env:
				return nil
			default:
				return fmt.Errorf("zerofeed/relay: subscriber queue full (slow consumer)")
			}
		}

		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case c.sendCh <- env:
			return nil
		case <-c.done:
			return fmt.Errorf("zerofeed/relay: subscriber closed")
		case <-timer.C:
			return fmt.Errorf("zerofeed/relay: subscriber queue full timeout (slow consumer)")
		}
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_ = c.netConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer c.netConn.SetWriteDeadline(time.Time{})
	return protocol.Encode(c.netConn, env)
}

// Close gracefully closes net.Conn.
func (c *ClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.role == 2 {
			go func() {
				time.Sleep(20 * time.Millisecond)
				_ = c.netConn.Close()
			}()
		} else {
			_ = c.netConn.Close()
		}
	})
	return nil
}

// RelaySession manages an in-memory session matching Publisher and Subscriber(s).
type RelaySession struct {
	sessionID   [protocol.SessionIDSize]byte
	publisher   *ClientConn
	subscribers map[string]*ClientConn
	createdAt   time.Time
	mu          sync.RWMutex
	closed      bool
}

// sessionGracePeriod is how long a freshly created session is kept even while
// empty. getOrCreateSession returns before the caller registers its publisher or
// subscriber, so without a grace period the reaper can delete a session in that
// window and the two peers then build separate sessions and never meet.
const sessionGracePeriod = 30 * time.Second

// NewRelaySession creates a new ephemeral in-memory session.
func NewRelaySession(sessionID [protocol.SessionIDSize]byte) *RelaySession {
	return &RelaySession{
		sessionID:   sessionID,
		subscribers: make(map[string]*ClientConn),
		createdAt:   time.Now(),
	}
}

// IsEmpty returns true if there is no active publisher and no active subscribers.
func (s *RelaySession) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return true
	}
	hasPub := s.publisher != nil && s.publisher.netConn != nil
	hasSubs := len(s.subscribers) > 0
	return !hasPub && !hasSubs
}

// IsReapable reports whether the session is empty and old enough to discard.
// Sessions inside sessionGracePeriod are kept even when empty, so a session
// created for a peer that has not finished registering is not torn down.
func (s *RelaySession) IsReapable() bool {
	s.mu.RLock()
	createdAt := s.createdAt
	s.mu.RUnlock()

	if !s.IsEmpty() {
		return false
	}
	return time.Since(createdAt) >= sessionGracePeriod
}

// RegisterPublisher sets the publisher for this session after inspecting liveness of any existing connection.
func (s *RelaySession) RegisterPublisher(conn net.Conn, env *protocol.Envelope) *ClientConn {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publisher != nil && s.publisher.netConn != nil {
		// Do NOT read the existing socket to probe liveness: its loopPublisher
		// goroutine is already reading it, and a stolen byte would desync the
		// framed protocol. Rely on the connection's own teardown signal instead.
		// A dead publisher's read loop closes the ClientConn (and tears down the
		// session) on its next failed Decode or the 5-minute read deadline.
		if !s.publisher.IsClosed() {
			// Existing publisher still active — reject the duplicate.
			_ = conn.Close()
			return nil
		}

		// Existing publisher already torn down — replace it.
		_ = s.publisher.Close()
		s.publisher = nil
	}

	pub := NewClientConn(conn, 1, env)
	s.publisher = pub
	return pub
}

// RegisterSubscriber adds a subscriber to this session, returning the key that
// identifies it in the session's subscriber map. The key is unique per
// connection: conn.RemoteAddr() is not, since behind a reverse proxy every
// client presents the proxy's address.
func (s *RelaySession) RegisterSubscriber(conn net.Conn, env *protocol.Envelope) (*ClientConn, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub := NewClientConn(conn, 2, env)
	key := fmt.Sprintf("%s#%d", conn.RemoteAddr().String(), subKeyCounter.Add(1))
	s.subscribers[key] = sub
	return sub, key
}

// RemoveSubscriber removes a subscriber connection.
func (s *RelaySession) RemoveSubscriber(addr string) {
	s.mu.Lock()
	sub, ok := s.subscribers[addr]
	if ok {
		delete(s.subscribers, addr)
	}
	s.mu.Unlock()

	if ok {
		_ = sub.Close()
	}
}

// ForwardFromPublisher broadcasts an encrypted frame from the Publisher to all active Subscribers.
// Applies watermark-driven backpressure: if any subscriber queue crosses HighWatermark,
// it pauses to allow the subscriber to drain below LowWatermark before reading the next publisher frame.
func (s *RelaySession) ForwardFromPublisher(env *protocol.Envelope) {
	s.mu.RLock()
	subs := make([]*ClientConn, 0, len(s.subscribers))
	addrs := make([]string, 0, len(s.subscribers))
	for addr, sub := range s.subscribers {
		subs = append(subs, sub)
		addrs = append(addrs, addr)
	}
	s.mu.RUnlock()

	var highWatermarkHit bool

	for i, sub := range subs {
		if err := sub.SendFrame(env); err != nil {
			addr := addrs[i]
			go s.RemoveSubscriber(addr)
		} else if sub.IsHighWatermark() {
			highWatermarkHit = true
		}
	}

	if highWatermarkHit {
		for _, sub := range subs {
			sub.WaitForDrain(500 * time.Millisecond)
		}
	}
}

// ForwardToPublisher forwards a frame from a Subscriber to the Publisher (e.g. PAKE response).
func (s *RelaySession) ForwardToPublisher(env *protocol.Envelope) error {
	s.mu.RLock()
	pub := s.publisher
	s.mu.RUnlock()

	if pub == nil {
		return fmt.Errorf("zerofeed/relay: publisher not connected for session %x", s.sessionID)
	}

	return pub.SendFrame(env)
}

// Close closes all client connections in this session and wipes references.
func (s *RelaySession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	if s.publisher != nil {
		_ = s.publisher.Close()
		s.publisher = nil
	}

	for _, sub := range s.subscribers {
		_ = sub.Close()
	}
	s.subscribers = make(map[string]*ClientConn)
}
