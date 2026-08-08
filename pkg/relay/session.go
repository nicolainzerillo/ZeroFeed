package relay

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
)

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
	mu          sync.RWMutex
	closed      bool
}

// NewRelaySession creates a new ephemeral in-memory session.
func NewRelaySession(sessionID [protocol.SessionIDSize]byte) *RelaySession {
	return &RelaySession{
		sessionID:   sessionID,
		subscribers: make(map[string]*ClientConn),
	}
}

// RegisterPublisher sets the publisher for this session after inspecting liveness of any existing connection.
func (s *RelaySession) RegisterPublisher(conn net.Conn, env *protocol.Envelope) *ClientConn {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.publisher != nil && s.publisher.netConn != nil {
		// Probe existing publisher connection liveness with deadline
		_ = s.publisher.netConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		var oneByte [1]byte
		_, err := s.publisher.netConn.Read(oneByte[:])
		_ = s.publisher.netConn.SetReadDeadline(time.Time{})

		// If connection is active and responsive, reject duplicate registration
		if err == nil {
			_ = conn.Close()
			return nil
		}

		// Clean up dead connection
		_ = s.publisher.Close()
		s.publisher = nil
	}

	pub := NewClientConn(conn, 1, env)
	s.publisher = pub
	return pub
}

// RegisterSubscriber adds a subscriber to this session.
func (s *RelaySession) RegisterSubscriber(conn net.Conn, env *protocol.Envelope) (*ClientConn, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub := NewClientConn(conn, 2, env)
	addr := conn.RemoteAddr().String()
	s.subscribers[addr] = sub
	return sub, addr
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
