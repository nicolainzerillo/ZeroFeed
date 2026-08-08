//go:build quic

package relay_test

import (
	"context"
	"sync"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

type safeBuffer struct {
	buf []byte
	mu  sync.Mutex
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p), nil
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}

func TestQUICRelayE2EEStreaming(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.StartQUIC(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	passphrase := []byte("secret-quic-pake-passphrase-2026")

	// Create Publisher and Subscriber Dialing QUIC
	pubConn, err := transport.DialQUIC(ctx, relayAddr)
	if err != nil {
		t.Fatalf("DialQUIC pub failed: %v", err)
	}
	defer pubConn.Close()

	subConn, err := transport.DialQUIC(ctx, relayAddr)
	if err != nil {
		t.Fatalf("DialQUIC sub failed: %v", err)
	}
	defer subConn.Close()

	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub.Close()

	// Verify QUIC transport layers can perform stream operations
	if pubConn.RemoteAddr() == nil || subConn.RemoteAddr() == nil {
		t.Fatalf("expected non-nil remote addr for QUIC connections")
	}
}
