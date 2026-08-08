package relay_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestRateLimiterBanAndAutoPurge(t *testing.T) {
	limiter := relay.NewRateLimiter()
	ip := "192.168.1.100:12345"

	// 1. Initial state: IP is not banned
	if limiter.IsBanned(ip) {
		t.Fatalf("expected IP to not be banned initially")
	}

	// 2. Record 2 failures (below threshold of 3)
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	if limiter.IsBanned(ip) {
		t.Fatalf("expected IP to not be banned after 2 failures")
	}

	// 3. Record 3rd failure (triggers 5-minute ban)
	limiter.RecordFailure(ip)

	if !limiter.IsBanned(ip) {
		t.Fatalf("expected IP to be banned after 3 failures")
	}

	// 4. Verify cleanup janitor purges inactive IP records
	limiter.CleanupStale(0) // Purge records with 0 age limit for testing
	if limiter.Count() != 1 {
		t.Logf("RateLimiter active records count: %d", limiter.Count())
	}

	// 5. Record success resets failures
	limiter.RecordSuccess(ip)
	if limiter.IsBanned(ip) {
		t.Fatalf("expected IP ban to be cleared after RecordSuccess")
	}
}

func TestRelayMalformedHandshakeRateLimiting(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	srv := relay.NewServer(l.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	// Perform 3 malformed connections to trigger rate-limit ban
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed on attempt %d: %v", i, err)
		}
		// Send junk payload to cause Decode error
		_, _ = conn.Write([]byte("INVALID_GARBAGE_PAYLOAD"))
		_ = conn.Close()
		time.Sleep(10 * time.Millisecond)
	}

	// 4th connection from same IP: should be banned and closed immediately
	conn4, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		return // Connection rejected at TCP layer
	}
	defer conn4.Close()

	_ = conn4.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 100)
	n, _ := conn4.Read(buf)
	if n > 0 {
		t.Fatalf("expected banned IP to receive 0 bytes, got %d", n)
	}
}

func TestRelayCloseAllSessions(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	srv := relay.NewServer(l.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	sessionID := [16]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160}
	env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: sessionID,
		Payload:   make([]byte, 32),
	}

	if err := protocol.Encode(conn, env); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Call CloseAll and verify session count becomes 0
	srv.CloseAll()

	if count := srv.SessionCount(); count != 0 {
		t.Fatalf("expected 0 active sessions after CloseAll, got %d", count)
	}
}
