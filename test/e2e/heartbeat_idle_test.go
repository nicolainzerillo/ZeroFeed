package e2e_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestHeartbeatKeepaliveAndIdleCleanup tests periodic heartbeat frames and silent idle session cleanup.
func TestHeartbeatKeepaliveAndIdleCleanup(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatalf("failed to dial relay: %v", err)
	}
	defer conn.Close()

	var sessionID [protocol.SessionIDSize]byte
	copy(sessionID[:], []byte("idle-heartbeat16"))

	// 1. Send PAKEInitPub to create a session
	initEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: sessionID,
		Payload:   make([]byte, 32),
	}
	if err := protocol.Encode(conn, initEnv); err != nil {
		t.Fatalf("failed to encode initEnv: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify session was registered
	if srv.SessionCount() != 1 {
		t.Fatalf("expected 1 active session in relay, got %d", srv.SessionCount())
	}

	// 2. Send 3 periodic MsgTypeHeartbeat keepalive ping frames
	for i := 1; i <= 3; i++ {
		hbEnv := &protocol.Envelope{
			Version:   protocol.Version,
			MsgType:   protocol.MsgTypeHeartbeat,
			SessionID: sessionID,
		}
		if err := protocol.Encode(conn, hbEnv); err != nil {
			t.Fatalf("failed to encode heartbeat frame %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify session remains active during keepalive
	if srv.SessionCount() != 1 {
		t.Fatalf("expected session to remain active after heartbeats, got %d", srv.SessionCount())
	}

	// 3. Forcibly close TCP connection (simulate silent peer drop)
	_ = conn.Close()
	time.Sleep(150 * time.Millisecond)

	// Verify dead peer session was cleaned up and resources released
	if srv.SessionCount() != 0 {
		t.Fatalf("expected active sessions count to return to 0 after socket close, got %d", srv.SessionCount())
	}
}
