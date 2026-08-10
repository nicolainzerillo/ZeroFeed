package relay_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestRelayRateLimiting(t *testing.T) {
	rl := relay.NewRateLimiter()
	ip := "192.168.1.100:1234"

	if rl.IsBanned(ip) {
		t.Fatalf("expected IP not banned initially")
	}

	rl.RecordFailure(ip)
	rl.RecordFailure(ip)
	if rl.IsBanned(ip) {
		t.Fatalf("expected IP not banned after 2 failures")
	}

	rl.RecordFailure(ip)
	if !rl.IsBanned(ip) {
		t.Fatalf("expected IP banned after 3 failures")
	}

	rl.RecordSuccess(ip)
	if rl.IsBanned(ip) {
		t.Fatalf("expected IP unbanned after RecordSuccess")
	}
}

func TestRelayServerStreamForwarding(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	addr := srv.Addr()

	sessionID := [protocol.SessionIDSize]byte{0x01, 0x02, 0x03, 0x04}

	// 1. Dial Publisher
	pubConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial pub: %v", err)
	}
	defer pubConn.Close()

	pubEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: sessionID,
		Payload:   []byte("pub-init"),
	}
	if err := protocol.Encode(pubConn, pubEnv); err != nil {
		t.Fatalf("failed to send pub env: %v", err)
	}

	// 2. Dial Subscriber
	subConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial sub: %v", err)
	}
	defer subConn.Close()

	subEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitSub,
		SessionID: sessionID,
		Payload:   []byte("sub-init"),
	}
	if err := protocol.Encode(subConn, subEnv); err != nil {
		t.Fatalf("failed to send sub env: %v", err)
	}

	// Read subEnv forwarded to pubConn
	receivedByPub, err := protocol.Decode(pubConn)
	if err != nil {
		t.Fatalf("pub failed to receive sub init: %v", err)
	}
	if string(receivedByPub.Payload) != "sub-init" {
		t.Fatalf("expected 'sub-init', got '%s'", string(receivedByPub.Payload))
	}

	// 3. Publisher sends DataStream
	dataEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: sessionID,
		Payload:   []byte("hello subscriber"),
	}
	if err := protocol.Encode(pubConn, dataEnv); err != nil {
		t.Fatalf("pub failed to send data: %v", err)
	}

	// Read dataEnv from subConn
	receivedBySub, err := protocol.Decode(subConn)
	if err != nil {
		t.Fatalf("sub failed to receive data: %v", err)
	}
	if string(receivedBySub.Payload) != "hello subscriber" {
		t.Fatalf("expected 'hello subscriber', got '%s'", string(receivedBySub.Payload))
	}

	time.Sleep(50 * time.Millisecond)
}

func TestRelaySubscriberFirstConnectionOrdering(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	addr := srv.Addr()

	sessionID := [protocol.SessionIDSize]byte{0x0A, 0x0B, 0x0C, 0x0D}

	// 1. Dial Subscriber FIRST
	subConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial sub: %v", err)
	}
	defer subConn.Close()

	subEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitSub,
		SessionID: sessionID,
		Payload:   []byte("sub-first-init"),
	}
	if err := protocol.Encode(subConn, subEnv); err != nil {
		t.Fatalf("failed to send sub env: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// 2. Dial Publisher SECOND
	pubConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial pub: %v", err)
	}
	defer pubConn.Close()

	pubEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: sessionID,
		Payload:   []byte("pub-second-init"),
	}
	if err := protocol.Encode(pubConn, pubEnv); err != nil {
		t.Fatalf("failed to send pub env: %v", err)
	}

	// Read subEnv forwarded to pubConn upon publisher registration
	receivedByPub, err := protocol.Decode(pubConn)
	if err != nil {
		t.Fatalf("pub failed to receive sub-first init: %v", err)
	}
	if string(receivedByPub.Payload) != "sub-first-init" {
		t.Fatalf("expected 'sub-first-init', got '%s'", string(receivedByPub.Payload))
	}
}

func TestRelayUnsupportedProtocolVersionRejection(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	addr := srv.Addr()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial relay: %v", err)
	}
	defer conn.Close()

	// Send frame with Version 0x01 (below MinSupportedVersion 0x02)
	oldEnv := &protocol.Envelope{
		Version:   0x01,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: [protocol.SessionIDSize]byte{0x01},
		Payload:   []byte("old-client"),
	}
	if err := protocol.Encode(conn, oldEnv); err != nil {
		t.Fatalf("failed to send old env: %v", err)
	}

	// Relay should send MsgTypeClose frame with version rejection payload
	resp, err := protocol.Decode(conn)
	if err != nil {
		t.Fatalf("failed to receive response from relay: %v", err)
	}

	if resp.MsgType != protocol.MsgTypeClose {
		t.Errorf("expected MsgTypeClose, got %d", resp.MsgType)
	}

	if !bytes.Contains(resp.Payload, []byte("unsupported protocol version")) {
		t.Errorf("expected payload to explain unsupported version, got: %s", string(resp.Payload))
	}
}

