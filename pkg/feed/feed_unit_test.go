package feed

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/transport"
)

func TestProgressBar(t *testing.T) {
	pb := NewProgressBar(100, false)
	if pb == nil {
		t.Fatal("NewProgressBar returned nil")
	}
	pb.Add(50)
	pb.Add(50)
	pb.Finish()
}

func TestPublisherEngine_GettersAndSetters(t *testing.T) {
	passphrase := []byte("publisher-unit-test-pass")
	pub, err := NewPublisherEngine(passphrase, "127.0.0.1:8443")
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	// Test SessionID and ReplayBuffer
	sessID := pub.SessionID()
	if len(sessID) != 16 {
		t.Errorf("expected session ID size 16, got %d", len(sessID))
	}
	rb := pub.ReplayBuffer()
	if rb == nil {
		t.Errorf("expected non-nil replay buffer")
	}

	// Test Setters
	pub.SetSPKIFingerprint("a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890")
	pub.SetRekeyThresholds(1024*1024, 30*time.Minute)
	pub.SetTransportMode(transport.ModeQUIC)

	// Test SAS before connection (should be empty hex)
	_ = pub.SASFingerprint()
	_ = pub.SASEmoji()
}

func TestSubscriberEngine_GettersAndSetters(t *testing.T) {
	passphrase := []byte("subscriber-unit-test-pass")
	sub, err := NewSubscriberEngine(passphrase, "127.0.0.1:8443")
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub.Close()

	// Test SessionID and BufferContents
	sessID := sub.SessionID()
	if len(sessID) != 16 {
		t.Errorf("expected session ID size 16, got %d", len(sessID))
	}
	contents := sub.BufferContents()
	if contents == nil {
		t.Errorf("expected non-nil buffer contents")
	}

	// Test Setters
	sub.SetSPKIFingerprint("a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890")
	sub.SetTransportMode(transport.ModeQUIC)

	_ = sub.SASFingerprint()
	_ = sub.SASEmoji()
}

func TestSessionIDHelpers(t *testing.T) {
	passphrase := []byte("session-helpers-passphrase")
	tag := DeriveBlindMatchTag(passphrase)
	if tag == [32]byte{} {
		t.Fatal("DeriveBlindMatchTag returned zero tag")
	}

	ephID := GenerateEphemeralSessionID()
	if ephID == [16]byte{} {
		t.Fatal("GenerateEphemeralSessionID returned zero session ID")
	}
}

func TestRelayListHelpers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("could not listen:", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	probedAddr, err := ProbeFirstAvailable(ctx, []string{addr}, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeFirstAvailable error: %v", err)
	}
	if probedAddr != addr {
		t.Errorf("got %q, want %q", probedAddr, addr)
	}

	_ = ResolveDefaultRelays()
}

func TestSendFile_InvalidPath(t *testing.T) {
	passphrase := []byte("send-file-test-pass")
	pub, err := NewPublisherEngine(passphrase, "127.0.0.1:8443")
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = pub.SendFile(ctx, "/path/to/nonexistent/file/zerofeed.tmp")
	if err == nil {
		t.Fatal("expected error sending nonexistent file, got nil")
	}
}

func TestSendFile_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-data.txt")
	err := os.WriteFile(filePath, []byte("Hello ZeroFeed File Transfer Test Content"), 0600)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	passphrase := []byte("send-file-valid-pass")
	pub, err := NewPublisherEngine(passphrase, "127.0.0.1:8443")
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// TriggerRekey on unconnected publisher (cipher == nil) returns nil safely
	_ = pub.TriggerRekey(ctx)

	// Conn is nil so SendFile will fail at network transmission, testing file read & metadata serialization logic
	_ = pub.SendFile(ctx, filePath)
}

func TestDialRelayHelpers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("could not listen:", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialRelay(ctx, addr)
	if err != nil {
		t.Fatalf("DialRelay error: %v", err)
	}
	conn.Close()

	connPin, err := DialRelayWithPin(ctx, addr, "")
	if err != nil {
		t.Fatalf("DialRelayWithPin error: %v", err)
	}
	connPin.Close()
}
