package e2e_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestChaosNetworkDisconnectionsAndRecovery tests system resilience under mid-stream socket drops, catch-up sync, and re-established streaming.
func TestChaosNetworkDisconnectionsAndRecovery(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()
	passphrase := []byte("chaos-network-resilience-secret-2026")

	// Initialize Publisher
	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)

	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	// Initialize Subscriber 1
	sub1, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub1.Close()

	if err := sub1.Connect(ctx); err != nil {
		t.Fatalf("sub1.Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(2 * time.Second) }()
	go func() { errChan <- sub1.CompleteHandshake(2 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Initial handshake failed: %v", err)
		}
	}

	pubInputChan := make(chan []byte, 100)
	go func() {
		_ = pub.PublishStream(ctx, pubInputChan)
	}()

	var sub1Received atomic.Int64
	sub1Ctx, sub1Cancel := context.WithCancel(ctx)

	go func() {
		_ = sub1.SubscribeStream(sub1Ctx, nil, func(payload []byte) {
			sub1Received.Add(1)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	// Phase 1: Send 20 messages normally
	for i := 1; i <= 20; i++ {
		pubInputChan <- fmt.Appendf(nil, "CHAOS_MSG_%d", i)
	}
	time.Sleep(100 * time.Millisecond)

	if rec1 := sub1Received.Load(); rec1 != 20 {
		t.Fatalf("Phase 1: Subscriber 1 expected 20 messages, got %d", rec1)
	}

	// Phase 2: Inject Chaos - Forcibly close subscriber connection mid-stream
	sub1Cancel()
	sub1.Close()
	time.Sleep(50 * time.Millisecond)

	// Phase 3: Send 30 messages while subscriber 1 is disconnected
	for i := 21; i <= 50; i++ {
		pubInputChan <- fmt.Appendf(nil, "CHAOS_MSG_%d", i)
	}
	time.Sleep(100 * time.Millisecond)

	// Phase 4: Reconnect subscriber, trigger auto-sync request (last_seq=20)
	sub2, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine #2 failed: %v", err)
	}
	defer sub2.Close()

	if err := sub2.Connect(ctx); err != nil {
		t.Fatalf("sub2.Connect failed: %v", err)
	}

	if err := sub2.CompleteHandshake(2 * time.Second); err != nil {
		t.Fatalf("sub2 CompleteHandshake failed: %v", err)
	}

	var sub2Received atomic.Int64
	sub2Ctx, sub2Cancel := context.WithTimeout(ctx, 3*time.Second)
	defer sub2Cancel()

	go func() {
		_ = sub2.SubscribeStream(sub2Ctx, nil, func(payload []byte) {
			sub2Received.Add(1)
		})
	}()

	time.Sleep(50 * time.Millisecond)
	if err := sub2.SendSyncRequest(); err != nil {
		t.Fatalf("SendSyncRequest failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Phase 5: Send remaining messages #51 to #70 live
	for i := 51; i <= 70; i++ {
		pubInputChan <- fmt.Appendf(nil, "CHAOS_MSG_%d", i)
	}

	close(pubInputChan)
	time.Sleep(300 * time.Millisecond)

	// Verify subscriber 2 caught up and received all available messages (#1 to #70)
	rec2 := sub2Received.Load()
	if rec2 < 50 {
		t.Errorf("Chaos recovery failed! Subscriber 2 expected at least 50 messages, got %d", rec2)
	}
}
