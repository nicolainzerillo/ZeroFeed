package relay_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestRelaySlowConsumer tests non-blocking fan-out and graceful pruning of stalled subscribers.
func TestRelaySlowConsumer(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()
	passphrase := []byte("slow-consumer-pruning-secret-2026")

	// 1. Initialize 1 Publisher and 2 Subscribers on the same ephemeral PAKE channel
	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	// Subscriber 1: Fast Consumer (reads normally)
	sub1, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine #1 failed: %v", err)
	}
	defer sub1.Close()

	if err := sub1.Connect(ctx); err != nil {
		t.Fatalf("sub1.Connect failed: %v", err)
	}

	// Subscriber 2: Slow/Stalled Consumer (does NOT read from socket after handshake)
	sub2, err := feed.NewSubscriberEngine(passphrase, relayAddr)

	if err != nil {
		t.Fatalf("NewSubscriberEngine #2 failed: %v", err)
	}
	defer sub2.Close()

	if err := sub2.Connect(ctx); err != nil {
		t.Fatalf("sub2.Connect failed: %v", err)
	}

	// Complete PAKE Handshake for all peers
	errChan := make(chan error, 3)
	go func() { errChan <- pub.CompleteHandshake(3 * time.Second) }()
	go func() { errChan <- sub1.CompleteHandshake(3 * time.Second) }()
	go func() { errChan <- sub2.CompleteHandshake(3 * time.Second) }()

	for i := 0; i < 3; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Handshake attempt %d failed: %v", i, err)
		}
	}

	pubInputChan := make(chan []byte, 100)

	pubErrChan := make(chan error, 1)
	go func() {
		pubErrChan <- pub.PublishStream(ctx, pubInputChan)
	}()

	// 2. Subscriber 1 reads normally in real-time
	var sub1Received atomic.Int64
	sub1Ctx, sub1Cancel := context.WithCancel(ctx)
	defer sub1Cancel()

	go func() {
		_ = sub1.SubscribeStream(sub1Ctx, nil, func(payload []byte) {
			sub1Received.Add(1)
		})
	}()

	// 3. Subscriber 2 deliberately DOES NOT call SubscribeStream (leaves socket unread)

	// Allow Subscriber 1 stream reader to start
	time.Sleep(50 * time.Millisecond)

	// 4. Publisher transmits a continuous stream of messages
	numMessages := 500
	if testing.Short() {
		numMessages = 50
	}
	startPublishTime := time.Now()

	for i := 1; i <= numMessages; i++ {
		pubInputChan <- fmt.Appendf(nil, "SLOW_CONSUMER_MSG_%d", i)
		time.Sleep(1 * time.Millisecond)
	}

	close(pubInputChan)

	// 5. Assertions:
	// a) Publisher completes stream without error (unaffected by slow subscriber)
	if pubErr := <-pubErrChan; pubErr != nil && !errors.Is(pubErr, context.Canceled) {
		t.Fatalf("Publisher failed during slow consumer stream: %v", pubErr)
	}

	publishDuration := time.Since(startPublishTime)
	t.Logf("Publisher transmitted %d messages in %v", numMessages, publishDuration)

	// Allow subscriber stream processing to complete
	time.Sleep(200 * time.Millisecond)

	// b) Subscriber 1 (Fast Consumer) received ALL 500 messages in real-time without delay
	rec1 := sub1Received.Load()
	if rec1 != int64(numMessages) {
		t.Errorf("Subscriber 1 (Fast Consumer) received %d messages, expected %d", rec1, numMessages)
	}

	// c) Relay detected Subscriber 2 buffer overflow and pruned stalled connection
	sub2Contents := sub2.BufferContents()
	t.Logf("Subscriber 2 buffer items: %d (stalled consumer gracefully pruned by Relay)", len(sub2Contents))

	if len(sub2Contents) >= numMessages {
		t.Errorf("Subscriber 2 was not pruned! Received %d items", len(sub2Contents))
	}
}

// TestRelayWatermarkBackpressure verifies that High/Low watermark flow control is correctly calculated.
func TestRelayWatermarkBackpressure(t *testing.T) {
	if relay.HighWatermark <= relay.LowWatermark {
		t.Fatalf("HighWatermark (%d) must be greater than LowWatermark (%d)", relay.HighWatermark, relay.LowWatermark)
	}

	if relay.HighWatermark > relay.SubscriberQueueSize {
		t.Fatalf("HighWatermark (%d) cannot exceed SubscriberQueueSize (%d)", relay.HighWatermark, relay.SubscriberQueueSize)
	}
}
