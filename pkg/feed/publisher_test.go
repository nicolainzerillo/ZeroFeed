package feed_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestHighLoadFanOut tests high-concurrency fan-out (1 Publisher to 50 Subscribers sending 1,000 messages at 1ms intervals).
func TestHighLoadFanOut(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	passphrase := []byte("high-load-fanout-pake-passphrase-2026")
	numSubscribers := 50
	numMessages := 1000
	if testing.Short() {
		numSubscribers = 5
		numMessages = 100
	}

	// 1. Initialize Publisher
	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)

	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	// Initialize 50 Subscribers
	subs := make([]*feed.SubscriberEngine, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)
		if err != nil {
			t.Fatalf("NewSubscriberEngine[%d] failed: %v", i, err)
		}
		defer sub.Close()
		subs[i] = sub
	}

	// Connect subscriber 0 and perform initial handshake with Publisher to establish master AEAD cipher
	if err := subs[0].Connect(ctx); err != nil {
		t.Fatalf("subs[0].Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(5 * time.Second) }()
	go func() { errChan <- subs[0].CompleteHandshake(5 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Initial handshake failed: %v", err)
		}
	}

	pubInputChan := make(chan []byte, 100)

	pubErrChan := make(chan error, 1)
	go func() {
		pubErrChan <- pub.PublishStream(ctx, pubInputChan)
	}()

	// Connect and handshake remaining 49 subscribers concurrently using goroutines & sync.WaitGroup
	var connectWg sync.WaitGroup
	handshakeErrs := make([]error, numSubscribers)

	for i := 1; i < numSubscribers; i++ {
		connectWg.Add(1)
		go func(idx int) {
			defer connectWg.Done()
			if err := subs[idx].Connect(ctx); err != nil {
				handshakeErrs[idx] = fmt.Errorf("sub[%d].Connect error: %w", idx, err)
				return
			}
			if err := subs[idx].CompleteHandshake(10 * time.Second); err != nil {
				handshakeErrs[idx] = fmt.Errorf("sub[%d].CompleteHandshake error: %w", idx, err)
				return
			}
		}(i)
	}

	connectWg.Wait()

	for i := 1; i < numSubscribers; i++ {
		if handshakeErrs[i] != nil {
			t.Fatalf("Handshake error for subscriber %d: %v", i, handshakeErrs[i])
		}
	}

	// Start all 50 subscribers streaming concurrently using goroutines & sync.WaitGroup
	var subWg sync.WaitGroup
	receivedCounts := make([]int64, numSubscribers)
	seqErrors := make([]atomic.Value, numSubscribers)

	for i := 0; i < numSubscribers; i++ {
		subWg.Add(1)
		go func(idx int) {
			defer subWg.Done()

			expectedSeq := 1

			err := subs[idx].SubscribeStream(ctx, nil, func(payload []byte) {
				atomic.AddInt64(&receivedCounts[idx], 1)
				var seq int
				if _, fmtErr := fmt.Sscanf(string(payload), "MSG_%d", &seq); fmtErr != nil {
					if seqErrors[idx].Load() == nil {
						seqErrors[idx].Store(fmt.Errorf("sub[%d] invalid payload %q: %w", idx, string(payload), fmtErr))
					}
					return
				}
				if seq != expectedSeq {
					if seqErrors[idx].Load() == nil {
						seqErrors[idx].Store(fmt.Errorf("sub[%d] sequence error: expected %d, got %d", idx, expectedSeq, seq))
					}
				}
				expectedSeq++
			})

			if err != nil && !errors.Is(err, context.Canceled) {
				// Ignore expected stream teardown errors
			}
		}(i)
	}

	// Allow subscriber stream loops to start listening
	time.Sleep(50 * time.Millisecond)

	// 2. Publisher transmits 1,000 consecutive messages at 1ms intervals
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	for i := 1; i <= numMessages; i++ {
		<-ticker.C
		pubInputChan <- fmt.Appendf(nil, "MSG_%d", i)
	}

	close(pubInputChan)

	doneChan := make(chan struct{})
	go func() {
		subWg.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// Subscribers completed successfully
	case <-time.After(15 * time.Second):
		for i := 0; i < numSubscribers; i++ {
			rec := atomic.LoadInt64(&receivedCounts[i])
			errVal := seqErrors[i].Load()
			t.Logf("Sub[%d] received %d msgs, seqErr=%v", i, rec, errVal)
		}
		t.Fatalf("Test timed out waiting for subscribers to finish (possible deadlock or lost messages)")
	}

	if pubErr := <-pubErrChan; pubErr != nil && !errors.Is(pubErr, context.Canceled) {
		t.Fatalf("PublishStream failed: %v", pubErr)
	}

	// 3. Verify ALL 50 Subscribers received exactly 1,000 messages without loss or sequence misalignment
	for i := 0; i < numSubscribers; i++ {
		rec := atomic.LoadInt64(&receivedCounts[i])
		errVal := seqErrors[i].Load()
		if errVal != nil {
			t.Errorf("Subscriber %d sequence error: %v", i, errVal)
		}
		if rec != int64(numMessages) {
			t.Errorf("Subscriber %d received %d messages, expected %d", i, rec, numMessages)
		}
	}
}
