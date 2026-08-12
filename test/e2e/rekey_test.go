package e2e_test

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestInStreamKeyRatchetPFS(t *testing.T) {
	relaySrv := relay.NewServer("127.0.0.1:0")
	relaySrv.SetRateLimiting(false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = relaySrv.Start(ctx)
	}()
	<-relaySrv.Ready()
	relayAddr := relaySrv.Addr()

	code := []byte("pfs-rekey-test-code-12345")

	pub, err := feed.NewPublisherEngine(code, relayAddr)
	if err != nil {
		t.Fatalf("Failed to create publisher: %v", err)
	}
	defer pub.Close()

	// Set low byte threshold (100 bytes) to force rapid in-stream rekeying during test
	pub.SetRekeyThresholds(100, 1*time.Minute)

	sub, err := feed.NewSubscriberEngine(code, relayAddr)
	if err != nil {
		t.Fatalf("Failed to create subscriber: %v", err)
	}
	defer sub.Close()

	errCh := make(chan error, 2)

	go func() {
		if err := pub.Connect(ctx); err != nil {
			errCh <- err
			return
		}
		if err := pub.CompleteHandshake(5 * time.Second); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	go func() {
		if err := sub.Connect(ctx); err != nil {
			errCh <- err
			return
		}
		if err := sub.CompleteHandshake(5 * time.Second); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("Handshake error: %v", err)
		}
	}

	pr, pw := io.Pipe()
	var recCount atomic.Int64

	go func() {
		defer pr.Close()
		buf := make([]byte, 1024)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				recCount.Add(1)
			}
			if err != nil {
				return
			}
		}
	}()

	subCtx, subCancel := context.WithTimeout(ctx, 10*time.Second)
	defer subCancel()

	go func() {
		_ = sub.SubscribeStream(subCtx, pw, nil)
	}()

	// Send 5 messages (each 50 bytes = 250 bytes > 100 byte threshold), triggering multiple key ratchets
	for i := 1; i <= 5; i++ {
		payload := fmt.Appendf(nil, "%d: Continuous E2EE Stream Payload Data Chunk #%d", i, i)
		if err := pub.PublishPayload(ctx, payload); err != nil {
			t.Fatalf("PublishPayload error on msg %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)
	if recCount.Load() < 5 {
		t.Errorf("Expected 5 received messages across key ratchets, got %d", recCount.Load())
	}
}
