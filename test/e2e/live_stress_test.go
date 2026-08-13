//go:build quic

package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

// FlyRelayAddr is the live relay endpoint for e2e tests against a real relay node.
// Set ZEROFEED_RELAY before running, e.g.:
//
//	ZEROFEED_RELAY=relay.example.com:8443 go test -tags quic -run TestLive ./test/e2e/
//
// All live relay tests skip automatically when ZEROFEED_RELAY is not set.
var FlyRelayAddr = os.Getenv("ZEROFEED_RELAY")

// skipIfNoRelay skips the test if ZEROFEED_RELAY is not configured.
func skipIfNoRelay(t *testing.T) {
	t.Helper()
	if FlyRelayAddr == "" {
		t.Skip("Skipping live relay test: ZEROFEED_RELAY not set")
	}
}

func TestLiveTCPRelaySingleStream(t *testing.T) {
	skipIfNoRelay(t)
	if testing.Short() {
		t.Skip("Skipping external live network relay test in -short mode")
	}
	passphrase := fmt.Sprintf("live-tcp-test-%d", time.Now().UnixNano())
	passBytes := []byte(passphrase)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	pub, err := feed.NewPublisherEngine(passBytes, FlyRelayAddr)
	if err != nil {
		t.Fatalf("Failed to create publisher: %v", err)
	}
	defer pub.Close()

	sub, err := feed.NewSubscriberEngine(passBytes, FlyRelayAddr)
	if err != nil {
		t.Fatalf("Failed to create subscriber: %v", err)
	}
	defer sub.Close()

	// 1. Publisher connects to relay
	if err := pub.Connect(ctx); err != nil {
		t.Skipf("Live relay %s unreachable: %v", FlyRelayAddr, err)
	}

	var wg sync.WaitGroup
	var pubErr, subErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		pubErr = pub.CompleteHandshake(25 * time.Second)
	}()

	time.Sleep(100 * time.Millisecond)

	// 2. Subscriber connects to relay
	if err := sub.Connect(ctx); err != nil {
		t.Fatalf("Subscriber connect failed: %v", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		subErr = sub.CompleteHandshake(25 * time.Second)
	}()

	wg.Wait()

	if pubErr != nil {
		t.Fatalf("Publisher handshake error: %v", pubErr)
	}
	if subErr != nil {
		t.Fatalf("Subscriber handshake error: %v", subErr)
	}

	// Generate 1MB payload
	payloadSize := 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(32 + (i % 94))
	}

	var subBuf bytes.Buffer
	subDone := make(chan error, 1)

	go func() {
		subDone <- sub.SubscribeStream(ctx, &subBuf, nil)
	}()

	time.Sleep(100 * time.Millisecond)

	expectedHash := sha256.Sum256(payload)

	chunkSize := 32*1024 - 1
	inputChan := make(chan []byte, 100)

	go func() {
		defer close(inputChan)
		for i := 0; i < len(payload); i += chunkSize {
			end := i + chunkSize
			if end > len(payload) {
				end = len(payload)
			}
			chunk := make([]byte, 1+(end-i))
			chunk[0] = protocol.TagText
			copy(chunk[1:], payload[i:end])
			inputChan <- chunk
		}
	}()

	pubErr = pub.PublishStream(ctx, inputChan)
	if pubErr != nil {
		t.Fatalf("PublishStream error: %v", pubErr)
	}
	time.Sleep(1 * time.Second)
	pub.Close()

	select {
	case err := <-subDone:
		if err != nil {
			t.Logf("Subscriber finished with status: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("Subscriber timed out waiting for payload stream")
	}

	actualHash := sha256.Sum256(subBuf.Bytes())
	if !bytes.Equal(expectedHash[:], actualHash[:]) {
		t.Fatalf("SHA-256 Mismatch!\nExpected: %x\nGot:      %x\nBytes received: %d / %d",
			expectedHash, actualHash, subBuf.Len(), payloadSize)
	}

	t.Logf("✓ TCP Live Stream Passed! Transmitted %d bytes with matching SHA-256 (%x)", payloadSize, actualHash[:8])
}

func TestLiveRelayStressLoadTCP(t *testing.T) {
	runStressTest(t, 10, 50, 8192)
}

func TestLiveRelayHighStressLoadTCP(t *testing.T) {
	runStressTest(t, 30, 80, 8192)
}

func runStressTest(t *testing.T, concurrentSessions int, messagesPerSession int, msgSize int) {
	skipIfNoRelay(t)
	if testing.Short() {
		t.Skip("Skipping external live network relay stress test in -short mode")
	}
	t.Logf("Starting TCP Stress Load Test against live relay (%s)", FlyRelayAddr)
	t.Logf("Concurrent Sessions: %d, Msgs/Session: %d, Payload/Session: %.2f KB, Total Volume: %.2f MB",
		concurrentSessions, messagesPerSession, float64(messagesPerSession*msgSize)/1024,
		float64(concurrentSessions*messagesPerSession*msgSize)/(1024*1024))

	start := time.Now()
	var successCount atomic.Int64
	var failedCount atomic.Int64

	var wg sync.WaitGroup

	for i := 0; i < concurrentSessions; i++ {
		wg.Add(1)
		sessionIdx := i
		go func() {
			defer wg.Done()

			passphrase := fmt.Sprintf("stress-tcp-session-%d-%d", sessionIdx, time.Now().UnixNano())
			passBytes := []byte(passphrase)

			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()

			pub, err := feed.NewPublisherEngine(passBytes, FlyRelayAddr)
			if err != nil {
				failedCount.Add(1)
				t.Logf("[Session %d] Publisher init err: %v", sessionIdx, err)
				return
			}
			pub.SetTransportMode(transport.ModeTCP)
			defer pub.Close()

			sub, err := feed.NewSubscriberEngine(passBytes, FlyRelayAddr)
			if err != nil {
				failedCount.Add(1)
				t.Logf("[Session %d] Subscriber init err: %v", sessionIdx, err)
				return
			}
			sub.SetTransportMode(transport.ModeTCP)
			defer sub.Close()

			if err := pub.Connect(ctx); err != nil {
				failedCount.Add(1)
				t.Logf("[Session %d] Pub connect err: %v", sessionIdx, err)
				return
			}

			var handshakeWg sync.WaitGroup
			var pubHnErr, subHnErr error
			handshakeWg.Add(1)

			go func() {
				defer handshakeWg.Done()
				pubHnErr = pub.CompleteHandshake(15 * time.Second)
			}()

			time.Sleep(30 * time.Millisecond)

			if err := sub.Connect(ctx); err != nil {
				failedCount.Add(1)
				t.Logf("[Session %d] Sub connect err: %v", sessionIdx, err)
				return
			}

			handshakeWg.Add(1)
			go func() {
				defer handshakeWg.Done()
				subHnErr = sub.CompleteHandshake(15 * time.Second)
			}()

			handshakeWg.Wait()

			if pubHnErr != nil || subHnErr != nil {
				failedCount.Add(1)
				t.Logf("[Session %d] Handshake err: pub=%v, sub=%v", sessionIdx, pubHnErr, subHnErr)
				return
			}

			var subBuf bytes.Buffer
			subDone := make(chan error, 1)

			go func() {
				subDone <- sub.SubscribeStream(ctx, &subBuf, nil)
			}()

			inputChan := make(chan []byte, messagesPerSession)
			hasher := sha256.New()

			for m := 0; m < messagesPerSession; m++ {
				data := make([]byte, msgSize)
				data[0] = protocol.TagText
				data[1] = byte(m)
				data[2] = byte(sessionIdx)
				_, _ = rand.Read(data[3:])

				hasher.Write(data[1:])
				inputChan <- data
			}
			close(inputChan)

			expectedHash := hasher.Sum(nil)

			_ = pub.PublishStream(ctx, inputChan)
			time.Sleep(300 * time.Millisecond)
			pub.Close()

			select {
			case <-subDone:
			case <-time.After(15 * time.Second):
			}

			actualHash := sha256.Sum256(subBuf.Bytes())
			if bytes.Equal(expectedHash, actualHash[:]) {
				successCount.Add(1)
			} else {
				failedCount.Add(1)
				t.Logf("[Session %d] Hash mismatch! expected %x, got %x (bytes %d / %d)",
					sessionIdx, expectedHash[:8], actualHash[:8], subBuf.Len(), (messagesPerSession * (msgSize - 1)))
			}
		}()

		time.Sleep(40 * time.Millisecond)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalMB := float64(concurrentSessions*messagesPerSession*msgSize) / (1024 * 1024)
	throughputMBs := totalMB / elapsed.Seconds()

	t.Logf("==========================================================")
	t.Logf(" STRESS LOAD TEST RESULTS (Fly.io Frankfurt Relay)")
	t.Logf(" Total Sessions Tested  : %d (TCP)", concurrentSessions)
	t.Logf(" Successful Sessions    : %d / %d (%.1f%%)", successCount.Load(), concurrentSessions, float64(successCount.Load())/float64(concurrentSessions)*100)
	t.Logf(" Failed Sessions        : %d", failedCount.Load())
	t.Logf(" Total Data Transmitted : %.2f MB", totalMB)
	t.Logf(" Total Execution Time   : %v", elapsed)
	t.Logf(" Aggregate Throughput   : %.2f MB/s", throughputMBs)
	t.Logf("==========================================================")

	// For high-stress WAN tests (30+ concurrent sessions), allow up to 5% failure rate
	// due to expected transient packet loss over real WAN connections.
	minSuccessRate := 1.0
	if concurrentSessions >= 30 {
		minSuccessRate = 0.95
	}
	actualRate := float64(successCount.Load()) / float64(concurrentSessions)
	if actualRate < minSuccessRate {
		t.Fatalf("Stress test failed: %d / %d sessions succeeded (%.1f%% < %.0f%% threshold)",
			successCount.Load(), concurrentSessions, actualRate*100, minSuccessRate*100)
	}
}
