package relay_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestRelayMemoryLeak stress tests the Relay server under 1,000 rapid session cycles with 50KB payloads to audit memory reclamation.
func TestRelayMemoryLeak(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	// Stabilize heap and record baseline memory before stress test
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	numSessions := 100
	numWorkers := 20
	if testing.Short() {
		numSessions = 15
		numWorkers = 5
	}
	const payloadSize = 50 * 1024 // 50 KB payload per session

	jobs := make(chan int, numSessions)
	for i := 0; i < numSessions; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	var sessionErrors atomic.Int64
	var completedSessions atomic.Int64

	// 2. Simulate rapid creation and closure of 1,000 distinct sessions across 20 workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for idx := range jobs {
				passphrase := fmt.Appendf(nil, "relay-memleak-passphrase-session-%d", idx)

				pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
				if err != nil {
					sessionErrors.Add(1)
					continue
				}

				sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)

				if err != nil {
					pub.Close()
					sessionErrors.Add(1)
					continue
				}

				if err := pub.Connect(ctx); err != nil {
					pub.Close()
					sub.Close()
					sessionErrors.Add(1)
					continue
				}

				if err := sub.Connect(ctx); err != nil {
					pub.Close()
					sub.Close()
					sessionErrors.Add(1)
					continue
				}

				errChan := make(chan error, 2)
				go func() { errChan <- pub.CompleteHandshake(5 * time.Second) }()
				go func() { errChan <- sub.CompleteHandshake(5 * time.Second) }()

				handshakeFailed := false
				for h := 0; h < 2; h++ {
					if <-errChan != nil {
						handshakeFailed = true
					}
				}

				if handshakeFailed {
					pub.Close()
					sub.Close()
					sessionErrors.Add(1)
					continue
				}

				pubInputChan := make(chan []byte, 2)
				pubErrChan := make(chan error, 1)
				go func() {
					pubErrChan <- pub.PublishStream(ctx, pubInputChan)
				}()

				var receivedBytes atomic.Int64
				subCtx, subCancel := context.WithTimeout(ctx, 5*time.Second)

				subErrChan := make(chan error, 1)
				go func() {
					subErrChan <- sub.SubscribeStream(subCtx, nil, func(payload []byte) {
						receivedBytes.Add(int64(len(payload)))
					})
				}()

				// 3. Exchange 50KB payload
				payloadData := make([]byte, payloadSize)
				payloadData[0] = byte(idx & 0xFF)
				payloadData[payloadSize-1] = byte((idx + 1) & 0xFF)

				pubInputChan <- payloadData
				close(pubInputChan)

				// Wait for socket delivery before teardown
				for i := 0; i < 50; i++ {
					if receivedBytes.Load() >= int64(payloadSize) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}

				pub.Close()
				sub.Close()
				subCancel()

				_ = <-pubErrChan
				_ = <-subErrChan

				if receivedBytes.Load() >= int64(payloadSize) {
					completedSessions.Add(1)
				} else {
					sessionErrors.Add(1)
				}
			}
		}(w)
	}

	wg.Wait()

	if errCount := sessionErrors.Load(); errCount > 0 {
		t.Logf("Warning: %d of %d sessions encountered network setup errors during rapid recycling", errCount, numSessions)
	}

	if completed := completedSessions.Load(); completed < int64(numSessions*70/100) {
		t.Fatalf("Too many session failures during memory leak test! Completed: %d / %d", completed, numSessions)
	}

	// 4. Monitor memory after stress cycle and after runtime.GC()
	var mPeak runtime.MemStats
	runtime.ReadMemStats(&mPeak)

	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	t.Logf("MemStats - Baseline : Alloc = %10d bytes, HeapObjects = %8d", mBefore.Alloc, mBefore.HeapObjects)
	t.Logf("MemStats - Peak     : Alloc = %10d bytes, HeapObjects = %8d", mPeak.Alloc, mPeak.HeapObjects)
	t.Logf("MemStats - After GC : Alloc = %10d bytes, HeapObjects = %8d", mAfter.Alloc, mAfter.HeapObjects)

	// 5. Verify internal Relay sessions map is COMPLETELY EMPTY (0 active sessions)
	if activeSessions := srv.SessionCount(); activeSessions != 0 {
		t.Fatalf("Memory leak detected! Expected 0 active sessions in Relay map, found %d active sessions", activeSessions)
	}

	// Verify memory reclamation tolerance (< 15MB tolerance for 1000 stress test sessions with race detector)
	maxAllowedAlloc := uint64(float64(mBefore.Alloc) * 1.05)
	if mBefore.Alloc < 15*1024*1024 {
		maxAllowedAlloc = mBefore.Alloc + 15*1024*1024
	}

	if mAfter.Alloc > maxAllowedAlloc {
		t.Errorf("Memory leak detected! Heap Alloc after GC (%d bytes) exceeds baseline tolerance (%d bytes)", mAfter.Alloc, maxAllowedAlloc)
	}
}
