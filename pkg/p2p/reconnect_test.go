package p2p_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

type safeBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestAutoSyncCatchUpAndLiveStream tests socket drop, catch-up sync from Replay Buffer, and transition back to Live stream.
func TestAutoSyncCatchUpAndLiveStream(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()
	passphrase := []byte("p2p-reconnect-catchup-secret")

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
		t.Fatalf("NewSubscriberEngine #1 failed: %v", err)
	}
	defer sub1.Close()

	if err := sub1.Connect(ctx); err != nil {
		t.Fatalf("sub1.Connect failed: %v", err)
	}

	// Handshake Publisher and Subscriber 1
	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(10 * time.Second) }()
	go func() { errChan <- sub1.CompleteHandshake(10 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Handshake error: %v", err)
		}
	}

	inputChan := make(chan []byte, 20)

	// Start publisher stream
	go func() {
		_ = pub.PublishStream(ctx, inputChan)
	}()

	var sub1Buf safeBuffer
	sub1Ctx, sub1Cancel := context.WithCancel(ctx)

	go func() {
		_ = sub1.SubscribeStream(sub1Ctx, &sub1Buf, nil)
	}()

	// 1. Publisher transmits messages #1 and #2
	inputChan <- []byte("Message #1")
	inputChan <- []byte("Message #2")

	time.Sleep(150 * time.Millisecond)

	// 2. Subscriber 1 receives #1 and #2, then connection is FORCIBLY closed (simulating abrupt drop)
	if !bytes.Contains([]byte(sub1Buf.String()), []byte("Message #1")) ||
		!bytes.Contains([]byte(sub1Buf.String()), []byte("Message #2")) {
		t.Fatalf("Subscriber #1 failed to receive initial messages #1 and #2. Got: %q", sub1Buf.String())
	}

	sub1Cancel()
	sub1.Close()

	// 3. WHILE Subscriber 1 is disconnected, Publisher sends messages #3, #4, and #5
	inputChan <- []byte("Message #3")
	inputChan <- []byte("Message #4")
	inputChan <- []byte("Message #5")

	time.Sleep(150 * time.Millisecond)

	// 4. Subscriber 2 reconnects and sends SYNC_REQ with last_seq=2
	sub2, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine #2 failed: %v", err)
	}
	defer sub2.Close()

	if err := sub2.Connect(ctx); err != nil {
		t.Fatalf("sub2.Connect failed: %v", err)
	}

	if err := sub2.CompleteHandshake(10 * time.Second); err != nil {
		t.Fatalf("sub2 CompleteHandshake failed: %v", err)
	}

	var sub2Buf safeBuffer
	sub2Ctx, sub2Cancel := context.WithTimeout(ctx, 2*time.Second)
	defer sub2Cancel()

	go func() {
		_ = sub2.SubscribeStream(sub2Ctx, &sub2Buf, nil)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := sub2.SendSyncRequest(); err != nil {
		t.Fatalf("SendSyncRequest failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// 5. Verify Catch-Up of messages #3, #4, and #5 from Replay Buffer
	contents := sub2Buf.String()
	if !bytes.Contains([]byte(contents), []byte("Message #3")) ||
		!bytes.Contains([]byte(contents), []byte("Message #4")) ||
		!bytes.Contains([]byte(contents), []byte("Message #5")) {
		t.Fatalf("Catch-Up failed! Reconnected subscriber did not receive #3, #4, #5. Got: %q", contents)
	}

	// 5 (cont). Publisher sends live message #6 and verifies return to Live stream mode
	inputChan <- []byte("Message #6")

	time.Sleep(200 * time.Millisecond)
	close(inputChan)
	sub2Cancel()

	contentsFinal := sub2Buf.String()
	if !bytes.Contains([]byte(contentsFinal), []byte("Message #6")) {
		t.Fatalf("Live stream mode failed! Reconnected subscriber did not receive live message #6. Got: %q", contentsFinal)
	}
}

// TestReplayBufferOverflow tests edge case when subscriber disconnect exceeds Replay Buffer capacity.
func TestReplayBufferOverflow(t *testing.T) {
	const capacity = 50
	const numPushed = 200

	rb := feed.NewRingBuffer(capacity)

	// 6. Simulate pushing 200 messages into buffer of capacity 50
	for i := 1; i <= numPushed; i++ {
		msg := fmt.Appendf(nil, "OVERFLOW_MSG_%d", i)
		rb.Push(uint64(i), msg)
	}

	// Verify RAM capacity limit (no memory leak)
	if rb.Len() != capacity {
		t.Fatalf("expected ring buffer size %d, got %d", capacity, rb.Len())
	}

	// Verify oldest sequence number in buffer is 151
	oldest := rb.OldestSeqNum()
	if oldest != 151 {
		t.Fatalf("expected oldest seq num 151, got %d", oldest)
	}

	// Verify overflow detection for last_seq = 2
	if !rb.IsOverflow(2) {
		t.Fatalf("expected IsOverflow(2) to return true")
	}

	// Verify GetAfter(2) returns remaining 50 messages safely without crash or panic
	items := rb.GetAfter(2)
	if len(items) != capacity {
		t.Fatalf("expected GetAfter(2) to return %d items, got %d", capacity, len(items))
	}

	if string(items[0].Payload) != "OVERFLOW_MSG_151" {
		t.Fatalf("expected first returned item OVERFLOW_MSG_151, got %s", string(items[0].Payload))
	}
	if string(items[len(items)-1].Payload) != "OVERFLOW_MSG_200" {
		t.Fatalf("expected last returned item OVERFLOW_MSG_200, got %s", string(items[len(items)-1].Payload))
	}

	// Verify RAM wiping
	rb.Wipe()
	if rb.Len() != 0 {
		t.Fatalf("expected size 0 after Wipe, got %d", rb.Len())
	}
}

// TestReplayBufferOverflowIntegration tests end-to-end overflow recovery when subscriber reconnects after ring buffer wraps.
func TestReplayBufferOverflowIntegration(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()
	passphrase := []byte("p2p-overflow-integration-secret")

	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	sub1, err := feed.NewSubscriberEngine(passphrase, relayAddr)

	if err != nil {
		t.Fatalf("NewSubscriberEngine #1 failed: %v", err)
	}
	defer sub1.Close()

	if err := sub1.Connect(ctx); err != nil {
		t.Fatalf("sub1.Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(10 * time.Second) }()
	go func() { errChan <- sub1.CompleteHandshake(10 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Handshake error: %v", err)
		}
	}

	inputChan := make(chan []byte, 250)

	go func() {
		_ = pub.PublishStream(ctx, inputChan)
	}()

	// Subscriber 1 receives message #1 and #2 then disconnects
	var sub1Buf safeBuffer
	sub1Ctx, sub1Cancel := context.WithCancel(ctx)

	go func() {
		_ = sub1.SubscribeStream(sub1Ctx, &sub1Buf, nil)
	}()

	inputChan <- []byte("MSG_1")
	inputChan <- []byte("MSG_2")
	time.Sleep(100 * time.Millisecond)

	sub1Cancel()
	sub1.Close()

	// Push 150 messages while subscriber is disconnected (replay buffer capacity is 100)
	for i := 3; i <= 150; i++ {
		inputChan <- fmt.Appendf(nil, "MSG_%d", i)
	}
	time.Sleep(150 * time.Millisecond)

	// Reconnect subscriber 2 and request sync with last_seq=2
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

	var sub2Buf safeBuffer
	sub2Ctx, sub2Cancel := context.WithTimeout(ctx, 2*time.Second)
	defer sub2Cancel()

	go func() {
		_ = sub2.SubscribeStream(sub2Ctx, &sub2Buf, nil)
	}()

	time.Sleep(50 * time.Millisecond)
	if err := sub2.SendSyncRequest(); err != nil {
		t.Fatalf("SendSyncRequest failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	close(inputChan)
	sub2Cancel()

	// Verify subscriber received available messages from buffer without crashing
	contents := sub2Buf.String()
	if !bytes.Contains([]byte(contents), []byte("MSG_150")) {
		t.Fatalf("Overflow integration test failed! Expected MSG_150 in buffer, got: %q", contents)
	}
}
