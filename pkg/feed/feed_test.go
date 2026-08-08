package feed_test

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
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

func TestRingBufferCapacityAndWipe(t *testing.T) {
	rb := feed.NewRingBuffer(3)

	rb.Push(1, []byte("msg1"))
	rb.Push(2, []byte("msg2"))
	rb.Push(3, []byte("msg3"))

	if rb.Len() != 3 {
		t.Fatalf("expected size 3, got %d", rb.Len())
	}

	msgs := rb.GetAll()
	if string(msgs[0]) != "msg1" || string(msgs[1]) != "msg2" || string(msgs[2]) != "msg3" {
		t.Fatalf("unexpected msgs content: %v", msgs)
	}

	after1 := rb.GetAfter(1)
	if len(after1) != 2 || string(after1[0].Payload) != "msg2" || string(after1[1].Payload) != "msg3" {
		t.Fatalf("unexpected GetAfter(1) content: %v", after1)
	}

	rb.Push(4, []byte("msg4"))
	if rb.Len() != 3 {
		t.Fatalf("expected size 3 after push, got %d", rb.Len())
	}

	msgs2 := rb.GetAll()
	if string(msgs2[0]) != "msg2" || string(msgs2[1]) != "msg3" || string(msgs2[2]) != "msg4" {
		t.Fatalf("unexpected msgs2 content: %v", msgs2)
	}

	rb.Wipe()
	if rb.Len() != 0 {
		t.Fatalf("expected size 0 after Wipe, got %d", rb.Len())
	}
}

func TestE2EEPubSubStreamingPipeline(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	passphrase := []byte("secret-ephemeral-code-99")

	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub.Close()

	if err := sub.Connect(ctx); err != nil {
		t.Fatalf("sub.Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(2 * time.Second) }()
	go func() { errChan <- sub.CompleteHandshake(2 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Handshake error: %v", err)
		}
	}

	inputChan := make(chan []byte, 3)
	inputChan <- []byte("Line 1: Config payload\n")
	inputChan <- []byte("Line 2: Secret API token\n")
	close(inputChan)

	var stdoutBuf safeBuffer
	var subWg sync.WaitGroup
	subWg.Add(1)

	subCtx, subCancel := context.WithTimeout(ctx, 2*time.Second)
	defer subCancel()

	go func() {
		defer subWg.Done()
		_ = sub.SubscribeStream(subCtx, &stdoutBuf, nil)
	}()

	if err := pub.PublishStream(ctx, inputChan); err != nil {
		t.Fatalf("pub.PublishStream failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	subCancel()
	subWg.Wait()

	expectedOutput := "Line 1: Config payload\nLine 2: Secret API token\n"
	if stdoutBuf.String() != expectedOutput {
		t.Fatalf("expected stdout output %q, got %q", expectedOutput, stdoutBuf.String())
	}
}

func TestAutoSyncOnReconnect(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	passphrase := []byte("resilience-sync-test-42")

	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub.Close()

	if err := sub.Connect(ctx); err != nil {
		t.Fatalf("sub.Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(2 * time.Second) }()
	go func() { errChan <- sub.CompleteHandshake(2 * time.Second) }()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			t.Fatalf("Handshake failed: %v", err)
		}
	}

	inputChan := make(chan []byte, 10)
	inputChan <- []byte("Pre-disconnect message #1")

	var stdoutBuf safeBuffer
	subCtx, subCancel := context.WithCancel(ctx)

	go func() {
		_ = sub.SubscribeStream(subCtx, &stdoutBuf, nil)
	}()

	go func() {
		_ = pub.PublishStream(ctx, inputChan)
	}()

	time.Sleep(150 * time.Millisecond)

	sub.Close()
	subCancel()

	inputChan <- []byte("Post-disconnect message #2")
	inputChan <- []byte("Post-disconnect message #3")

	time.Sleep(150 * time.Millisecond)

	sub2, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine #2 failed: %v", err)
	}
	defer sub2.Close()

	if err := sub2.Connect(ctx); err != nil {
		t.Fatalf("sub2.Connect failed: %v", err)
	}

	if err := sub2.CompleteHandshake(2 * time.Second); err != nil {
		t.Fatalf("sub2.CompleteHandshake failed: %v", err)
	}

	var stdoutBuf2 safeBuffer
	subCtx2, subCancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer subCancel2()

	var subErr atomic.Value
	go func() {
		err := sub2.SubscribeStream(subCtx2, &stdoutBuf2, nil)
		if err != nil {
			subErr.Store(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := sub2.SendSyncRequest(); err != nil {
		t.Fatalf("SendSyncRequest failed: %v", err)
	}

	time.Sleep(800 * time.Millisecond)

	close(inputChan)
	subCancel2()

	contents := stdoutBuf2.String()
	if !bytes.Contains([]byte(contents), []byte("Post-disconnect message #2")) ||
		!bytes.Contains([]byte(contents), []byte("Post-disconnect message #3")) {
		t.Fatalf("Auto-Sync failed! subErr=%v, stdoutBuf2=%q", subErr.Load(), contents)
	}
}

func TestRingBufferOverflowAndEdgeCases(t *testing.T) {
	rbDefault := feed.NewRingBuffer(0)
	if rbDefault.Len() != 0 {
		t.Fatalf("expected initial size 0, got %d", rbDefault.Len())
	}

	rb := feed.NewRingBuffer(3)
	if rb.OldestSeqNum() != 0 {
		t.Fatalf("expected OldestSeqNum 0 for empty buffer, got %d", rb.OldestSeqNum())
	}
	if rb.IsOverflow(10) {
		t.Fatalf("expected IsOverflow false for empty buffer")
	}

	rb.Push(10, []byte("msg10"))
	rb.Push(11, []byte("msg11"))
	rb.Push(12, []byte("msg12"))

	if rb.OldestSeqNum() != 10 {
		t.Fatalf("expected OldestSeqNum 10, got %d", rb.OldestSeqNum())
	}

	rb.Push(13, []byte("msg13")) // Overwrites seqNum 10
	if rb.OldestSeqNum() != 11 {
		t.Fatalf("expected OldestSeqNum 11 after overflow, got %d", rb.OldestSeqNum())
	}

	if !rb.IsOverflow(8) {
		t.Fatalf("expected IsOverflow true for seqNum 8 < oldest-1 (10)")
	}
	if rb.IsOverflow(11) {
		t.Fatalf("expected IsOverflow false for seqNum 11")
	}
}
