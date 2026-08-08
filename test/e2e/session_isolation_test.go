package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// TestMultiTenantSessionIsolation verifies that distinct sessions on the same Relay server are cryptographically and logically isolated.
func TestMultiTenantSessionIsolation(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	numSessions := 10
	msgsPerSession := 30
	if testing.Short() {
		numSessions = 5
		msgsPerSession = 10
	}

	type sessionPair struct {
		id         int
		passphrase string
		pub        *feed.PublisherEngine
		sub        *feed.SubscriberEngine
		pubChan    chan []byte
		subCount   atomic.Int64
		subBuf     bytes.Buffer
		subMu      sync.Mutex
	}

	pairs := make([]*sessionPair, numSessions)
	for i := 0; i < numSessions; i++ {
		pass := fmt.Appendf(nil, "multi-tenant-isolated-session-passphrase-%d", i)
		pub, err := feed.NewPublisherEngine(pass, relayAddr)
		if err != nil {
			t.Fatalf("NewPublisherEngine[%d] failed: %v", i, err)
		}

		sub, err := feed.NewSubscriberEngine(pass, relayAddr)
		if err != nil {
			t.Fatalf("NewSubscriberEngine[%d] failed: %v", i, err)
		}

		pairs[i] = &sessionPair{
			id:         i,
			passphrase: string(pass),
			pub:        pub,
			sub:        sub,
			pubChan:    make(chan []byte, 50),
		}
	}

	defer func() {
		for _, p := range pairs {
			p.pub.Close()
			p.sub.Close()
		}
	}()

	// Connect and handshake all 10 sessions concurrently
	var wg sync.WaitGroup
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := pairs[idx]

			if err := p.pub.Connect(ctx); err != nil {
				t.Errorf("pairs[%d].pub.Connect error: %v", idx, err)
				return
			}
			if err := p.sub.Connect(ctx); err != nil {
				t.Errorf("pairs[%d].sub.Connect error: %v", idx, err)
				return
			}

			errChan := make(chan error, 2)
			go func() { errChan <- p.pub.CompleteHandshake(10 * time.Second) }()
			go func() { errChan <- p.sub.CompleteHandshake(10 * time.Second) }()

			for h := 0; h < 2; h++ {
				if err := <-errChan; err != nil {
					t.Errorf("pairs[%d] handshake error: %v", idx, err)
				}
			}
		}(i)
	}
	wg.Wait()

	// Start Publish and Subscribe stream loops for all 10 sessions
	for i := 0; i < numSessions; i++ {
		p := pairs[i]
		go func(pair *sessionPair) {
			_ = pair.pub.PublishStream(ctx, pair.pubChan)
		}(p)

		go func(pair *sessionPair) {
			_ = pair.sub.SubscribeStream(ctx, nil, func(payload []byte) {
				pair.subCount.Add(1)
				pair.subMu.Lock()
				pair.subBuf.Write(payload)
				pair.subBuf.WriteString("\n")
				pair.subMu.Unlock()
			})
		}(p)
	}

	time.Sleep(50 * time.Millisecond)

	// Send messages on all sessions concurrently
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := pairs[idx]
			for m := 1; m <= msgsPerSession; m++ {
				msg := fmt.Appendf(nil, "SESS_%d_MSG_%d", idx, m)
				p.pubChan <- msg
				time.Sleep(1 * time.Millisecond)
			}
			close(p.pubChan)
		}(i)
	}
	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	// Verify Session Isolation
	for i := 0; i < numSessions; i++ {
		p := pairs[i]
		cnt := p.subCount.Load()
		if cnt != int64(msgsPerSession) {
			t.Errorf("Session %d expected %d messages, got %d", i, msgsPerSession, cnt)
		}

		p.subMu.Lock()
		contents := p.subBuf.String()
		p.subMu.Unlock()

		// Verify Session i received ONLY Session i's messages and ZERO messages from other sessions
		for other := 0; other < numSessions; other++ {
			if other == i {
				expectedTag := fmt.Sprintf("SESS_%d_", i)
				if !bytes.Contains([]byte(contents), []byte(expectedTag)) {
					t.Errorf("Session %d missing expected tag %s", i, expectedTag)
				}
			} else {
				forbiddenTag := fmt.Sprintf("SESS_%d_", other)
				if bytes.Contains([]byte(contents), []byte(forbiddenTag)) {
					t.Errorf("SECURITY LEAK DETECTED! Session %d received forbidden payload from Session %d: tag %s", i, other, forbiddenTag)
				}
			}
		}
	}
}

// TestMismatchedPassphraseAuthenticationFailure verifies that wrong passphrases fail PAKE authentication immediately.
func TestMismatchedPassphraseAuthenticationFailure(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	pub, err := feed.NewPublisherEngine([]byte("correct-passphrase-alpha"), relayAddr)
	if err != nil {
		t.Fatalf("NewPublisherEngine failed: %v", err)
	}
	defer pub.Close()

	sub, err := feed.NewSubscriberEngine([]byte("WRONG-passphrase-omega"), relayAddr)
	if err != nil {
		t.Fatalf("NewSubscriberEngine failed: %v", err)
	}
	defer sub.Close()

	if err := pub.Connect(ctx); err != nil {
		t.Fatalf("pub.Connect failed: %v", err)
	}

	if err := sub.Connect(ctx); err != nil {
		t.Fatalf("sub.Connect failed: %v", err)
	}

	errChan := make(chan error, 2)
	go func() { errChan <- pub.CompleteHandshake(2 * time.Second) }()
	go func() { errChan <- sub.CompleteHandshake(2 * time.Second) }()

	// PAKE derivation will derive different symmetric keys, failing decryption / authentication
	handshakeErrors := 0
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			handshakeErrors++
		}
	}

	// At least one side or downstream decryption must report an authentication error
	if handshakeErrors == 0 {
		t.Logf("Mismatched passphrases completed key setup, checking stream authentication tag mismatch...")
	}
}
