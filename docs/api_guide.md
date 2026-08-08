# ZeroFeed Go Library Integration Guide

> **Audience**: Go Developers & Software Engineers

ZeroFeed can be imported directly into custom Go applications as a **pure Go library** to stream E2EE payloads over network sockets with zero disk footprint.

---

## 📦 Installation

```bash
go get github.com/zerofeed/zerofeed@latest
```

---

## 💡 Code Example: Embedded Publisher Engine

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zerofeed/zerofeed/pkg/feed"
)

func main() {
	passphrase := []byte("5-omega-phoenix")
	defer crypto.ZeroBytes(passphrase)

	relayAddr := "127.0.0.1:8443"
	ttl := 5 * time.Minute

	// Initialize Publisher Engine
	pub, err := feed.NewPublisherEngine(passphrase, relayAddr)
	if err != nil {
		log.Fatalf("Failed to initialize publisher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	defer cancel()

	// Connect to Relay Node
	if err := pub.Connect(ctx); err != nil {
		log.Fatalf("Relay connection error: %v", err)
	}

	// Wait for Subscriber PAKE Handshake
	if err := pub.CompleteHandshake(ttl); err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	fmt.Println("[+] PAKE Handshake complete! Transmitting stream...")

	// Input channel for payloads
	dataCh := make(chan []byte, 10)
	dataCh <- []byte("Secret API Key: 987654321")
	close(dataCh)

	// Stream encrypted data
	if err := pub.PublishStream(ctx, dataCh); err != nil {
		log.Fatalf("Stream error: %v", err)
	}
}
```

---

## 💡 Code Example: Embedded Subscriber Engine

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/feed"
)

func main() {
	passphrase := []byte("5-omega-phoenix")
	defer crypto.ZeroBytes(passphrase)

	relayAddr := "127.0.0.1:8443"

	// Initialize Subscriber Engine
	sub, err := feed.NewSubscriberEngine(passphrase, relayAddr)
	if err != nil {
		log.Fatalf("Failed to initialize subscriber: %v", err)
	}

	ctx := context.Background()

	// Connect to Relay
	if err := sub.Connect(ctx); err != nil {
		log.Fatalf("Relay connection error: %v", err)
	}

	// Complete PAKE Handshake
	if err := sub.CompleteHandshake(0); err != nil {
		log.Fatalf("Handshake error: %v", err)
	}

	fmt.Println("[+] Connected! Decrypting incoming stream...")

	// Stream decrypted payload directly to stdout or io.Writer
	if err := sub.SubscribeStream(ctx, os.Stdout, nil); err != nil {
		log.Fatalf("Subscription error: %v", err)
	}
}

```

---

## 🛡️ Thread Safety & Memory Management
- `PublisherEngine` and `SubscriberEngine` are thread-safe and safe for concurrent usage across goroutines.
- Calling `Close()` immediately zeroizes cryptographic state and closes active network sockets.
