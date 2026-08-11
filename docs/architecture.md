# ZeroFeed Software Architecture & Engineering Design

This document details the internal software architecture, package boundaries, concurrency model, and thread-safety design patterns of **ZeroFeed**.

---

## 🏗️ Directory & Package Structure

```
ZeroFeed/
├── main.go               # Unified CLI entrypoint & flag dispatcher
├── pkg/
│   ├── crypto/           # Cryptographic primitives (PAKE, AEAD, Memzero)
│   │   ├── cipher.go     # AES-256-GCM AEAD & SHA-256 key derivation
│   │   ├── pake.go       # SPAKE2 Curve25519 key exchange
│   │   ├── memzero.go    # Compiler-safe memory zeroing
│   │   └── crypto_test.go# Crypto test suite
│   ├── protocol/         # Binary frame envelope & serialisation
│   │   ├── envelope.go   # Envelope Encode/Decode routines
│   │   ├── messages.go   # Message type constants & protocol header
│   │   └── protocol_test.go
│   ├── feed/             # Pub/Sub Engine & Standby Auto-Sync
│   │   ├── publisher.go  # Publisher engine with sequence numbering
│   │   ├── subscriber.go # Subscriber engine with auto-reconnect backoff
│   │   ├── ringbuffer.go # Circular RAM buffer with sequence tracking
│   │   ├── session_id.go # Session ID derivation
│   │   └── feed_test.go  # Integration test suite
│   └── relay/            # Zero-Knowledge Relay Server
│       ├── server.go     # TCP Relay server & connection handler
│       ├── session.go    # RelaySession & non-blocking client queues
│       ├── ratelimit.go  # Anti-brute-force rate limiter
│       └── relay_test.go # Relay test suite
└── docs/
    ├── protocol.md       # Binary protocol envelope specification
    ├── architecture.md   # Internal software architecture (This doc)
    ├── security.md       # Security & cryptographic whitepaper
    ├── deployment.md     # DevOps & deployment guide
    └── api_guide.md      # Go library integration guide
```

---

## 🔒 Concurrency & Thread-Safety Model

ZeroFeed is designed for high-concurrency streaming under strict multi-threaded operations.

### 1. Publisher State Synchronization (`pkg/feed/publisher.go`)
- `PublisherEngine` uses `sync.Mutex` (`p.mu`) to synchronize access to network connections (`p.conn`), cipher instances (`p.cipher`), and PAKE states.
- Monotonic sequence numbering uses atomic operations (`atomic.AddUint64(&p.seqCounter, 1)`).
- Incoming `MsgTypeSyncReq` requests are processed asynchronously in a dedicated `handleSyncRequests` goroutine without blocking stdout/stdin pipelines.

### 2. Subscriber State Synchronization (`pkg/feed/subscriber.go`)
- `SubscriberEngine` uses `sync.Mutex` (`s.mu`) to protect connections, cipher states, and `s.lastSeqNum`.
- Deduplication is atomic: frames with `SeqNum <= s.lastSeqNum` are immediately dropped and zeroed.
- Connection failures trigger an exponential backoff reconnect loop (`100ms`, `500ms`, `1s`, `2s`... up to `5s`), creating a fresh socket and re-issuing `SYNC_REQ(lastSeqNum)`.

### 3. Relay Non-Blocking Sockets (`pkg/relay/session.go`)
- Each `ClientConn` maintains an asynchronous send queue (`sendCh chan *protocol.Envelope` with capacity 100).
- Slow consumers (sluggish Subscribers) do NOT block the Publisher or other Subscribers.
- Write deadlines (`2s`) prevent socket hang-ups from stalling relay goroutines.

---

## 🧹 Memory Zeroing & Ephemerality

ZeroFeed strictly enforces in-RAM ephemerality:

1. **`crypto.ZeroBytes(b []byte)`**: Overwrites slice contents with `0x00` and passes `b` to `runtime.KeepAlive(b)` to prevent compiler optimization from stripping zeroing loops.
2. **RAM Circular Replay Buffer (`pkg/feed/ringbuffer.go`)**: Holds up to 100 sequence-numbered unencrypted frames in RAM for reconnect sync.
3. **Session Teardown**: Calling `Close()` or reaching session TTL immediately triggers `ringbuffer.Wipe()`, zeros symmetric cipher keys, closes TCP sockets, and purges all pointers.

---

## 🏷️ Versioning Architecture & Gopls Configuration

### Dual-Version Scheme
ZeroFeed maintains a clear separation between product release versions and wire protocol frame versions:
- **Software Release Version (`v1.3.0`)**: Injected into `pkg/version.Version` at build time. Governs CLI releases, WASM initialization logs, build scripts (`scripts/build_release.sh`), and landing page badges.
- **Wire Protocol Version (`0x02` / Protocol v2)**: Hardcoded in `pkg/protocol.Version` (`0x02`). Governs the 38-byte binary frame header (`ZFED`), HKDF domain separation strings (`zerofeed-v2-hkdf-aead`), and frame serialization specs.

### Gopls Build Tags Configuration
To support QUIC implementation files with `//go:build quic` in IDEs without missing package diagnostics, `.vscode/settings.json` is configured with:
```json
{
  "gopls": { "buildFlags": ["-tags=quic"] },
  "go.buildFlags": ["-tags=quic"],
  "go.testFlags": ["-tags=quic"]
}
```
