# ZeroFeed — Roadmap

> **Current stable release**: v1.3  
> **Repository**: [github.com/zerofeed/zerofeed](https://github.com/zerofeed/zerofeed)

ZeroFeed is a zero-knowledge, end-to-end encrypted pub/sub CLI and Go engine.  
This roadmap is public and honest: items listed here are concrete engineering goals, not marketing promises.

---

## ✅ v1.3 — Current Release

> Focus: **Relay resilience**, **Stateless Invites**, and **Enterprise Unit Test Suite**

- [x] **Multi-relay list with automatic fallback**  
  The CLI accepts a comma-separated list of relay addresses (or resolves default DNS relays) and falls through to the next relay on connection failure, eliminating single points of failure.  
  _Implemented in_: `pkg/feed/relay_list.go`, `main.go`
- [x] **Client-Generated Stateless Invite System**  
  Zero-knowledge, 100% stateless invite links (`zerofeed invite [code]` / `zerofeed join <invite>`) supporting terminal ASCII cards, native `zerofeed://` URIs, and Web `#join=` URL fragments.  
  _Implemented in_: `pkg/feed/invite.go`, `main.go`, `ZeroFeed-Landing`
- [x] **`SIGPIPE` graceful termination**  
  Piping `zerofeed sub | head -n 10` handles `syscall.SIGPIPE` and exits cleanly with status 0 without printing panics or tracebacks.  
  _Implemented in_: `main.go`
- [x] **Relay backpressure / flow control**  
  Watermark-driven flow control (`HighWatermark` 80% / `LowWatermark` 40%) with `WaitForDrain()` pauses fast publishers on slow subscriber sessions to prevent relay RAM saturation.  
  _Implemented in_: `pkg/relay/session.go`, `pkg/relay/slow_consumer_test.go`
- [x] **Configurable relay address via `ZEROFEED_RELAY` env var**  
  Full parity between CLI `--relay` flag and `ZEROFEED_RELAY` environment variable.  
  _Implemented in_: `main.go`, `pkg/feed/relay_list.go`
- [x] **SAS (Short Authentication String) visual badge**  
  Displays deterministic 8-hex character fingerprint and 4-emoji visual badge (`[🛡️ ⚡ 🚀 💎]`) on both terminals after PAKE completion for out-of-band Anti-MITM verification.  
  _Implemented in_: `pkg/crypto/cipher.go`, `main.go`
- [x] **In-stream key rekeying (Forward Secrecy per chunk)**  
  Automatic session key ratcheting every 1 GB transferred or every 1 hour, zeroizing parent keys in RAM immediately.  
  _Implemented in_: `pkg/feed/publisher.go`, `pkg/crypto/cipher.go`
- [x] **Enterprise Security-Grade Unit Test Suite (>85% target coverage)**  
  Extensive Table-Driven tests, native Go Fuzzing (`FuzzDecodeEnvelope`), memory zeroization assertions (`ZeroBytesSlice`), and Prometheus metrics unit tests.  
  _Implemented in_: `pkg/crypto`, `pkg/feed`, `pkg/relay`, `pkg/transport`, `pkg/protocol`

---

## 🗓️ v1.4 — Planned

> Focus: **Observability** and **Developer Experience**

- [ ] **Structured JSON logging mode** (`--log-format json`)  
  Machine-readable log output for CI/CD pipelines and log aggregators (Loki, Datadog, etc.) without leaking payload content.

- [ ] **Automated CI/CD Release Pipelines & Multi-arch Binaries**  
  GitHub Actions matrix generating static binaries for `darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, and `windows/amd64`.

---

## 🔮 Future Scope (no milestone yet)

These are confirmed directions, not committed timelines.

- **PKCS#11 / HSM support for publisher keys**  
  Allow the publisher to derive or protect its session keys using a hardware security module (YubiKey, Nitrokey, cloud HSM). Relevant for enterprise deployments where key material must never reside in process memory.

- **Self-hosted relay Docker image on Docker Hub / GHCR**  
  A single `docker run zerofeed/relay` command to launch a fully operational relay node, eliminating the need to compile from source for self-hosters.

- **Helm chart for Kubernetes relay deployment**  
  StatelessSet + HPA for horizontally scalable enterprise relay clusters inside private VPCs.

- **Federated community relay mesh**  
  Anycast DNS (`relay.zerofeed.app`) distributing across community-hosted relay nodes. Any node launched with `zerofeed relay --public` joins the mesh.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup.  

Architecture decisions and protocol specs live in [`docs/`](docs/).
