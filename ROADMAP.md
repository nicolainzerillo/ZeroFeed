# ZeroFeed — Roadmap

> **Current stable release**: v1.2  
> **Repository**: [github.com/zerofeed/zerofeed](https://github.com/zerofeed/zerofeed)

ZeroFeed is a zero-knowledge, end-to-end encrypted pub/sub CLI and Go engine.  
This roadmap is public and honest: items listed here are concrete engineering goals, not marketing promises.

---

## ✅ v1.2 — Current Release

- Post-Quantum Hybrid E2EE: **NIST FIPS 203 ML-KEM-768** + X25519 PAKE (ACN Italia 2024/2026 aligned)
- AES-256-GCM AEAD stream encryption with per-session key derivation
- QUIC transport (`-tags quic`) with automatic TCP fallback
- WebSocket relay endpoint (`8444`) for browser-side E2EE decryption via WASM
- In-memory 100-message circular replay buffer with automatic reconnect backoff
- RAM-only relay node: zero disk persistence, zero payload logs
- Anti-brute-force relay: IP rate-limiting, 3-strike PAKE ban
- Prometheus metrics endpoint (`/metrics`) — zero-knowledge, no IPs/keys logged
- File transfer with `TagFileStart`/`TagFileChunk`/`TagFileEnd` protocol frames
- `mlockall` + `DisableCoreDumps` + `crypto.ZeroBytes()` memory hygiene
- Multi-subscriber fan-out on a single channel code
- P2P direct mode (`--p2p`) with STUN/UDP hole punching fallback

---

## 🔨 v1.3 — In Progress

> Focus: **Relay resilience** and **Unix correctness**

- [ ] **Multi-relay list with automatic fallback**  
  The CLI currently requires a single `--relay` address. v1.3 will accept a comma-separated list (or a well-known default list) and fall through to the next relay on connection failure. This removes the single point of failure on the public Oracle relay.  
  _Tracked in_: `pkg/feed`, `main.go` flag parsing

- [ ] **`SIGPIPE` graceful termination**  
  Piping `zerofeed sub | head -n 10` currently panics or prints a traceback on early consumer exit. Handle `syscall.SIGPIPE` and exit cleanly with status 0.

- [ ] **Relay backpressure / flow control**  
  A fast publisher on a slow-subscriber session can buffer unbounded chunks in relay RAM. Implement relay-side read-halt when subscriber buffer exceeds a configurable threshold (default: 16 MB).

- [ ] **Configurable relay address via `ZEROFEED_RELAY` env var** _(done in main, needs CLI flag parity)_

---

## 🗓️ v1.4 — Planned

> Focus: **Authentication hardening** and **observability**

- [ ] **SAS (Short Authentication String) visual badge**  
  Display a 4-char visual fingerprint on both terminals after PAKE completion (`[🛡️ 9A4F]`). Provides out-of-band verification that both peers completed the same PAKE without MITM. No code change needed on the relay.

- [ ] **In-stream key rekeying (Forward Secrecy per chunk)**  
  Automatic session key rotation every 1 GB transferred or every 1 hour. Protects long-running streams from retrospective decryption if a session key is later compromised.

- [ ] **Structured JSON logging mode** (`--log-format json`)  
  Machine-readable log output for CI/CD pipelines and log aggregators (Loki, Datadog, etc.) without leaking payload content.

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

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (coming in v1.3) for development setup.  

Good first issues are tagged [`good first issue`](https://github.com/zerofeed/zerofeed/labels/good%20first%20issue) on GitHub.

Architecture decisions and protocol specs live in [`docs/`](docs/).
