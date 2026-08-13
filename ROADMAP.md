# ZeroFeed — Roadmap

> **Current stable release**: v1.4  
> **Repository**: [github.com/zerofeed/zerofeed](https://github.com/zerofeed/zerofeed)

ZeroFeed is a zero-knowledge, end-to-end encrypted pub/sub CLI and Go engine.  
This roadmap is public and honest: items listed here are concrete engineering goals, not marketing promises.

---

## ✅ v1.4 — Current Release

> Focus: **Post-Quantum State-of-the-Art Security**, **Observability**, **Relay Containerization**, and **Multi-Arch Pipelines**

- [x] **State-of-the-Art PQC Ephemeral Group Key Distribution (`PQC Key Wrapping`)**  
  Random 256-bit CSPRNG master session key ($K_{\text{sess}}$) wrapped inside hybrid **ML-KEM-768 + X25519 + Argon2id** PAKE tunnels for each subscriber, providing True Ephemeral Post-Quantum Forward Secrecy (PFS) across 1-to-N broadcast channels.  
  _Implemented in_: `pkg/crypto/cipher.go`, `pkg/feed/publisher.go`, `pkg/feed/subscriber.go`

- [x] **Thread-Safe AEAD Cipher Engine**  
  `sync.RWMutex` synchronization across `Cipher` struct methods (`UpdateKey`, `Encrypt`, `Decrypt`, `Close`) ensuring 100% thread-safety during active key ratcheting.  
  _Implemented in_: `pkg/crypto/cipher.go`

- [x] **Relay Memory-Leak Prevention (Automated Session Reaper)**  
  Periodic background worker (`reapStaleSessions()`) running every 2 minutes in `pkg/relay/server.go` to purge orphaned sessions lacking active connections, eliminating long-term RAM accumulation.  
  _Implemented in_: `pkg/relay/server.go`, `pkg/relay/session.go`

- [x] **Structured JSON logging mode** (`--log-format json`)  
  Zero-dependency machine-readable log output on `stderr` built with Go stdlib `log/slog` for CI/CD pipelines and log aggregators (Loki, Datadog) without leaking payload content or cryptographic key material.  
  _Implemented in_: `pkg/logger/logger.go`, `main.go`

- [x] **Production Dockerization for Relay Node**  
  Multi-stage static non-root Alpine container (`Dockerfile` & `docker-compose.yml`) with automated healthchecks on `/metrics` endpoint (~12 MB).  
  _Implemented in_: `Dockerfile`, `docker-compose.yml`

- [x] **Automated CI/CD Release Pipelines & Multi-arch Container Registry**  
  GitHub Actions matrix (`release.yml` & `ci.yml`) generating static binaries for `darwin/arm64`, `darwin/amd64`, `linux/amd64`, `linux/arm64`, `windows/amd64`, `android/arm64` and pushing multi-arch Docker images to `ghcr.io`.  
  _Implemented in_: `.github/workflows/release.yml`, `scripts/build_release.sh`

---

## 🗓️ Planned Engineering Tasks (Next Sprint)

- [ ] **WASM Zero-Copy Uint8Array Buffer Interface**  
  Refactor `cmd/wasm/main.go` to accept `js.TypedArray` / `Uint8Array` directly via `js.CopyBytesToGo()` instead of hex/plain Go `string` objects, eliminating immutable string memory leaks in browser V8/WebKit heaps.

- [ ] **Resilient `handleSyncRequests` Worker Loop**  
  Refactor the background `handleSyncRequests` goroutine in `publisher.go` so temporary socket timeouts or network resets do not terminate the sync listener permanently.

- [ ] **Dynamic Lowest-RTT Relay Selection (Active Latency Probing)**  
  Enhance `pkg/feed/relay_list.go` with parallel ICMP/TCP RTT latency probing to automatically select the lowest-latency relay node (EU, US, Asia).

- [ ] **Production Domain Migration & Cloudflare Infrastructure (`relay.zerofeed.app`)**  
  Migrate public relay endpoint from DuckDNS (`zerofeed.duckdns.org`) to dedicated custom production domain `relay.zerofeed.app` behind Cloudflare Free Tier + Let's Encrypt TLS.

- [ ] **Continuous PQC Performance Benchmark Suite**  
  Create benchmark scripts in `scripts/` measuring handshake latency and CPU memory overhead of ML-KEM-768 hybrid key exchange on Native CLI vs WASM.


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
