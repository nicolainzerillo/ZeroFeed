# ZeroFeed ⚡

> **Zero-Knowledge Payload Encryption · End-to-End Encrypted · Ephemeral Pub/Sub CLI & Go Engine**

ZeroFeed is a lightweight, zero-dependency command-line utility and pure Go library designed for secure, real-time transmission of sensitive payloads (configurations, secrets, API tokens, logs, small files) between Publisher and Subscriber nodes. 

Built with **Zero-Knowledge Payload Encryption** at its core: no payload data is EVER written to disk on intermediate servers or relay nodes, and all transmissions execute strictly via in-memory E2EE streams that self-destruct upon delivery or session timeout (TTL). Session metadata (IP addresses, timestamps, byte counts) is not encrypted at the relay level — see [Security Whitepaper § Metadata Limits](docs/security.md) for the full threat model.

---

## 📚 Technical Documentation & Guides

- 🛡️ **[Security & Cryptographic Whitepaper](docs/security.md)**: SPAKE2 PAKE, AES-256-GCM AEAD, threat model, memory zeroing, and DoS defenses.
- ⚙️ **[DevOps & Deployment Guide](docs/deployment.md)**: Docker container (< 5 MB), Docker Compose, Systemd Linux service, and Cloudflare Tunnel setups.
- 💻 **[Go Library API Guide](docs/api_guide.md)**: Programmatic integration guide for embedding ZeroFeed into custom Go projects.
- 📐 **[Wire Protocol Specification](docs/protocol.md)**: Binary frame envelope specification (`ZFED` 38-byte header).
- 🏗️ **[Internal Architecture](docs/architecture.md)**: Software design, package structure, and concurrency model.

---

## 🌟 Key Features

- **🔒 Zero-Knowledge Payload Encryption & Zero-Disk Storage**: 100% RAM-only execution. No databases, temp files, or disk logs. The relay cannot decrypt your payload. Session metadata (IPs, timing) is visible to the relay — [details](docs/security.md#4-zero-knowledge-scope--metadata-limits).
- **🛡️ Post-Quantum Hybrid E2EE**: NIST FIPS 203 ML-KEM-768 + X25519 hybrid Password-Authenticated Key Exchange (PAKE) combined with Argon2id memory-hardening and AES-256-GCM AEAD payload encryption.
- **🇮🇹 Technical Alignment with ACN Guidelines**: Engineered in technical alignment with Italian National Cybersecurity Agency (ACN) guidelines for Quantum-Safe Hybrid Key Exchanges (ACN Luglio 2024 & 2026 directives).
- **⚡ Zero External Dependencies**: 100% written in pure Go stdlib (`crypto/mlkem`, `crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/sha256`, `net`, `sync`).
- **🔁 Standby & Auto-Sync Resilience**: In-memory 100-message circular replay buffer (`SeqNum uint64`) with automatic reconnect backoff and stream replay upon Wi-Fi drop or standby.
- **🧹 Compiler-Safe Memory Zeroing**: Explicit byte-buffer scrubbing powered by `runtime.KeepAlive` to prevent compiler dead-code elimination.
- **🛡️ Anti-Brute-Force Rate Limiting**: Built-in IP rate-limiting engine enforcing temporary bans after 3 failed PAKE authentication attempts.

---

## 📐 Architecture & Protocol Overview

ZeroFeed uses a high-performance **38-byte fixed binary envelope (`ZFED`)** for zero-copy binary frame routing.

```
       [ PUBLISHER ]                                               [ SUBSCRIBER ]
             │                                                           │
             │ ── (1) PAKE Init (MsgType 0x01) ───────────►             │
             │                                              │            │
             │ ◄── (2) PAKE Response (MsgType 0x02) ────────┼─────────── │
             │                                              │            │
             │ ── (3) PAKE Complete (MsgType 0x03) ─────────┼──────────► │
             │     [ Shared Key Derived via PAKE ]          │            │
             │                                              │            │
             │                                      ┌───────────────┐    │
             │ ── (4) AES-256-GCM Stream (0x04) ──►│ RELAY SERVER  │──► │
             │     (Encrypted Payload in RAM)       │ Zero-Knowledge│    │
             │                                      └───────────────┘    │
             │                                                           │
             └───────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### macOS / Linux
```bash
# Build from source
go build -o zerofeed main.go

# Or install globally
go install github.com/zerofeed/zerofeed@latest
```

### Windows
```cmd
# Cross-compile for Windows from Mac/Linux
GOOS=windows GOARCH=amd64 go build -o zerofeed.exe main.go

# Or build natively in Windows PowerShell / Command Prompt
go build -o zerofeed.exe main.go
```

---

## 💡 Real-World Developer Use Cases & Recipes

ZeroFeed composes natively with Unix pipelines (`cat`, `tail`, `docker`, `pg_dump`, `tar`, `grep`) for zero-disk encrypted operations:

### 1. 🐳 Stream Live Remote Docker Container Logs
```bash
# On Remote Production Server (Publisher)
docker logs -f prod_api_gateway | zerofeed publish --channel prod-gateway-logs --stream

# On Developer Machine (Subscriber)
zerofeed subscribe --code prod-gateway-logs --stream
```

### 2. 🔑 Securely Inject `.env` Secrets into CI/CD Runners
```bash
# On Security Workstation (Publisher)
cat .env.production | zerofeed publish --channel ci-deploy-key --ttl 2m --stream

# In CI/CD Runner Script (Subscriber)
zerofeed subscribe --code ci-deploy-key --stream > .env
```

### 3. 🗄️ Zero-Disk Database Backup Stream (PostgreSQL / MySQL)
```bash
# On Database Server (Publisher)
pg_dump -U postgres production_db | zerofeed publish --channel db-migration-snap --stream

# On Target Database Server (Subscriber)
zerofeed subscribe --code db-migration-snap --stream | psql -U postgres staging_db
```

### 4. 📦 Stream Multiple PDFs / Folders E2EE (`tar` Pipe)
```bash
# Publisher (Send multiple PDFs or directory)
tar -czf - doc1.pdf doc2.pdf doc3.pdf | zerofeed publish --channel 5-omega-phoenix --stream

# Subscriber (Receive & extract automatically)
zerofeed subscribe --code 5-omega-phoenix --stream | tar -xzf -
```

---

## 💻 CLI Command Reference

```bash
# Start Standalone Relay Node (with Prometheus Observability on port 9090)
zerofeed relay --port 8443 --metrics-port 9090

# Subscribe to Channel
zerofeed subscribe --code 5-omega-phoenix --relay 127.0.0.1:8443 --stream

# Publish Interactive or Pipe Stream
zerofeed publish --channel 5-omega-phoenix --ttl 5m --stream
```

---

## 🧪 Testing & Verification

ZeroFeed maintains 100% unit and integration test coverage with 0 data races.

Run the test suite with race detector enabled:
```bash
go test -v -race ./...
```

---

## 🤖 Development Philosophy & AI Assistance

ZeroFeed was architected and built using modern AI pair-programming tools (Google Antigravity SDK) as interactive coding partners. 

Following pragmatic open-source engineering principles:
- **Human Architecture**: All cryptographic protocol boundaries, memory locking logic, and stateless relay designs were architected and directed by the human maintainer.
- **AI Acceleration**: AI tools were utilized to accelerate unit test writing, cross-platform build scripts, and edge-case code verification.
- **100% Manual Audit & Verification**: Every line of code has been audited, formatted with `gofmt`, checked via `go vet`, and verified for zero data-races (`go test -race`).

---

## ⚖️ Dual License Structure

- **Client CLI, Package SDK & Engine** (`main.go`, `pkg/crypto`, `pkg/feed`, `pkg/protocol`, WASM): Distributed under the **Apache License 2.0** for zero-friction integration.
- **Relay Server Engine** (`pkg/relay`): Distributed under the **GNU Affero General Public License v3.0 (AGPLv3)** to protect the open-source infrastructure from unauthorized commercial cloud SaaS re-selling.

See `LICENSE` and `pkg/relay/LICENSE` for details.

---

## ⚠️ Disclaimer of Liability & Acceptable Use Policy

ZeroFeed is an open-source security utility engineered strictly for privacy compliance, legitimate data encryption, and authorized developer pipeline operations.

- **Limitation of Liability**: ZeroFeed is provided "AS IS", without warranty of any kind. In no event shall the author or maintainers be liable for any claim, damages, or legal liabilities arising from the use or misuse of the software.
- **No Liability for Misuse**: The author explicitly disclaims any responsibility for illegal, malicious, or unethical activities conducted by third parties. Users are solely responsible for ensuring compliance with all local and international laws.
