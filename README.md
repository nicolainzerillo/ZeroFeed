# ZeroFeed ⚡

> **Post-Quantum End-to-End Encrypted (E2EE) Multicast Streaming Protocol & WebAssembly Engine**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![PQC Standard](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--768-purple?style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-Client--Side%20RAM-blue?style=flat-square&logo=webassembly)](https://nicolainzerillo.github.io/ZeroFeed-Landing/)
[![Live WSS Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen?style=flat-square&logo=github)](https://nicolainzerillo.github.io/ZeroFeed-Landing/)
[![License](https://img.shields.io/badge/License-Apache%202.0%20%2F%20AGPLv3-orange?style=flat-square)](LICENSE)

ZeroFeed is a minimalist, zero-dependency command-line utility and pure Go engine designed for secure, real-time transmission of sensitive payloads (configurations, secrets, API tokens, terminal logs, database dumps, files) between CLI nodes and web browser clients.

Built with **Zero-Knowledge Ephemeral Transit** at its core: no payload data is EVER written to disk on intermediate relay servers, and all transmissions execute strictly via in-memory E2EE streams that self-destruct upon session completion.

---

## 📺 Live WebAssembly Streaming Demo

Experience zero-install, client-side E2EE WebAssembly decryption directly in your browser:
👉 **[Launch Interactive WebAssembly Subscriber](https://nicolainzerillo.github.io/ZeroFeed-Landing/)**

---

## 🌟 Key Architectural Features

- **🔒 Zero-Knowledge & Zero-Disk Storage**: 100% RAM-only execution on relay nodes (`0 bytes written to disk, 0 databases, 0 payload logs`). The relay cannot decrypt or inspect payloads.
- **🛡️ NIST FIPS 203 Hybrid Post-Quantum Cryptography**: SPAKE2+ hybrid key exchange combining **ML-KEM-768** (Module-Lattice Key Encapsulation) + **X25519** with **Argon2id** memory-hardening to protect against "Store Now, Decrypt Later" quantum attacks.
- **📡 1-to-N Multicast Streaming**: Broadcast real-time streams concurrently from 1 CLI Publisher to N Subscribers (mix of CLI terminals and in-browser WASM instances).
- **🌐 Native Client-Side WebAssembly (WASM)**: Decrypt payloads in real-time inside browser RAM without installing local binaries, browser extensions, or creating user accounts.
- **🇮🇹 Technical Alignment with ACN Guidelines**: Engineered in technical alignment with Italian National Cybersecurity Agency (ACN) guidelines for Quantum-Safe Hybrid Key Exchanges (ACN Luglio 2024 directives).
- **🛡️ SAS Visual Verification Badges**: Short Authentication String (SAS) 4-element emoji/hex badges generated on client endpoints to visually confirm zero Man-in-the-Middle (MitM) interference.
- **⚡ Zero External Dependencies**: 100% written in pure Go stdlib (`crypto/mlkem`, `crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/sha256`, `net`, `sync`).
- **🔁 Standby & Replay Resilience**: In-memory 100-message circular ring replay buffer with automatic reconnect backoff and stream replay upon Wi-Fi drops.

---

## 📐 Architecture & Protocol Overview

ZeroFeed uses a high-performance **38-byte fixed binary envelope (`ZFED`)** for zero-copy binary frame routing over TCP/QUIC and WSS (WebSocket Secure).

```text
       [ PUBLISHER CLI ]                                           [ SUBSCRIBER (CLI / WASM) ]
             │                                                                  │
             │ ── (1) PAKE Init (MsgType 0x01) ─────────────────►              │
             │                                                  │               │
             │ ◄── (2) PAKE Sub Response (MsgType 0x02) ────────┼────────────── │
             │                                                  │               │
             │ ── (3) PAKE Step 2 (MsgType 0x03) ──────────────┼──────────────► │
             │     [ Shared E2EE Key Derived via ML-KEM-768 ]   │               │
             │                                                  │               │
             │                                          ┌───────────────┐       │
             │ ── (4) AES-256-GCM Stream (0x04) ──────►│ RELAY SERVER  │─────► │
             │     (Encrypted Payload in RAM)           │ Zero-Knowledge│       │
             │                                          └───────────────┘       │
             │                                                                  │
             └──────────────────────────────────────────────────────────────────┘
```

### Public Relay Specs (Oracle Cloud Always Free Node)
- **Primary Public Relay IP**: `92.4.216.150:8443` (TCP & QUIC UDP) — Turin `eu-turin-1` node.
- **WSS TLS Endpoint**: `wss://zerofeed.duckdns.org:8444/` (Native Let's Encrypt TLS).
- **Default Zero-Config**: CLI binaries automatically connect to the public relay if `--relay` is omitted.

---

## 🚀 Quickstart & Installation

### Build from Source
```bash
# Clone repository
git clone https://github.com/nicolainzerillo/ZeroFeed.git
cd ZeroFeed

# Build CLI binary
go build -tags quic -o bin/zerofeed main.go

# Install globally
go install -tags quic github.com/nicolainzerillo/ZeroFeed@latest
```

### Basic CLI Usage

#### 1. Start Publisher Stream (CLI)
```bash
# Auto-generates a random high-entropy channel code and web link
./bin/zerofeed pub --stream

# Or specify a custom channel code
./bin/zerofeed pub -c my-secret-channel --stream
```

#### 2. Subscribe (CLI)
```bash
./bin/zerofeed sub -c my-secret-channel --stream
```

#### 3. Subscribe via Browser (WebAssembly)
Open the generated Web Link or visit:
`https://nicolainzerillo.github.io/ZeroFeed-Landing/#join=zerofeed://join?code=my-secret-channel`

---

## 💡 Real-World Developer Use Cases & Recipes

ZeroFeed composes natively with Unix pipelines (`cat`, `tail`, `docker`, `pg_dump`, `tar`, `grep`) for zero-disk encrypted operations:

### 1. 🐳 Stream Live Remote Docker Container Logs
```bash
# On Remote Production Server (Publisher)
docker logs -f prod_api_gateway | zerofeed pub -c prod-gateway-logs --stream

# On Developer Machine (Subscriber CLI)
zerofeed sub -c prod-gateway-logs --stream
```

### 2. 🔑 Securely Inject `.env` Secrets into CI/CD Runners
```bash
# On Security Workstation (Publisher)
cat .env.production | zerofeed pub -c ci-deploy-key --ttl 2m --stream

# In CI/CD Runner Script (Subscriber)
zerofeed sub -c ci-deploy-key --stream > .env
```

### 3. 🗄️ Zero-Disk Database Backup Stream (PostgreSQL / MySQL)
```bash
# On Database Server (Publisher)
pg_dump -U postgres production_db | zerofeed pub -c db-migration-snap --stream

# On Target Database Server (Subscriber)
zerofeed sub -c db-migration-snap --stream | psql -U postgres staging_db
```

### 4. 📦 Stream Multiple PDFs / Folders E2EE (`tar` Pipe)
```bash
# Publisher (Send directory or multiple files)
tar -czf - doc1.pdf doc2.pdf | zerofeed pub -c 5-omega-phoenix --stream

# Subscriber (Receive & extract automatically)
zerofeed sub -c 5-omega-phoenix --stream | tar -xzf -
```

---

## 💻 CLI Command Reference

```bash
# Start Standalone Ephemeral Relay Node (with Prometheus metrics on port 9090)
zerofeed relay -port 8443 -ws-port 8444 -quic -metrics-addr 0.0.0.0:9090

# Subscribe to Channel Code
zerofeed sub -c test1234 --stream

# Publish Interactive Input or Pipe Stream
zerofeed pub -c test1234 --ttl 5m --stream
```

---

## 🧪 Testing & Verification

ZeroFeed maintains unit and integration test suites with zero data races.

Run short unit test suite:
```bash
go test -short -tags quic ./...
```

Run integration test suite with race detector enabled:
```bash
go test -v -race -tags quic ./...
```

---

## ⚖️ License & Dual-Structure

- **Client CLI, Package SDK & WASM Engine** (`main.go`, `pkg/crypto`, `pkg/feed`, `pkg/protocol`, `cmd/wasm`): Distributed under the **Apache License 2.0**.
- **Relay Server Engine** (`pkg/relay`): Distributed under the **GNU Affero General Public License v3.0 (AGPLv3)** to protect open-source infrastructure from unauthorized commercial SaaS re-selling.

See `LICENSE` and `pkg/relay/LICENSE` for details.

---

## ⚠️ Disclaimer & Acceptable Use Policy

ZeroFeed is an open-source security utility engineered strictly for legitimate data privacy, developer pipeline operations, and authorized security research. Maintainers disclaim any liability for unauthorized or illegal third-party activities.
