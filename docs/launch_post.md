# HackerNews / Reddit / ProductHunt Launch Post (ZeroFeed v1.3.0)

## Title Option 1 (Recommended for Show HN):
> **Show HN: ZeroFeed – Post-Quantum, Zero-Knowledge Pub/Sub CLI & WASM Engine**

## Title Option 2 (Recommended for r/netsec / r/golang):
> **ZeroFeed v1.3: NIST FIPS 203 ML-KEM-768 + X25519 Hybrid E2EE Pub/Sub in Pure Go & WASM**

---

## Post Body:

Hi Hacker News & Security Community,

I'm excited to share **ZeroFeed v1.3.0**: a zero-knowledge, Post-Quantum hybrid encrypted pub/sub CLI utility, Go engine, and WASM web client designed for streaming sensitive payloads (API tokens, configs, live Docker logs, database dumps, multi-file archives) across untrusted networks.

### 🛡️ Why ZeroFeed?

Existing secret-sharing tools often rely on centralized web services that store encrypted payloads in databases or S3 buckets. Tools like `croc` or `magic-wormhole` are great for one-off file transfers, but not optimized for continuous, RAM-only pub/sub streaming, WebAssembly in-browser decryption, or Post-Quantum key exchange.

ZeroFeed adheres strictly to 6 core engineering principles:

1. **Post-Quantum Hybrid E2EE (NIST FIPS 203 ML-KEM-768 + X25519 PAKE)**:
   Key exchange combines Post-Quantum Kyber/ML-KEM-768 lattice cryptography (`golang.org/x/crypto/mlkem` by Google's Go Crypto Team) with classical X25519 PAKE via a Dual-Input HKDF Key Combiner (aligned with **ACN Italia July 2024 PQC Guidance**, **NIST FIPS 203**, and **ETSI TS 103 744**). Protects against "Store Now, Decrypt Later" quantum attacks.

2. **Stateless Rendezvous & Client-Generated Invites**:
   Intermediate relays maintain **zero persistent state**, **zero databases**, and **zero payload logs**. Invites (`zerofeed invite [code]`) generate 100% client-side terminal ASCII banners, `zerofeed://` native URIs, and Web `#join=` URL hash fragments for instant browser decryption.

3. **Short Authentication String (SAS) Visual Badges**:
   Displays a deterministic 8-hex character fingerprint and 4-emoji visual badge (`[🛡️ ⚡ 🚀 💎]`) on both subscriber and publisher terminals after PAKE completion for instant out-of-band Anti-MITM verification.

4. **In-Stream Key Rekeying & Backpressure Flow Control**:
   Automatic AES-256-GCM AEAD key ratcheting every 1 GB transferred or every 1 hour, immediately zeroizing parent keys in RAM. Watermark-driven flow control (`HighWatermark` 80% / `LowWatermark` 40%) pauses fast publishers on slow subscriber sessions to prevent relay RAM saturation.

5. **OS & Memory Hygiene (`mlockall` + `DisableCoreDumps` + `ZeroBytes`)**:
   Prevents sensitive key paging to disk via `mlockall(MCL_CURRENT|MCL_FUTURE)`, disables core dump creation via `setrlimit(RLIMIT_CORE, 0)`, and scrubs key slices using `crypto.ZeroBytes()` with `runtime.KeepAlive()` to prevent compiler dead-store elimination.

6. **Dual Transport (TCP/QUIC for CLI & WebSocket for WASM)**:
   The CLI communicates over native TCP / QUIC (`:8443`), while browser clients decrypt streams in-browser via WebAssembly over WebSocket (`:8444`). Try it live against our public RAM-only Oracle Cloud relay (`92.4.216.150:8443` in Turin `eu-turin-1`):
   👉 **Web Landing Page**: https://nicolainzerillo.github.io/ZeroFeed-Landing/

---

### 💻 Real-World Use Cases & CLI Recipes:

**1. Stream Remote Docker Logs Live (E2EE):**
```bash
# On Remote Server:
docker logs -f prod_container | zerofeed publish --channel prod-logs --stream

# On Dev Laptop:
zerofeed join zerofeed://join?code=prod-logs
```

**2. Zero-Disk Database Backup Migration (PostgreSQL):**
```bash
# On Source DB Server:
pg_dump -U postgres prod_db | zerofeed publish --channel db-snap --stream

# On Target DB Server:
zerofeed subscribe --code db-snap --stream | psql -U postgres staging_db
```

**3. Stream Multiple PDFs / Folders E2EE (`tar` Pipe):**
```bash
# Publisher:
tar -czf - doc1.pdf doc2.pdf doc3.pdf | zerofeed publish --channel cipher-falcon-orbit-948201 --stream

# Subscriber:
zerofeed subscribe --code cipher-falcon-orbit-948201 --stream | tar -xzf -
```

**4. 1-Click Self-Hosted RAM-Only Docker Relay:**
```bash
docker run -d --name zerofeed-relay -p 8443:8443/tcp -p 8443:8443/udp -p 8444:8444/tcp -p 9090:9090/tcp --read-only zerofeed/relay:v1.3.0
```

---

### ⚖️ Threat Model & Cryptographic Boundaries

To maintain absolute transparency with security researchers:

- **Standardized PQC Math**: ZeroFeed does not implement custom lattice math; it uses `golang.org/x/crypto/mlkem` maintained by Google's Go Crypto Team.
- **Dual-Input HKDF Combiner**: Hybrid key exchange combines X25519 PAKE ($S_{\text{pake}}$) and ML-KEM-768 ($S_{\text{kem}}$) via $\text{HKDF-SHA256}(S_{\text{pake}} \parallel S_{\text{kem}})$, modelled after Signal PQXDH.
- **Zero-Knowledge Relay (ZKR) Architecture**: ZeroFeed uses a Zero-Knowledge Relay Architecture. The relay matches session IDs via Argon2id Blind HMAC tags without knowing passphrases, session keys, or payload contents. (ZeroFeed does not use ZK-SNARKs; "Zero-Knowledge" refers to intermediate relay blindness).
- **IP Anonymity & Traffic Analysis**: ZeroFeed guarantees payload confidentiality and authenticity. It does not hide IP addresses or traffic timing against global network adversaries. For full IP anonymity, run ZeroFeed over **Tor** (`torsocks zerofeed ...`) or **I2P**.
- **Native CLI vs Web WASM Trust Boundary**: The native Go CLI is the primary target for maximum side-channel resistance (`mlockall` + `DisableCoreDumps`). Web WASM on GitHub Pages is provided as a convenience preview client.

---

### 🔍 Technical FAQ & Cryptographic Deep Dive

**Q: Are you using custom PQC lattice math?**
> **A:** No. ZeroFeed relies strictly on `golang.org/x/crypto/mlkem`, the FIPS 203 ML-KEM-768 implementation maintained directly by Google's Go Cryptography Team.

**Q: How are low-entropy human codes protected against offline dictionary brute-force attacks by malicious relays?**
> **A:** Before performing the hybrid X25519 PAKE + ML-KEM-768 key exchange, ZeroFeed passes human passphrases through **Argon2id** (`64 MB RAM, time=1, threads=1`). The relay only sees a 32-byte Blind HMAC match tag derived from Argon2id (`DeriveBlindMatchTag`). A malicious relay cannot test guessed passphrases offline without computing memory-hard Argon2id hashes for every candidate code.

**Q: How do you prevent Go Garbage Collector & stack movement from leaking key material in RAM?**
> **A:** On startup, ZeroFeed calls `crypto.LockMemory()` which executes `mlockall(MCL_CURRENT|MCL_FUTURE)` on Linux/macOS to lock process memory pages and disable swap paging. Additionally, core dumps are explicitly disabled via `setrlimit(RLIMIT_CORE, 0)` (`DisableCoreDumps()`), and all cryptographic buffers are zeroed using `crypto.ZeroBytes()` bound with `runtime.KeepAlive()` to block compiler optimization passes.

---

### 📦 Code & Architecture Specs:

- **GitHub Repository**: https://github.com/nicolainzerillo/ZeroFeed
- **Web Landing Page & WASM**: https://nicolainzerillo.github.io/ZeroFeed-Landing/
- **PQC State-of-the-Art Hub**: https://github.com/nicolainzerillo/ZeroFeed-PQC-StateOfTheArt

I'd love to hear your feedback on the architecture, Post-Quantum PAKE framing, or protocol zero-knowledge design!
