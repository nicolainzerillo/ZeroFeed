# Security Policy, Threat Model & Known Limitations

ZeroFeed prioritizes the security, confidentiality, and integrity of zero-knowledge, end-to-end encrypted transmissions. We appreciate the work of security researchers and open-source audit contributors.

---

## 🛡️ Threat Model & Explicit Security Boundaries

To maintain complete transparency with security auditors, ZeroFeed explicitly defines its security boundaries and known operational trade-offs:

### 1. "Zero-Knowledge Relay" (ZKR) Architecture
- **Scope**: ZeroFeed uses a **Zero-Knowledge Relay (ZKR) Architecture**. The relay server operates 100% in volatile RAM with zero disk persistence, zero databases, and zero payload logging.
- **Relay Knowledge**: Relays match publisher and subscriber sessions via 32-byte Argon2id Blind HMAC tags (`DeriveBlindMatchTag`). Relays **never** possess passphrases, master keys, session keys, or unencrypted payload contents.
- **ZK-Proof Clarification**: ZeroFeed does not use Zero-Knowledge Proofs (zk-SNARKs/zk-STARKs); the term "Zero-Knowledge" refers to the Zero-Knowledge Relay boundary (untrusted intermediate nodes learn zero data about payload contents).

### 2. Network Metadata & IP Anonymity
- **Boundary**: ZeroFeed guarantees **payload confidentiality and authenticity** against network eavesdroppers and untrusted relay operators.
- **Traffic Analysis**: E2EE does not mask network-level metadata (IP addresses of publisher/subscriber, packet throughput timing, or block sizes) against global network adversaries.
- **Recommended Anonymity Layer**: For complete IP anonymity and connection unlinkability, users should run the ZeroFeed CLI over **Tor** (`torsocks zerofeed ...`) or **I2P**.

### 3. Post-Quantum Hybrid Handshake MTU Overhead
- **Framing**: NIST FIPS 203 ML-KEM-768 wire frames require ~1216 bytes for `MsgTypePAKEInitSub` and ~1120 bytes for `MsgTypePAKEInitPub`.
- **MTU Safety**: Wire messages are explicitly engineered to fit under standard 1500-byte Ethernet MTUs, preventing IP-level fragmentation across standard networks.
- **Transport Reliability**: Over TCP and QUIC, transport stream framing handles loss recovery automatically.

### 4. Side-Channel Protections: Native CLI vs Web WASM
- **Native CLI**: Uses OS-level memory locking (`mlockall`), core dump disabling (`RLIMIT_CORE = 0`), and native Go constant-time operations (`subtle.ConstantTimeCompare`) for maximum side-channel resistance.
- **Web WASM Client**: WebAssembly execution inside browser JIT compilers (V8/SpiderMonkey) is provided as a zero-installation convenience preview. For high-security environments, the native Go CLI is recommended.

### 5. Relay DoS & Resource Saturation Defense
- **IP Rate Limiting**: Abuse detection bans IPs after 3 failed PAKE attempts or malformed frame injections (`pkg/relay/ratelimit.go`).
- **Watermark Backpressure**: High Watermark (80%) and Low Watermark (40%) flow control pauses publisher ingestion if a subscriber reads slowly, preventing unbounded RAM accumulation.
- **Bounded Bumper Queues**: Bounded subscriber queues (`SubscriberQueueSize = 200`) enforce strict RAM ceilings on relay nodes.

### 6. In-Stream Key Rekeying & Stream Order Guarantee
- **PFS Rekeying**: In-stream key ratcheting (`MsgTypeRekey`) occurs every 1 GB or 1 hour, immediately zeroizing parent keys in RAM.
- **Ordered Delivery**: Over TCP and QUIC stream transports, frame sequence numbers (`seqNum uint64`) are strictly ordered, preventing out-of-order rekeying decryption failures.

---

## Reporting a Vulnerability

> [!CAUTION]
> **Do NOT create public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability, cryptographic weakness, or memory safety defect in ZeroFeed:

1. **Email Contact**: Send a private report to `security@zerofeed.dev` (or submit a private vulnerability advisory via GitHub Security Advisories).
2. **Details to Include**:
   - Description of the vulnerability and affected packages (`pkg/crypto`, `pkg/protocol`, `pkg/relay`, `pkg/feed`).
   - Proof of concept (PoC) code or steps to reproduce.
   - Any proposed remediation or patch.
3. **Response SLA**: We acknowledge receipt of vulnerability reports within **24 hours** and aim to provide patch timelines within **72 hours**.

---

## ⚠️ Disclaimer of Liability & Acceptable Use Policy

ZeroFeed is an open-source software project engineered strictly as a defensive security utility for privacy compliance (GDPR / EU NIS2), data encryption, and authorized developer operations.

- **"AS IS" Basis & Limitation of Liability**: ZeroFeed is provided "AS IS", without warranty of any kind, express or implied.
- **No Liability for Third-Party Misuse**: The maintainers explicitly disclaim any legal liability for illegal or unauthorized activities conducted by third parties.
