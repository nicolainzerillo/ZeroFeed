# Security Policy, Threat Model & Cryptographic Specifications

ZeroFeed prioritizes the security, confidentiality, and integrity of zero-knowledge, end-to-end encrypted transmissions. We appreciate the work of security researchers and open-source audit contributors.

---

## 🛡️ Threat Model & Cryptographic Architecture

To maintain complete transparency with security auditors, ZeroFeed explicitly defines its cryptographic primitives, security boundaries, and operational trade-offs:

### 1. Standardized PQC Primitives (`golang.org/x/crypto/mlkem`)
- **No Custom Lattice Math**: ZeroFeed **does not** implement custom lattice sampling or un-audited PQC math.
- **Official Implementation**: Post-Quantum ML-KEM-768 lattice key encapsulation relies strictly on **`golang.org/x/crypto/mlkem`**, maintained directly by Google's Go Cryptography Team (FIPS 203 compliant).

### 2. State-of-the-Art PQC Ephemeral Group Key Distribution (`Key Wrapping`)
- **Composition Model**: The Publisher generates a 256-bit CSPRNG random master session key ($K_{\text{sess}}$). For each connecting subscriber, the key exchange establishes an ephemeral hybrid **ML-KEM-768 + X25519 + Argon2id** point-to-point tunnel secret ($K_{\text{p2p}}$).
- **Key Wrapping**: $K_{\text{sess}}$ is encrypted inside $K_{\text{p2p}}$ using AES-256-GCM (`WrapSessionKey`) and delivered to subscribers inside `MsgTypePAKEStep2` envelopes.
- **Security Guarantee**: Provides **True Ephemeral Post-Quantum Forward Secrecy (PFS)** across 1-to-N broadcast channels. Even if the passphrase is later compromised, past session recordings cannot be decrypted because $K_{\text{sess}}$ was generated randomly in RAM by the Publisher's CSPRNG and transported over quantum-safe ephemeral tunnels.

### 3. "Zero-Knowledge Relay" (ZKR) Architecture
- **Relay Blindness**: Relays operate 100% in volatile RAM with zero disk persistence, zero databases, and zero payload logging. Relays match sessions via 32-byte Argon2id Blind HMAC tags (`DeriveBlindMatchTag`).
- **Relay Knowledge**: Relays **never** possess passphrases, master keys, session keys, or unencrypted payload contents.
- **ZK Terminology**: "Zero-Knowledge" refers to intermediate relay blindness (ZKR); ZeroFeed does not use zk-SNARKs or zk-STARKs.

### 4. Trust Boundaries: Native CLI vs Web WASM
- **Native CLI (Gold Standard)**: Recommended for high-security threat models. Includes OS memory locking (`mlockall`), core dump disabling (`RLIMIT_CORE = 0`), and constant-time operations (`subtle.ConstantTimeCompare`).
- **Web WASM Client (Preview/Demo)**: Provided as a zero-installation convenience client. Browser WASM execution relies on Web PKI and CDN integrity (GitHub Pages); for hostile threat environments, users should execute locally compiled binaries verified via `SHA256SUMS`.

### 5. Network Metadata & Tor Anonymity
- **Boundary**: ZeroFeed guarantees **payload confidentiality and authenticity** against network eavesdroppers and untrusted relay operators.
- **Traffic Analysis**: E2EE does not hide network IP addresses or traffic timing against global adversaries. For complete IP anonymity, users should run ZeroFeed over **Tor** (`torsocks zerofeed ...`) or **I2P**.

### 6. Relay DoS Defense & PoW Roadmap
- **Relay Rate Limiting**: Abuse detection bans IPs after 3 failed PAKE attempts or malformed frame injections (`pkg/relay/ratelimit.go`).
- **Backpressure Flow Control**: High Watermark (80%) and Low Watermark (40%) flow control pauses publisher ingestion if a subscriber reads slowly, preventing unbounded RAM accumulation.
- **Proof-of-Work Roadmap**: Public relays are courtesy ephemeral rendezvous nodes. Natively integrated Hashcash Proof-of-Work (PoW) channel reservation is planned for v1.4.

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
