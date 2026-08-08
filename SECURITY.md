# Security Policy & Responsible Vulnerability Disclosure

ZeroFeed prioritizes the security, confidentiality, and integrity of zero-knowledge, end-to-end encrypted transmissions. We appreciate the work of security researchers and open-source audit contributors.

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

## Security Commitments

- **Memory Safety**: RAM buffers containing key material or plaintext are scrubbed using `runtime.KeepAlive()` to prevent compiler optimization dead-store elimination.
- **Memory Locking**: On supported platforms, process pages are locked (`mlock`) to prevent paging to swap space.
- **Core Dump Disabling**: Crash dumps (`RLIMIT_CORE = 0`) are disabled by default.
- **CSPRNG**: Cryptographic key material and nonces use `crypto/rand`.

---

## ⚠️ Disclaimer of Liability & Acceptable Use Policy

ZeroFeed is an open-source software project engineered strictly as a defensive security utility for privacy compliance (GDPR / EU NIS2), data encryption, and authorized developer operations.

- **"AS IS" Basis & Limitation of Liability**: ZeroFeed is provided "AS IS", without warranty of any kind, express or implied. In no event shall the author, maintainers, or copyright holders be liable for any claim, damages, or other liability arising from, out of, or in connection with the software or the use of the software.
- **No Liability for Third-Party Misuse**: The author, maintainers, and contributors explicitly disclaim any responsibility or legal liability for illegal, unauthorized, malicious, or unethical activities conducted by third parties using ZeroFeed.
- **User Responsibility**: Users of ZeroFeed are solely responsible for ensuring that their deployment, data transmission, and usage comply with all applicable local, national, and international laws and regulations.
