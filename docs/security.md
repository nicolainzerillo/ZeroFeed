# ZeroFeed Security & Cryptographic Specification Whitepaper

> **Version**: v1.3.0 (Wire Protocol Spec 0x02)  
> **Audience**: Security Engineers, Cryptographers, and Security Auditors

This whitepaper details the threat model, cryptographic primitives, memory management policies, and security guarantees enforced by **ZeroFeed v1.3.0** (utilizing Wire Protocol v2 format).

---

## 1. Threat Model & Security Goals

ZeroFeed is designed under a **Zero-Knowledge, Zero-Trust Relay Model**.

### Attacker Capabilities & Assumptions
1. **Untrusted Relay Node**: Intermediate relay servers, cloud providers, and network switches are assumed to be potentially malicious or compromised.
2. **Passive & Active Network Interception**: Attackers may intercept, inspect, replay, or inject arbitrary TCP packets on the network wire.
3. **No Persistent Disk Storage**: Payloads must NEVER touch physical storage media (HDDs/SSDs/SWAP) on intermediate servers.

### Security Guarantees
- **Confidentiality**: Only endpoints possessing the shared passphrase can decrypt transmitted payloads.
- **Integrity & Authenticity**: AEAD authentication tags ensure any bit flip, truncation, or tampering of ciphertext leads to immediate decryption failure and drop.
- **Forward Secrecy**: Ephemeral PAKE keys are generated per session and wiped from RAM upon connection termination.
- **Session Anonymity**: Cleartext Session IDs in wire envelope headers are derived via HKDF-SHA256 with domain salts to prevent rainbow table attacks.
- **Replay Protection**: Monotonic 64-bit sequence numbers (`SeqNum uint64`) combined with AES-GCM 96-bit nonces prevent replay attacks.

---

## 2. Cryptographic Architecture (v2.0)

### A. Password-Authenticated Key Exchange (PAKE)
ZeroFeed uses **Curve25519** (`crypto/ecdh`) key agreement combined with HKDF passphrase blinding and HMAC-SHA256 key confirmation tags.

1. **Wire Blinding Mask**:
   $$\text{Mask} = \text{HKDF-SHA256}(\text{Passphrase}, \text{"zerofeed-v2-pake-blinding-salt:"} \parallel \text{role}, \text{"zerofeed-v2-pake-wire-mask"}, 32)$$
2. **Blinded Wire Transmission**:
   $$\text{PubBlinded} = \text{RawPubKey} \oplus \text{Mask}$$
3. **Shared Secret Derivation & Handshake Auth**:
   $$\text{SharedSecret} = \text{ECDH}(\text{PrivKey}, \text{PeerPubKey})$$
   $$\text{MasterKey} = \text{HKDF-SHA256}(\text{SharedSecret}, \text{Passphrase}, \text{"zerofeed-v2-pake-master-secret"}, 32)$$
   $$\text{HandshakeTag} = \text{HMAC-SHA256}(\text{MasterKey}, \text{"zerofeed-v2-pake-handshake-auth"} \parallel \text{role})$$

### B. Symmetric Key Derivation & AEAD Encryption
Symmetric session keys are derived using HKDF-SHA256 (RFC 5869):

$$\text{SessionID} = \text{HKDF-SHA256}(\text{Passphrase}, \text{"zerofeed-v2-session-id-salt"}, \text{"zerofeed-v2-session-id-context"}, 16)$$
$$\text{AEAD Key} = \text{HKDF-SHA256}(\text{Passphrase}, \text{"zerofeed-v2-session-key-salt:"} \parallel \text{SessionID}, \text{"zerofeed-v2-hkdf-aead"}, 32)$$

Payloads are encrypted using **AES-256-GCM** with a cryptographically secure random 96-bit nonce (`crypto/rand`).

### C. SAS (Short Authentication String) Visual Verification
To protect against active MITM attackers intercepting handshake exchanges, ZeroFeed computes a 24-bit **Short Authentication String (SAS)** derived from SHA-256 hash of the master session key:

$$\text{SASHash} = \text{SHA-256}(\text{SessionKey})$$
$$\text{SAS Hex} = \text{HexEncode}(\text{SASHash}[0:2]) \quad (\text{e.g. } \text{"8F3A"})$$
$$\text{SAS Emoji} = \text{EmojiMap}(\text{SASHash}[2]) \parallel \text{EmojiMap}(\text{SASHash}[3]) \quad (\text{e.g. } \text{"🛡️⚡"})$$

Both Publisher and Subscriber display the SAS badge upon handshake completion (`🛡️⚡ [8F3A]`). Users out-of-band compare these 4 characters / 2 emojis to confirm zero active middleman interception.


---

## 4. Zero-Knowledge Scope & Metadata Limits

ZeroFeed guarantees **zero-knowledge with respect to payload content**: the relay cannot decrypt, read, or store the data being transmitted.

However, the relay **does observe the following session metadata** (held in RAM, never written to disk):

| Metadata | Visible to Relay? | Notes |
| :--- | :--- | :--- |
| Publisher IP address | ✅ Yes | Required for TCP/QUIC connection routing |
| Subscriber IP address | ✅ Yes | Required for TCP/QUIC connection routing |
| Session start / end timestamps | ✅ Yes | Used for TTL and heartbeat enforcement |
| Bytes transferred per session | ✅ Yes | Used for flow control and rate limiting |
| Connection frequency / patterns | ✅ Yes | Derivable from relay logs |
| Payload plaintext content | ❌ No | AES-256-GCM E2EE, relay has no keys |
| Session encryption keys | ❌ No | Derived end-to-end via PAKE, never sent to relay |
| Passphrases / channel codes | ❌ No | Never transmitted in cleartext |

**This metadata is not cryptographically protected.** A relay operator (or an attacker who has compromised the relay) can perform traffic analysis and correlation attacks based on IP addresses and timing patterns.

> **Recommendation**: If your threat model requires anonymity of *who communicates with whom* (not just *what* they transmit), route ZeroFeed through Tor or a trusted VPN before connecting to the public relay.

---

## 3. RAM Scrubbing & Memory Zeroization

To mitigate cold-boot attacks and process RAM dumps:
1. **Byte Slice Secrets**: Passphrases and master keys are maintained as zeroable `[]byte` slices instead of immutable strings.
2. **Explicit Zeroization**: Sensitive scalar slices, AES keys, and plaintext buffers are explicitly overwritten with `0x00` immediately after use.
3. **Compiler Optimization Defense**: Go compilers may optimize away trailing zeroization loops if the variable is no longer read (*Dead Code Elimination*). ZeroFeed defends against this by invoking `runtime.KeepAlive(b)` on zeroed byte slices:
   ```go
   func ZeroBytes(b []byte) {
       for i := range b {
           b[i] = 0
       }
       runtime.KeepAlive(b)
   }
   ```
4. **Buffer Reuse Pooling**: Ring buffers use `sync.Pool` for payload buffer reuse and zeroing to prevent memory fragmentation.

> **Known Limitation**: The Go runtime may internally copy slice backing arrays during garbage collection, stack growth, or channel operations *before* `ZeroBytes` is called. This is an inherent property of the Go runtime and cannot be fully mitigated in pure Go without CGO. `ZeroBytes` is therefore **best-effort**: it reduces the window during which sensitive material resides in memory, but does not provide hardware-grade guarantees. For workloads requiring certified zeroization (e.g. FIPS 140-3 Level 2+), use an external HSM.

---

## 4. Network Rate-Limiting & DoS Defense

The Relay server implements thread-safe DoS protections (`pkg/relay/ratelimit.go` & `pkg/relay/server.go`):
- Tracks failed PAKE handshake attempts per client IP address.
- Enforces a 5-minute ban after 3 failed attempts.
- Enforces a maximum connection limit (`MaxActiveConnections = 10000`) to prevent goroutine exhaustion.
- Enforces 15-second connection read deadlines with 3-second heartbeat ping frames (`MsgTypeHeartbeat`) to purge half-open sockets automatically.

---

## 5. Responsible Vulnerability Disclosure

If you discover a security vulnerability in ZeroFeed, please submit an issue or contact the maintainers directly.

