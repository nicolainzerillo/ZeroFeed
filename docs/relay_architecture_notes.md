# ZeroFeed Public Relay Node — Knowledge Base & Deployment Specs

> **Public Relay Endpoint**: `66.241.125.54` (Fly.io Datacenter: Frankfurt `fra`, EU)  
> **Supported Ports**: `443` (TCP), `8443` (Raw TCP & QUIC UDP)  
> **Jurisdiction & Privacy**: European Union (RAM-Only Zero-Disk Ephemerality)

---

## 1. Public Frankfurt Relay Architecture

1. **Frankfurt (`fra`) Hub Node**:
   - Hosted on Fly.io Anycast Infrastructure in Frankfurt, Germany (`66.241.125.54`).
   - Serves as the default zero-configuration matchmaking relay for ZeroFeed CLI users worldwide.

2. **RAM-Only Ephemeral Routing**:
   - Operating in volatile RAM memory with zero disk persistence, zero databases, and zero message logs.
   - All session buffers and key slices are wiped via `crypto.ZeroBytes()` and `runtime.KeepAlive()` upon stream closure.

3. **Zero-Knowledge Blind Matchmaking**:
   - Relays route encrypted frames using 32-byte **Blind HMAC Match Tags** derived from Argon2id.
   - The public relay never possesses user passphrases, session encryption keys, or unencrypted payload data.

---

## 2. Real-World WAN Performance & Network Specs

- **EU WAN Latency**: ~20 - 35 ms round-trip latency across European endpoints.
- **Global Anycast Edge**: Sub-50 ms RTT connection establishment via Fly.io edge routing.
- **Relay Matchmaking Latency**: `< 1 ms` in-memory Blind HMAC tag lookup and stream binding.
- **Wire Overhead**: 33 Bytes minimum envelope per frame (`ZFED` magic header + MsgType + 16B SessionID + 12B Nonce).
- **Flow Control**: 512KB sliding window ACKs with 32KB binary data chunks.

---

## 3. Fly.io Deployment & Port Handler Gotchas

1. **Port 443 TCP Handler (`EOF` Fix)**:
   - On `fly.toml`, port 443 TCP has `handlers = ["tls"]` by default.
   - Raw CLI clients connecting over TCP without TLS proxy encapsulation receive `EOF`.
   - **Public Fix**: Use raw UDP port 8443 for QUIC streams (`--quic --relay 66.241.125.54:8443`), or deploy custom raw TCP listener without `handlers = ["tls"]`.

2. **Container Footprint**:
   - Scratch Linux ARM64 image size: `< 5 MB`.
   - RAM allocation limit: `64 MB`.

---

## 4. Security & DoS Protection Rules

1. **Magic Header Drop (`ZFED`)**:
   - Drops incoming TCP/UDP connections immediately if the first 4 bytes do not match ASCII `0x5A 0x46 0x45 0x44` (`ZFED`).
2. **Rate Limiting & Blacklisting**:
   - Blacklists client IPs that send malformed frames or fail PAKE validation more than 3 times.
3. **Replay Buffer**:
   - Maintains an in-memory 100-message circular replay buffer indexed by 64-bit monotonic sequence numbers to allow subscriber reconnects after Wi-Fi drops.

---

## 5. Quick CLI Usage with Public Relay

```bash
# Subscribe using Public Frankfurt Relay (QUIC UDP)
./zerofeed sub --code "channel-name" --relay "66.241.125.54:8443" --quic --stream

# Publish using Public Frankfurt Relay (QUIC UDP)
./zerofeed pub --code "channel-name" --relay "66.241.125.54:8443" --quic --stream
```
