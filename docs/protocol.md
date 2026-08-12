# ZeroFeed Wire Protocol Specification (v2.0)

This document defines the binary frame envelope, cryptographic exchange, and frame sequence specification of the **ZeroFeed Wire Protocol v2 (Header Version 0x02)** used in **ZeroFeed v1.3.0**.

---

## 1. Binary Envelope Header Format (`ZFED`)

All ZeroFeed control and stream messages are encapsulated in a fixed **38-byte binary header envelope** followed by an optional payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Magic Header (0x5A464544)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x02) |MsgType (0xNN) |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+                              +
|                                                               |
+                    Anonymized Session ID (16 Bytes)           +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                       AES Nonce (12 Bytes)                    |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |        Payload Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Payload Length (cont)         |    Payload Bytes (Variable)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 2. Message Types (`MsgType`)

| Code | Constant Name | Description |
| :--- | :--- | :--- |
| `0x01` | `MsgTypePAKEInitPub` | Publisher initial PAKE Step 1 payload frame |
| `0x02` | `MsgTypePAKEInitSub` | Subscriber initial PAKE Step 1 payload frame |
| `0x03` | `MsgTypePAKEStep2` | Publisher PAKE Step 2 response frame |
| `0x04` | `MsgTypeDataStream` | Encrypted sequence-numbered data payload frame |
| `0x05` | `MsgTypeHeartbeat` | Session keep-alive ping frame (emitted every 3s) |
| `0x06` | `MsgTypeClose` | Graceful session termination frame |
| `0x07` | `MsgTypeSyncReq` | Reconnecting Subscriber sequence catch-up request |

---

## 3. Data Stream Payload Structure (`MsgTypeDataStream` `0x04`)

When `MsgType` is `0x04`, the envelope payload contains an 8-byte BigEndian sequence number followed by AES-256-GCM ciphertext and MAC authentication tag.

```
+--------------------------+-----------------------------------+
|  SeqNum (8 Bytes uint64) |  AES-256-GCM Ciphertext + MAC Tag  |
+--------------------------+-----------------------------------+
```

---

## 4. Key Derivation & Cryptography (v2.0 Specifications)

1. **Session ID Anonymization**: 
   $$\text{SessionID} = \text{HKDF-SHA256}(\text{passphrase}, \text{"zerofeed-v2-session-id-salt"}, \text{"zerofeed-v2-session-id-context"}, 16)$$
   *Ensures cleartext Session IDs in wire headers cannot be reverse-mapped to passphrases.*

2. **Symmetric Key Derivation**: 
   $$\text{Salt} = \text{"zerofeed-v2-session-key-salt:"} \parallel \text{SessionID}$$
   $$\text{SessionKey} = \text{HKDF-SHA256}(\text{passphrase}, \text{Salt}, \text{"zerofeed-v2-hkdf-aead"}, 32)$$

3. **Curve25519 PAKE Exchange**:
   - Ephemeral Curve25519 ECDH key generation.
   - Wire payload blinded via HKDF passphrase masks.
   - Mutual handshake authentication validated via HMAC-SHA256 tags.

4. **Chunked Payload Decoding**:
   - Frame payloads are decoded incrementally in **64KB chunks** via `io.ReadFull` bounds checking to eliminate DoS memory pre-allocation vulnerabilities.

---

## 5. Uniform Traffic Padding Specifications (1280B Bucket Padding)

To defend against side-channel packet length analysis and traffic profiling:

1. **Text & Control Stream Payload Padding**:
   - Plaintext data stream payloads (`TagText`, `TagFileStart`, `TagFileEnd`) are prepended with a 2-byte big-endian `uint16` real payload length header.
   - The payload is padded with `0x00` bytes up to a uniform target size of **1280 bytes** (IPv6 Minimum MTU) prior to AES-256-GCM encryption.

2. **File Chunk Uniformity**:
   - Binary file chunks (`TagFileChunk`) maintain native fixed-size 64KB chunks (`65,536 bytes`).

3. **Wire View**:
   - To network observers and intermediate relay nodes, all stream frames are rendered uniform in size (1318 bytes for text/control frames: 38B header + 1280B padded ciphertext), completely hiding individual message lengths, keypress timing, and payload types.

