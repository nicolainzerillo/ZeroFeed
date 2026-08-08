# HackerNews / Reddit Launch Post Draft

## Title Option 1:
> **Show HN: ZeroFeed – Zero-knowledge, ephemeral E2EE Pub/Sub CLI in pure Go**

## Title Option 2:
> **ZeroFeed: RAM-only, end-to-end encrypted pub/sub CLI and Go library**

---

## Post Body:

Hi Hacker News,

I built **ZeroFeed**: a lightweight, zero-dependency command-line utility and pure Go library for streaming sensitive payloads (API tokens, configs, live Docker logs, database dumps, multi-file archives) between nodes with zero-knowledge E2EE guarantees.

### Why build ZeroFeed?
Existing secret-sharing tools often rely on centralized web services that store encrypted payloads in databases or S3 buckets (even if temporary). Tools like `croc` or `magic-wormhole` are great for one-off file transfers, but not optimized for continuous, RAM-only pub/sub streaming or Unix pipeline composition.

ZeroFeed was built around a few strict architectural constraints:

1. **Zero-Knowledge & Ephemerality**: Payloads reside strictly in RAM and are never written to disk on intermediate servers or relay nodes.
2. **Pure Go Stdlib (0 Dependencies)**: Built entirely using Go standard library primitives (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/sha256`, `net`, `sync`). Static binary size is ~3.8 MB.
3. **E2EE & SPAKE2 PAKE**: Mutual key exchange via SPAKE2 (Curve25519) and payload encryption via AES-256-GCM AEAD.
4. **Standby & Reconnect Resilience**: Monotonic 64-bit sequence numbers (`SeqNum uint64`) with an in-memory 100-message circular replay buffer. If a subscriber experiences a Wi-Fi drop or laptop sleep, it auto-reconnects with exponential backoff and catches up without data loss.
5. **Compiler-Safe Memory Zeroing**: Sensitive key buffers are zeroed using `runtime.KeepAlive` to prevent compiler optimization routines from stripping memory wipes.

---

### Real-World Use Cases & Recipes:

**1. Stream Remote Docker Logs Live (E2EE):**
```bash
# On Remote Server:
docker logs -f prod_container | zerofeed publish --channel prod-logs --stream

# On Dev Machine:
zerofeed subscribe --code prod-logs --stream
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
tar -czf - doc1.pdf doc2.pdf doc3.pdf | zerofeed publish --channel 5-omega-phoenix --stream

# Subscriber:
zerofeed subscribe --code 5-omega-phoenix --stream | tar -xzf -
```

The code and full protocol spec are open-source: https://github.com/zerofeed/zerofeed

I'd love to hear your feedback on the architecture, protocol framing, or cryptographic design!
