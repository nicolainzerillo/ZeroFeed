# ZeroFeed Public Relay Node — Knowledge Base & Deployment Specs

> **Public Relay Endpoint**: `YOUR_RELAY_IP:8443` (Oracle Cloud Always Free — Turin `eu-turin-1`, EU)  
> **Supported Ports**: `8443` (Raw TCP & QUIC UDP), `8444` (WebSocket)  
> **Jurisdiction & Privacy**: European Union (RAM-Only Zero-Disk Ephemerality)

---

## 1. Public Relay Architecture (Oracle Cloud EU-Turin-1)

1. **Turin (`eu-turin-1`) Hub Node**:
   - Hosted on Oracle Cloud Always Free ARM instance (`VM.Standard.A1.Flex`, 1 OCPU, 6 GB RAM).
   - IP: `YOUR_RELAY_IP` — permanent static reserved public IP.
   - Serves as the default zero-configuration matchmaking relay for ZeroFeed CLI users worldwide.
   - **Cost**: Always Free — no credit card charges, no trial expiry.

2. **RAM-Only Ephemeral Routing**:
   - Operating in volatile RAM memory with zero disk persistence, zero databases, and zero message logs.
   - All session buffers and key slices are wiped via `crypto.ZeroBytes()` and `runtime.KeepAlive()` upon stream closure.

3. **Zero-Knowledge Blind Matchmaking**:
   - Relays route encrypted frames using 32-byte **Blind HMAC Match Tags** derived from Argon2id.
   - The public relay never possesses user passphrases, session encryption keys, or unencrypted payload data.

---

## 2. Oracle Cloud Deployment Notes

1. **Systemd Service**:
   - Service: `zerofeed-relay.service` — `enabled`, starts automatically on reboot.
   - Binary: `/usr/local/bin/zerofeed` (static ARM64, ~7.3 MB).
   - Logs: `journalctl -u zerofeed-relay -f`

2. **Firewall Configuration**:
   - OS-level: `firewalld` — ports 8443/tcp, 8443/udp, 8444/tcp, 9090/tcp open.
   - VCN Security List: Ingress rules open for all 4 ports from `0.0.0.0/0`.
   - SSH Access: `ssh -i ~/.ssh/id_ed25519 opc@YOUR_RELAY_IP`

3. **QUIC UDP Buffer**:
   - `net.core.rmem_max=7340032` and `net.core.wmem_max=7340032` set in `/etc/sysctl.conf`.

4. **TLS Behaviour**:
   - The relay runs plain TCP on port 8443 (no TLS termination).
   - Clients probe TLS first (2.5s timeout) then fall back to plain TCP automatically.
   - QUIC connections use QUIC's built-in TLS 1.3.

---

## 3. Real-World WAN Performance & Network Specs

- **EU WAN Latency**: ~20 - 35 ms round-trip latency across European endpoints.
- **Relay Matchmaking Latency**: `< 1 ms` in-memory Blind HMAC tag lookup and stream binding.
- **Wire Overhead**: 33 Bytes minimum envelope per frame (`ZFED` magic header + MsgType + 16B SessionID + 12B Nonce).
- **Flow Control**: 512KB sliding window ACKs with 32KB binary data chunks.

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
# Subscribe using Public Oracle Relay (QUIC UDP)
./zerofeed sub --code "channel-name" --relay "YOUR_RELAY_IP:8443" --quic --stream

# Publish using Public Oracle Relay (QUIC UDP)
./zerofeed pub --code "channel-name" --relay "YOUR_RELAY_IP:8443" --quic --stream

# Subscribe using plain TCP fallback
./zerofeed sub --code "channel-name" --relay "YOUR_RELAY_IP:8443" --stream
```

---

## 6. Server Management

```bash
# SSH into relay server
ssh -i ~/.ssh/id_ed25519 opc@YOUR_RELAY_IP

# Check service status
sudo systemctl status zerofeed-relay

# View live logs
sudo journalctl -u zerofeed-relay -f

# Redeploy (from local Mac)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags quic -ldflags="-s -w" -o bin/zerofeed-linux-arm64 main.go
scp -i ~/.ssh/id_ed25519 bin/zerofeed-linux-arm64 opc@YOUR_RELAY_IP:/tmp/zerofeed-new
ssh -i ~/.ssh/id_ed25519 opc@YOUR_RELAY_IP "sudo systemctl stop zerofeed-relay && sudo mv /tmp/zerofeed-new /usr/local/bin/zerofeed && sudo systemctl start zerofeed-relay"
```
