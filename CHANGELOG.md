# Changelog

All notable changes to **ZeroFeed** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.3.0] - 2026-08-10

### 🚀 Features & Enhancements
- **Stateless Invites & Multi-Relay Fallback**: Zero-knowledge client-generated invites (`zerofeed invite` / `zerofeed join`) and multi-relay connection list handling.
- **Short Authentication String (SAS) Badges**: Out-of-band Anti-MITM verification displaying 8-hex fingerprints and 4-emoji visual badges (`[🛡️ ⚡ 🚀 💎]`).
- **In-Stream Key Rekeying**: Perfect Forward Secrecy (PFS) ratcheting every 1 GB or 1 hour with automatic parent key zeroization.

### 🧹 Code Quality & Linter Cleanups
- **Zero-Allocation String Formatting**: Replaced `[]byte(fmt.Sprintf(...))` with `fmt.Appendf(nil, ...)` in relay server (`pkg/relay/server.go`) and e2e tests (`test/e2e/rekey_test.go`).
- **WebSocket Protocol Parser**: Refactored frame length checks in `pkg/relay/websocket.go` from `if/else` chains to clean tagged `switch payloadLen`.
- **CSS Compatibility**: Added standard `background-clip: text;` property in `ZeroFeed-Landing/styles.css`.
- **IDE / GOPLS Integration**: Added `.vscode/settings.json` specifying `"buildFlags": ["-tags=quic"]` to eliminate LSP missing package warnings on build-constrained QUIC files.

### 🏷️ Version Alignment
- **Software Release Alignment**: Harmonized software release version strings to `v1.3.0` across CLI, Go `pkg/version`, WASM engine (`cmd/wasm`), release build scripts (`scripts/build_release.sh`), and landing page badge (`ZeroFeed-Landing/index.html`).
- **Wire Protocol Spec Clarification**: Documented explicit distinction between **Software Release v1.3.0** and **Wire Protocol Envelope Version 0x02** (`ZFED` 38-byte binary frame header & HKDF domain strings).
