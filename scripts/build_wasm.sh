#!/usr/bin/env bash
# ZeroFeed WebAssembly Compilation & Distribution Script
# Compiles cmd/wasm/main.go to zerofeed.wasm and copies wasm_exec.js to ZeroFeed-Landing.

set -euo pipefail

TARGET_DIR="${TARGET_DIR:-../ZeroFeed-Landing}"
GOROOT_VAL="$(go env GOROOT)"

echo "[+] Compiling ZeroFeed WebAssembly engine (GOOS=js GOARCH=wasm)..."
GOOS=js GOARCH=wasm go build -o "${TARGET_DIR}/zerofeed.wasm" ./cmd/wasm

if [ -f "${GOROOT_VAL}/misc/wasm/wasm_exec.js" ]; then
    echo "[+] Copying standard Go wasm_exec.js runtime loader..."
    cp "${GOROOT_VAL}/misc/wasm/wasm_exec.js" "${TARGET_DIR}/wasm_exec.js"
elif [ -f "${GOROOT_VAL}/lib/wasm/wasm_exec.js" ]; then
    echo "[+] Copying standard Go wasm_exec.js runtime loader from lib/wasm..."
    cp "${GOROOT_VAL}/lib/wasm/wasm_exec.js" "${TARGET_DIR}/wasm_exec.js"
fi

echo "[✓] WebAssembly build complete!"
echo "    Artifact 1: ${TARGET_DIR}/zerofeed.wasm ($(du -h "${TARGET_DIR}/zerofeed.wasm" | awk '{print $1}'))"
echo "    Artifact 2: ${TARGET_DIR}/wasm_exec.js"
