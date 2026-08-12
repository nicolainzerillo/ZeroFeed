#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo " ZeroFeed Production Release Cross-Builder"
echo "========================================="

OUTPUT_DIR="./bin/release"
mkdir -p "${OUTPUT_DIR}"

VERSION="v1.4.0"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "release")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w -X github.com/zerofeed/zerofeed/pkg/version.Version=${VERSION} -X github.com/zerofeed/zerofeed/pkg/version.GitCommit=${GIT_COMMIT} -X github.com/zerofeed/zerofeed/pkg/version.BuildDate=${BUILD_DATE}"

echo "[1/6] Building for Linux ARM64 (AWS Graviton / Raspberry Pi / UTM)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-linux-arm64" ./main.go

echo "[2/6] Building for Linux AMD64 (x86_64 Cloud / Servers)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-linux-amd64" ./main.go

echo "[3/6] Building for macOS ARM64 (Apple Silicon M1/M2/M3/M4)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-darwin-arm64" ./main.go

echo "[4/6] Building for macOS AMD64 (Intel Macs)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-darwin-amd64" ./main.go

echo "[5/6] Building for Windows AMD64 (x86_64 Windows PCs)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-windows-amd64.exe" ./main.go

echo "[6/6] Building for Android ARM64 (Pocophone / Mobile / Termux)..."
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags quic -ldflags="${LDFLAGS}" -o "${OUTPUT_DIR}/zerofeed-android-arm64" ./main.go

echo ""
echo "Generating SHA-256 Checksums for Release Integrity Verification..."
(cd "${OUTPUT_DIR}" && shasum -a 256 zerofeed-* > SHA256SUMS)

echo "========================================="
echo " Release binaries generated successfully in ${OUTPUT_DIR}/:"
ls -lh "${OUTPUT_DIR}"
echo "========================================="
