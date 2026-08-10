//go:build quic

package e2e_test

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCLIQUICPubSubPipeline(t *testing.T) {
	// Build binary
	buildCmd := exec.Command("go", "build", "-tags", "quic", "-o", "../../bin/zerofeed-test-quic", "../../main.go")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Start Relay Server with --quic
	relayCmd := exec.CommandContext(ctx, "../../bin/zerofeed-test-quic", "relay", "--port", "18443", "--quic")
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("failed to start quic relay: %v", err)
	}
	defer func() {
		_ = relayCmd.Process.Kill()
	}()

	relayReady := false
	for i := 0; i < 30; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:18443", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			relayReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !relayReady {
		t.Fatalf("quic relay failed to start listening on 127.0.0.1:18443 within 3s")
	}

	passphrase := "e2e-quic-test-code-99"

	// 2. Start Subscriber with --quic
	subCmd := exec.CommandContext(ctx, "../../bin/zerofeed-test-quic", "subscribe", "--code", passphrase, "--relay", "127.0.0.1:18443", "--quic", "--stream")
	var subStdout, subStderr bytes.Buffer
	subCmd.Stdout = &subStdout
	subCmd.Stderr = &subStderr

	if err := subCmd.Start(); err != nil {
		t.Fatalf("failed to start subscriber: %v", err)
	}
	defer func() {
		_ = subCmd.Process.Kill()
	}()

	time.Sleep(300 * time.Millisecond)

	// 3. Start Publisher with --quic
	pubCmd := exec.CommandContext(ctx, "../../bin/zerofeed-test-quic", "publish", "--code", passphrase, "--relay", "127.0.0.1:18443", "--quic", "--stream")
	var pubStderr bytes.Buffer
	pubCmd.Stderr = &pubStderr

	pubStdin, err := pubCmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get pub stdin: %v", err)
	}

	if err := pubCmd.Start(); err != nil {
		t.Fatalf("failed to start publisher: %v", err)
	}
	defer func() {
		_ = pubCmd.Process.Kill()
	}()

	time.Sleep(1 * time.Second)

	// Send message over QUIC
	testMsg := "QUIC_E2EE_STREAM_PAYLOAD_LINE_01\n"
	_, _ = pubStdin.Write([]byte(testMsg))
	_ = pubStdin.Close()

	time.Sleep(1 * time.Second)

	cancel()
	_ = pubCmd.Wait()
	_ = subCmd.Wait()

	if !strings.Contains(subStdout.String(), "QUIC_E2EE_STREAM_PAYLOAD_LINE_01") {
		t.Fatalf("Subscriber did not receive expected QUIC payload. Got stdout: %q, subStderr: %q, pubStderr: %q", subStdout.String(), subStderr.String(), pubStderr.String())
	}
}
