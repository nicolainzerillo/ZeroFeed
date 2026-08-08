package e2e_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type safeBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free TCP port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestCLIE2EPipeline(t *testing.T) {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "zerofeed")

	// 1. Compile zerofeed CLI binary
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../main.go")
	buildCmd.Env = os.Environ()
	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v, output: %s", err, string(output))
	}

	relayPort := getFreePort(t)
	relayAddr := fmt.Sprintf("127.0.0.1:%d", relayPort)

	// 2. Start Relay Server process
	relayCmd := exec.Command(binPath, "relay", "--port", fmt.Sprintf("%d", relayPort))
	var relayLog safeBuffer
	relayCmd.Stdout = &relayLog
	relayCmd.Stderr = &relayLog

	if err := relayCmd.Start(); err != nil {
		t.Fatalf("failed to start relay process: %v", err)
	}
	defer func() {
		_ = relayCmd.Process.Kill()
	}()

	time.Sleep(300 * time.Millisecond)

	passphrase := "cli-e2e-sha256-test-passphrase-2026"

	// Prepare 100 lines of data stream
	const lineCount = 100
	var inputBuffer bytes.Buffer
	inputHasher := sha256.New()

	for i := 1; i <= lineCount; i++ {
		line := fmt.Sprintf("E2E_STREAM_LINE_%04d_SECURE_TOKEN_%d\n", i, i*42)
		inputBuffer.WriteString(line)
		inputHasher.Write([]byte(strings.TrimSpace(line) + "\n"))
	}
	expectedHash := fmt.Sprintf("%x", inputHasher.Sum(nil))

	// 3. Start Publisher CLI process and pipe stdin
	pubCmd := exec.Command(binPath, "publish", "--channel", passphrase, "--relay", relayAddr)
	pubStdinWriter, err := pubCmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to get pub stdin pipe: %v", err)
	}

	var pubLog safeBuffer
	pubCmd.Stdout = &pubLog
	pubCmd.Stderr = &pubLog

	if err := pubCmd.Start(); err != nil {
		t.Fatalf("failed to start pub process: %v", err)
	}
	defer func() {
		_ = pubCmd.Process.Kill()
	}()

	time.Sleep(200 * time.Millisecond)

	// 4. Start Subscriber CLI process
	subCmd := exec.Command(binPath, "subscribe", "--code", passphrase, "--relay", relayAddr)
	subStdoutReader, err := subCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get sub stdout pipe: %v", err)
	}

	var subLog safeBuffer
	subCmd.Stderr = &subLog

	if err := subCmd.Start(); err != nil {
		t.Fatalf("failed to start sub process: %v", err)
	}
	defer func() {
		_ = subCmd.Process.Kill()
	}()

	// Write data stream to publisher stdin
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.Copy(pubStdinWriter, &inputBuffer)
		_ = pubStdinWriter.Close()
	}()

	// Read and hash output from subscriber stdout
	outputHasher := sha256.New()
	var receivedLines atomic.Int32
	doneChan := make(chan struct{})

	go func() {
		scanner := bufio.NewScanner(subStdoutReader)
		for scanner.Scan() {
			text := scanner.Text()
			if strings.HasPrefix(text, "E2E_STREAM_LINE_") {
				receivedLines.Add(1)
				outputHasher.Write([]byte(text + "\n"))
			}
		}
		if err := scanner.Err(); err != nil {
			t.Logf("scanner error: %v", err)
		}
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// Completed
	case <-time.After(8 * time.Second):
		t.Fatalf("CLI E2E test timed out! Received lines: %d / %d.\nPubLog:\n%s\nSubLog:\n%s\nRelayLog:\n%s",
			receivedLines.Load(), lineCount, pubLog.String(), subLog.String(), relayLog.String())
	}

	// 5. Verify bit-for-bit SHA-256 checksum and line count
	actualHash := fmt.Sprintf("%x", outputHasher.Sum(nil))

	if int(receivedLines.Load()) != lineCount {
		t.Errorf("expected %d received lines, got %d", lineCount, receivedLines.Load())
	}

	if actualHash != expectedHash {
		t.Errorf("SHA-256 Checksum mismatch!\nExpected: %s\nGot:      %s", expectedHash, actualHash)
	}
}
