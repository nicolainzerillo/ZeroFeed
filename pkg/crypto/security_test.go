package crypto_test

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

func TestSecuritySystemCalls(t *testing.T) {
	// Test LockMemory (may return non-fatal error if unprivileged in test container)
	err := crypto.LockMemory()
	if err != nil {
		t.Logf("LockMemory returned non-fatal info: %v", err)
	}

	// Test DisableCoreDumps
	err = crypto.DisableCoreDumps()
	if err != nil {
		t.Errorf("DisableCoreDumps failed: %v", err)
	}
}

func TestWipeAllRegistry(t *testing.T) {
	secret1 := []byte("SUPER_SECRET_PASSPHRASE_REGISTERED_001")
	secret2 := []byte("CONFIDENTIAL_AEAD_PAYLOAD_REGISTERED_02")

	ptr1 := unsafe.Pointer(&secret1[0])
	len1 := len(secret1)
	ptr2 := unsafe.Pointer(&secret2[0])
	len2 := len(secret2)

	customWiped := false
	crypto.RegisterWiper(func() {
		customWiped = true
	})
	crypto.RegisterBuffer(secret1)
	crypto.RegisterBuffer(secret2)

	crypto.WipeAll()

	if !customWiped {
		t.Errorf("custom wipe callback was not executed")
	}

	bytes1 := unsafe.Slice((*byte)(ptr1), len1)
	for i, b := range bytes1 {
		if b != 0x00 {
			t.Errorf("secret1 byte %d was not zeroed: got 0x%02x", i, b)
		}
	}

	bytes2 := unsafe.Slice((*byte)(ptr2), len2)
	for i, b := range bytes2 {
		if b != 0x00 {
			t.Errorf("secret2 byte %d was not zeroed: got 0x%02x", i, b)
		}
	}

	runtime.KeepAlive(secret1)
	runtime.KeepAlive(secret2)
}

func TestUnregisterBuffer(t *testing.T) {
	crypto.ClearWipers()
	buf := []byte("TEMPORARY_EPHEMERAL_STREAM_BUFFER_001")
	crypto.RegisterBuffer(buf)
	crypto.UnregisterBuffer(buf)

	// WipeAll should not wipe buf because it was unregistered
	crypto.WipeAll()

	if string(buf) != "TEMPORARY_EPHEMERAL_STREAM_BUFFER_001" {
		t.Errorf("unregistered buffer was unexpectedly zeroed")
	}
}
