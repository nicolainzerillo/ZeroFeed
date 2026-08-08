//go:build unix || linux || darwin

package crypto

import (
	"fmt"
	"syscall"
)

// LockMemory attempts to lock the current and future process memory pages in RAM,
// preventing the operating system from swapping sensitive cryptographic material to disk.
func LockMemory() error {
	err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	if err != nil {
		return fmt.Errorf("zerofeed/crypto: mlockall failed: %w", err)
	}
	return nil
}

// DisableCoreDumps sets the RLIMIT_CORE resource limit to 0, ensuring that no core dump
// memory snapshots are written to disk in the event of a critical process crash.
func DisableCoreDumps() error {
	var rlim syscall.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlim)
	if err != nil {
		return fmt.Errorf("zerofeed/crypto: setrlimit RLIMIT_CORE failed: %w", err)
	}
	return nil
}
