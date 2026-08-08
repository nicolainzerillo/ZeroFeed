//go:build windows

package crypto

// LockMemory is a Windows fallback stub for memory locking.
func LockMemory() error {
	// Memory locking on Windows requires VirtualLock or SetProcessWorkingSetSize.
	// For standard unprivileged execution, this is a graceful no-op.
	return nil
}

// DisableCoreDumps is a Windows fallback stub for disabling core dumps.
func DisableCoreDumps() error {
	// Core dumps on Windows are managed via WerRegisterMemoryBlock or system crash dump settings.
	return nil
}
