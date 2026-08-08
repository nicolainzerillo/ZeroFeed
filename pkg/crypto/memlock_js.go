//go:build js || wasm

package crypto

// LockMemory is a WebAssembly/JS fallback stub for memory locking.
func LockMemory() error {
	return nil
}

// DisableCoreDumps is a WebAssembly/JS fallback stub for disabling core dumps.
func DisableCoreDumps() error {
	return nil
}
