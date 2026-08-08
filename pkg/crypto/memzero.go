package crypto

import (
	"runtime"
	"sync"
	"unsafe"
)

var (
	wiperMu           sync.Mutex
	registeredWipers  []func()
	registeredBuffers [][]byte
	pinnedBuffers     map[uintptr]*runtime.Pinner
)

func init() {
	pinnedBuffers = make(map[uintptr]*runtime.Pinner)
}

// ZeroBytes explicitly overwrites the given byte slice with zero bytes (0x00)
// and calls runtime.KeepAlive to ensure the compiler does not optimize away the zeroing operation.
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}

	ptr := uintptr(unsafe.Pointer(unsafe.SliceData(b)))

	wiperMu.Lock()
	if pinner, ok := pinnedBuffers[ptr]; ok {
		pinner.Unpin()
		delete(pinnedBuffers, ptr)
	}
	wiperMu.Unlock()

	c := b[:cap(b)]
	for i := range c {
		c[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroBytesSlice cleans up multiple byte slices by overwriting their contents with zero bytes.
func ZeroBytesSlice(slices ...[]byte) {
	for _, s := range slices {
		ZeroBytes(s)
	}
}

// RegisterWiper registers a custom wipe callback function to be invoked on process termination or WipeAll.
func RegisterWiper(fn func()) {
	if fn == nil {
		return
	}
	wiperMu.Lock()
	defer wiperMu.Unlock()
	registeredWipers = append(registeredWipers, fn)
}

// RegisterBuffer registers a sensitive byte slice with the global wiping registry and pins it in RAM.
func RegisterBuffer(b []byte) {
	if len(b) == 0 {
		return
	}
	wiperMu.Lock()
	defer wiperMu.Unlock()

	registeredBuffers = append(registeredBuffers, b)

	ptr := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	if _, exists := pinnedBuffers[ptr]; !exists {
		pinner := new(runtime.Pinner)
		pinner.Pin(unsafe.SliceData(b))
		pinnedBuffers[ptr] = pinner
	}
}

// UnregisterBuffer removes a byte slice from the global wiping registry once it has been processed.
func UnregisterBuffer(b []byte) {
	if len(b) == 0 {
		return
	}
	targetPtr := unsafe.SliceData(b)
	ptr := uintptr(unsafe.Pointer(targetPtr))

	wiperMu.Lock()
	defer wiperMu.Unlock()

	if pinner, ok := pinnedBuffers[ptr]; ok {
		pinner.Unpin()
		delete(pinnedBuffers, ptr)
	}

	for i, reg := range registeredBuffers {
		if len(reg) > 0 && unsafe.SliceData(reg) == targetPtr {
			lastIdx := len(registeredBuffers) - 1
			registeredBuffers[i] = registeredBuffers[lastIdx]
			registeredBuffers[lastIdx] = nil
			registeredBuffers = registeredBuffers[:lastIdx]
			break
		}
	}
}

// ClearWipers resets the registered wipers and buffers.
func ClearWipers() {
	wiperMu.Lock()
	defer wiperMu.Unlock()

	for _, pinner := range pinnedBuffers {
		pinner.Unpin()
	}
	pinnedBuffers = make(map[uintptr]*runtime.Pinner)
	registeredWipers = nil
	registeredBuffers = nil
}

// WipeAll executes all registered wipe callbacks and zero-overwrites all registered byte buffers.
func WipeAll() {
	wiperMu.Lock()
	wipers := registeredWipers
	buffers := registeredBuffers
	registeredWipers = nil
	registeredBuffers = nil

	for _, pinner := range pinnedBuffers {
		pinner.Unpin()
	}
	pinnedBuffers = make(map[uintptr]*runtime.Pinner)
	wiperMu.Unlock()

	for _, w := range wipers {
		if w != nil {
			w()
		}
	}

	for _, b := range buffers {
		for i := range b {
			b[i] = 0
		}
	}

	runtime.KeepAlive(wipers)
	runtime.KeepAlive(buffers)
}
