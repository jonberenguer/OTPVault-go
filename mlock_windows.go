//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mlockBytes pins b in physical RAM via VirtualLock.
// Best-effort: errors are silently ignored.
func mlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))) //nolint:errcheck
}

// munlockBytes releases the VirtualLock on b. Call before zeroing.
func munlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))) //nolint:errcheck
}
