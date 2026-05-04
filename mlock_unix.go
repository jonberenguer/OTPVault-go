//go:build !windows

package main

import "syscall"

// mlockBytes pins b in physical RAM so the OS cannot swap it to disk.
// Best-effort: errors are silently ignored.
func mlockBytes(b []byte) {
	if len(b) > 0 {
		syscall.Mlock(b) //nolint:errcheck
	}
}

// munlockBytes releases the mlock on b. Call before zeroing.
func munlockBytes(b []byte) {
	if len(b) > 0 {
		syscall.Munlock(b) //nolint:errcheck
	}
}
