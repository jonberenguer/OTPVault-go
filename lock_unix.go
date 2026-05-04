//go:build !windows

package main

import (
	"os"
	"syscall"
)

func acquireInstanceLock() bool {
	f, err := os.OpenFile(lockFilePath(), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return true // can't create lock file; allow startup rather than block the user
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return false
	}
	instanceLockFile = f // keep open to hold the lock for the process lifetime
	return true
}
