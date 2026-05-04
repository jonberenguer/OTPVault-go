//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func acquireInstanceLock() bool {
	f, err := os.OpenFile(lockFilePath(), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return true // can't create lock file; allow startup rather than block the user
	}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0,
		new(windows.Overlapped),
	)
	if err != nil {
		f.Close()
		return false
	}
	instanceLockFile = f // keep open to hold the lock for the process lifetime
	return true
}
