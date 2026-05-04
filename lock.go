package main

import (
	"os"
	"path/filepath"
)

var instanceLockFile *os.File

func lockFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "otp-vault.lock"
	}
	return filepath.Join(filepath.Dir(exe), "otp-vault.lock")
}
