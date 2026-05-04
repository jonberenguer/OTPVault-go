# OTPVault — Claude Code Guide

## What this project is

A native Go desktop TOTP/HOTP authenticator built with Fyne. It replaces a Node.js/HTTP version
with a self-contained GUI binary that has no browser or network dependency. Secrets are stored in
`otp-accounts.json` (AES-256-GCM, Argon2id key derivation) next to the executable.

## File map

| File | Role |
|---|---|
| `main.go` | Fyne app entry point, all UI screens (lock, vault, add-account dialog) |
| `crypto.go` | Argon2id/PBKDF2 key derivation, AES-256-GCM encrypt/decrypt, HMAC-SHA256 verifier |
| `totp.go` | Base32 decode, HOTP (RFC 4226), TOTP (RFC 6238), `otpauth://` URI parser/builder |
| `store.go` | DB types (`Verifier`, `EncryptedSecret`, `Account`, `DB`), load/save JSON, `verifyPassword` |
| `lock.go` | Instance lock file path helper; `instanceLockFile` package var |
| `lock_unix.go` | `acquireInstanceLock` for Linux/macOS using `syscall.Flock` |
| `lock_windows.go` | `acquireInstanceLock` for Windows using `windows.LockFileEx` |
| `mlock_unix.go` | `mlockBytes`/`munlockBytes` — pin/unpin memory pages on Linux using `syscall.Mlock` |
| `mlock_windows.go` | `mlockBytes`/`munlockBytes` — pin/unpin memory pages on Windows using `VirtualLock` |
| `qr.go` | `showQRDialog` — renders account as a scannable QR code |
| `backup.go` | `exportBackup` / `importBackup` — encrypted backup file format |
| `importers.go` | Parsers for Google Authenticator migration, Aegis, and Bitwarden exports |
| `widgets.go` | `CountdownCircle` custom Fyne canvas widget |
| `icon.go` | Embedded app icon resource |
| `Dockerfile` | Multi-stage: `builder` → `test` → `export-linux` / `export-windows` |
| `Makefile` | `build-linux`, `build-windows`, `build-all`, `test`, `clean` |

## Build commands

Builds require Docker (Go and Fyne's system libs are handled inside the container).

```bash
make build-linux     # → dist/otpvault-linux-amd64
make build-windows   # → dist/otpvault-windows-amd64.exe
make build-all       # both targets in one pass
make test            # runs go test ./... inside builder
make clean           # removes dist/ and the test image
```

## No local Go required

`go mod tidy` runs inside Docker during the build. There is no `go.sum` committed — it is
generated fresh each build. Do not add `go.sum` to the repo.

## Crypto invariants — do not change without understanding

- **KDF (new secrets):** Argon2id — 64 MiB memory, 1 pass, 4 threads, 32-byte key, 16-byte random salt per secret. Written as `"kdf": "argon2id"` in `EncryptedSecret` and `Verifier`.
- **KDF (legacy read):** PBKDF2-SHA256, 200 000 iterations — used automatically when `kdf` field is absent or empty; never written for new secrets.
- **AES-256-GCM:** 12-byte IV, 16-byte auth tag — tag is appended to ciphertext then split on decrypt
- **Verifier:** HMAC-SHA256 of the sentinel string `"OTPVault-v1-verifier"` keyed with the derived key; uses its own dedicated stable salt (not regenerated on writes) so it can be reproduced on every unlock
- `checkVerifier` returns `"ok"` / `"wrong"` / `"missing"` — callers must handle all three
- `subtle.ConstantTimeCompare` is used for the HMAC comparison — do not replace with `==` or `bytes.Equal`
- **Password type:** `session.password` is `[]byte`, pinned in RAM with `mlockBytes`. All crypto functions take `[]byte`. Call `clearPassword()` (which calls `munlockBytes` + zero) before nilling the session. Call `clearSecrets()` too — both are called by the lock button, session timeout, tray Lock, and `SetOnStopped`.

## DB format

New vaults use `"kdf": "argon2id"` on each secret and the verifier. Legacy PBKDF2 vaults (no `kdf` field) are read-compatible. A password change migrates the entire vault to Argon2id in one atomic write.

HOTP accounts carry `"type": "hotp"` and `"counter": <uint64>`. TOTP accounts omit both fields (backward-compatible). `counter` is updated in-place by `updateCounter` after every HOTP code generation.

```json
{
  "verifier": { "kdf": "argon2id", "salt": "<base64>", "hmac": "<base64>" },
  "accounts": [
    {
      "id": "<uuid>",
      "name": "...",
      "issuer": "...",
      "secret": { "kdf": "argon2id", "salt": "<base64>", "iv": "<base64>", "tag": "<base64>", "data": "<base64>" },
      "digits": 6,
      "period": 30
    },
    {
      "id": "<uuid>",
      "name": "...",
      "secret": { ... },
      "digits": 6,
      "type": "hotp",
      "counter": 42
    }
  ]
}
```

`dbPath()` in `store.go` resolves the path relative to the executable, not the working directory.

## Session state

`activeSession` in `main.go` is the only place the master password lives at runtime. It is an `atomic.Pointer[session]`. On lock, call both `sess.clearPassword()` and `sess.clearSecrets()`, then `activeSession.Store(nil)`. Never persist or log the password value.

## Unlock flow

`doUnlock` in `showLockScreen` runs the expensive Argon2id operations inside a goroutine:
1. `mlockBytes(pw)` — pin the password bytes in RAM immediately, before the goroutine starts.
2. Goroutine: `loadDB()` → `verifyPassword()` (Argon2id) → decrypt all secrets → `activeSession.Store(sess)` → `showVault()`.
3. On failure: `munlockBytes(pw)`, zero the slice, re-enable the UI widgets.

## System tray

`main()` wires up a system tray (via `fyneApp.(desktop.App)`) with Show / Lock Vault / Quit items. The tray is only set up when the desktop environment supports it (the type assertion is a runtime check). Closing the main window hides it (`SetCloseIntercept`) rather than quitting; Quit must be chosen from the tray.

## UI refresh

`rebuildCards` is called every second via a `time.Ticker` goroutine started in `showVault`. The
goroutine checks `activeSession.Load() == nil` on each tick and stops itself when the vault is locked.
The ticker is not explicitly stopped on lock — it self-terminates on the next tick.

HOTP account cards show a `counter: N` label and a **Generate** button instead of a live code. Clicking Generate calls `generateHOTPCode(acc)` which: generates the code, calls `updateCounter` to increment and persist the counter, then shows the code in a dialog with a copy button.

## Adding a new UI screen

1. Write a `showXxx()` function that calls `mainWindow.SetContent(...)`.
2. Wire navigation by calling `showXxx()` from the relevant button handler.
3. Keep crypto/store calls out of `main.go` — call functions from `crypto.go` / `store.go` directly.

## Windows build notes

Cross-compilation uses `gcc-mingw-w64-x86-64` inside the Docker builder.
The `-H windowsgui` linker flag suppresses the console window on Windows — it must stay on the
`build-windows` go build command or users will see a black terminal behind the GUI.
