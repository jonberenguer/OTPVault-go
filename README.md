# OTPVault

A portable, offline TOTP/HOTP authenticator for Linux and Windows. Secrets are encrypted at rest
with AES-256-GCM and a master password that is never written to disk.

## Features

- Native desktop GUI — no browser, no Node.js, no network
- AES-256-GCM encryption with Argon2id key derivation (memory-hard; legacy PBKDF2 vaults remain readable)
- HMAC-SHA256 vault verifier detects wrong passwords and tampered files
- Single self-contained binary — no installer, no runtime dependencies
- System tray icon — minimize to tray; Show / Lock / Quit from tray menu

**Accounts**
- Add accounts manually, by URI, or by bulk import from Google Authenticator, Aegis, or Bitwarden
- TOTP: live circular countdown per token; HOTP: on-demand code generation with counter persistence
- One-click copy to clipboard — clears automatically after 30 seconds
- Show account as a QR code — scan directly into any TOTP/HOTP authenticator app
- Edit and delete accounts in-place
- Drag-to-reorder with ↑ / ↓ buttons
- Tag accounts with categories; filter by category or search by name/issuer

**Security**
- Single-instance enforcement — only one copy of OTPVault can run at a time
- Rate limiting on unlock — 5 failed attempts triggers a 30-second lockout; 10 triggers 5 minutes
- Auto-lock after 5 minutes of inactivity with a system notification
- Change master password at any time — all secrets are re-encrypted transparently
- Unlock runs in a background goroutine — UI stays responsive during Argon2id key derivation
- Password bytes pinned in RAM with `mlock` / `VirtualLock`; zeroed on lock and process exit
- Plaintext secret cache (`session.secrets`) is also zeroed on lock and process exit

**Backup / restore**
- Export an encrypted vault backup protected by a separate backup password
- Restore from backup into any vault — secrets are re-encrypted under the current master password

## Requirements

- **Docker** — only needed to build; not required to run the app
- **Linux runtime**: X11 or Wayland (XWayland works out of the box)
- **Windows runtime**: Windows 10 or later

## Build

```bash
# Linux binary → dist/otpvault-linux-amd64
make build-linux

# Windows binary → dist/otpvault-windows-amd64.exe
make build-windows

# Both at once
make build-all
```

## Run

**Linux**
```bash
./dist/otpvault-linux-amd64
```

**Windows**
```
dist\otpvault-windows-amd64.exe
```

The vault database (`otp-accounts.json`) is created automatically next to the executable on first
launch.

## Linux desktop integration

To add OTPVault to your application launcher:

```bash
# 1. Install the binary
cp dist/otpvault-linux-amd64 ~/.local/bin/otpvault
chmod +x ~/.local/bin/otpvault

# 2. Install the icon
mkdir -p ~/.local/share/icons/hicolor/scalable/apps
cp assets/otpvault.svg ~/.local/share/icons/hicolor/scalable/apps/otpvault.svg

# 3. Install the desktop entry
cp otpvault.desktop ~/.local/share/applications/

# 4. Refresh the icon and application caches (optional but recommended)
gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor
update-desktop-database ~/.local/share/applications
```

OTPVault will then appear in your launcher under **Utility** or **Security**. The icon and entry
are installed per-user and do not require root.

## First launch

1. Enter a master password when prompted. This password encrypts all your TOTP secrets.
   There is no recovery mechanism, so choose something memorable.
2. Click **Add Account** to add your first account.
3. Click the copy icon on any token to copy the code to the clipboard.

## Adding accounts

The **Add Account** dialog has five tabs:

| Tab | Use when |
|---|---|
| **Manual Entry** | You have the Base32 secret key |
| **URI / Google Auth** | You have an `otpauth://` URI or an `otpauth-migration://` URI from Google Authenticator's export QR |
| **Aegis** | Paste an Aegis unencrypted JSON export |
| **Bitwarden** | Paste a Bitwarden unencrypted JSON export |
| **Restore Backup** | Restoring from an OTPVault backup file |

For Google Authenticator migration, use the **Transfer accounts** feature in Google Authenticator,
scan the QR code with a QR reader app to get the `otpauth-migration://` URI, then paste it in.
Multiple accounts are imported in one step. HOTP accounts in the migration payload are imported as
HOTP with their embedded counter value.

In **Manual Entry**, select **TOTP** or **HOTP** from the Type field. For HOTP, set an initial
counter value (default: 0). Click **Generate** on an HOTP card to display the current code; the
counter is incremented and saved automatically on every generation.

## System tray

OTPVault minimises to the system tray instead of quitting when the window is closed. The tray icon
provides three actions:

| Action | Effect |
|---|---|
| **Show** | Raises the main window |
| **Lock Vault** | Locks the vault (equivalent to the Lock button) and shows the lock screen |
| **Quit** | Exits the application |

To fully quit, use **Tray → Quit** or press the platform close shortcut after using Quit from the
menu.

## Vault management

Click the **⚙** button in the toolbar to open the vault management dialog:

- **Export Vault Backup** — choose a backup password and save a `.otpvault` file. The backup is
  encrypted independently of your master password so it can be stored anywhere safely.
- **Change Master Password** — all secrets are re-encrypted and the vault verifier is rebuilt.
  The operation is atomic: the database is only updated after every secret is successfully
  re-encrypted.

## Exporting a token as a QR code

Click the **eye** icon on any account card to display its `otpauth://` URI as a QR code. Scan the
code with any TOTP authenticator app (Google Authenticator, Aegis, Authy, etc.) to add the account
to that app.

> **Note:** The QR code encodes your plaintext secret. Treat it like a password — do not display it
> in front of others or screenshot it on a shared device.

## Security

| Property | Detail |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | Argon2id (64 MiB, 1 pass, 4 threads) for new secrets; PBKDF2-SHA256 200 000 iterations accepted for legacy vaults |
| Vault integrity | HMAC-SHA256 verifier with dedicated stable salt |
| Password comparison | `crypto/subtle.ConstantTimeCompare` — timing-safe |
| Password storage | Never written to disk; held as `[]byte`, pinned with `mlock`/`VirtualLock`, zeroed on lock and process exit |
| Secret cache | Plaintext TOTP/HOTP secrets in `session.secrets` are deleted from the map on lock and process exit |
| Clipboard | Copied OTP codes are cleared from the clipboard after 30 seconds |
| Rate limiting | Throttled after failures; lockout state persisted across restarts |
| Session timeout | Vault locks automatically after 5 minutes of inactivity |
| Minimum password length | 8 characters enforced on vault creation and password change |
| Import size cap | All import inputs limited to 1 MiB before parsing |
| Atomic writes | Vault file written via temp-then-rename to prevent corruption on crash |
| Goroutine safety | Session pointer and shared filter state use `sync/atomic` and `sync.RWMutex` |
| Single instance | OS-level file lock (`flock` / `LockFileEx`) prevents two instances from opening the same vault |
| Unlock latency | Argon2id key derivation runs in a goroutine; UI displays a spinner and remains interactive |

Wrong password and tampered-file conditions are distinguished and reported separately.

---

## Security audit

A full security review was conducted against the source code. All identified issues were fixed. The findings and their resolutions are documented below.

### Cryptographic layer

The core crypto was found to be sound:

- AES-256-GCM provides authenticated encryption — ciphertext forgery is detected at decrypt time
- `crypto/subtle.ConstantTimeCompare` is used correctly for HMAC comparison
- The pre-comparison length check in `checkVerifier` is safe because HMAC-SHA256 always produces 32 bytes, so the branch never leaks timing information
- Argon2id (64 MiB, 1 pass, 4 threads) is now used for all new key derivation, meeting OWASP's memory-hardness recommendations; legacy PBKDF2-SHA256 vaults are still readable

### Findings and fixes

#### Medium — race condition on `activeSession` pointer ✅ fixed

`rebuildCards` ran in a background ticker goroutine and accessed `activeSession.password` after a nil-guard. The lock button ran on the UI goroutine and could set `activeSession = nil` between the nil-check and the dereference, producing a nil-pointer crash.

**Fix:** `activeSession` is now declared as `atomic.Pointer[session]`. All reads use `.Load()` and all writes use `.Store()`. `rebuildCards` snapshots the pointer once at entry so the nil-check and all subsequent field accesses are on the same value.

Additionally, `session.secrets` (the TOTP plaintext cache) was a plain map read by the ticker goroutine and written by UI callbacks. It is now protected by a `sync.RWMutex` inside the `session` struct, accessed only through `getSecret`, `setSecret`, and `replaceSecrets` methods.

The global filter variables `searchQuery` and `categoryFilter` were written by both goroutines without synchronization. They are now guarded by `filterMu sync.RWMutex` with dedicated helpers: `getFilters`, `setSearchQuery`, `setCategoryFilter`, `clearFilters`.

#### Medium — non-atomic vault file writes ✅ fixed

`os.WriteFile` truncates the existing file and rewrites it in-place. A crash or power loss mid-write would permanently corrupt the vault.

**Fix:** `saveDB` now writes to a `.tmp` file and calls `os.Rename` to replace the vault atomically (on POSIX, `rename(2)` is atomic).

#### Medium — PBKDF2 running per-account every second ✅ fixed

`rebuildCards` was called once per second and called `decryptSecret` (200 000 PBKDF2 iterations) for every account on every tick. With even a handful of accounts this consumed several hundred milliseconds of CPU per second.

**Fix:** Plaintext TOTP secrets are decrypted once at unlock and cached in `session.secrets`. The ticker now reads from this cache at zero crypto cost. The cache is updated incrementally: new entries are added by `saveAccount`/`showEditDialog`; deleted entries are pruned by `refreshSecretsCache`, which reuses cached plaintexts and only re-derives keys for genuinely new accounts.

#### Medium — rate limiting reset by app restart ✅ fixed

Failed-attempt counters and lockout timestamps lived only in process memory. Killing and relaunching the app reset all limits, enabling unlimited offline brute-force attempts against the vault file.

**Fix:** `recordFailure` and `resetRateLimit` persist the current lockout state to `otp-lockout.json` (mode `0600`) beside the vault file via `persistLockout`. `loadLockoutState` reads this file at startup so an active lockout survives restarts.

#### Low — `crypto/rand.Read` errors silently ignored ✅ fixed

`rand.Read(salt)` and `rand.Read(iv)` discarded errors. An undetected failure would produce a zero-filled salt (breaking PBKDF2 uniqueness) or a zero IV (catastrophic for AES-GCM, which must never reuse a nonce).

**Fix:** Both calls replaced with `io.ReadFull(rand.Reader, ...)` and the error is returned to callers. `buildVerifier`'s signature changed from `Verifier` to `(Verifier, error)` accordingly.

#### Low — protobuf length field integer overflow ✅ fixed

The hand-rolled Google Authenticator migration parser cast a `uint64` length field to `int` before comparing it to `len(data)`. A crafted input with a length field near `math.MaxInt64` could make the cast negative on some platforms, bypassing the bounds check.

**Fix:** Both `decodeMigrationProto` and `decodeOtpParameters` now validate `length > uint64(len(data)-pos)` before the cast, ensuring the check is safe regardless of platform int width.

#### Low — no import input size limits ✅ fixed

The URI, Aegis, Bitwarden, and backup import entry points accepted unbounded input. Pasting a multi-megabyte blob would trigger full JSON or protobuf parsing on the UI thread.

**Fix:** All four import paths now reject input exceeding 1 MiB (`maxImportBytes = 1 << 20`) before any parsing begins.

#### Low — minimum password length not enforced ✅ fixed

Only empty passwords were rejected. A user could set a one-character master password with no warning.

**Fix:** `minPasswordLen = 8` is enforced on new vault creation and on password change. It is intentionally not enforced on unlock of an existing vault to avoid locking out users with legacy short passwords.

#### Medium — master password held as Go `string` ✅ fixed

`session.password` was a Go `string`. Strings are immutable and cannot be zeroed; the plaintext password survived in heap memory until the garbage collector collected it, potentially minutes after lock.

**Fix:** `session.password` is now `[]byte`. A `clearPassword()` method overwrites every byte with zero and nils the slice. It is called on manual lock, session-timeout lock, and before assigning a new password on password change. All crypto function signatures (`deriveKey`, `buildVerifier`, `checkVerifier`, `encryptSecret`, `decryptSecret`) were updated to accept `[]byte` so no intermediate string copies are created in the crypto call chain.

Note: the password byte slice obtained from the Fyne widget is a copy of an immutable Go string inside the widget framework. That original string is beyond our control. The fix guarantees that the copy *we own* is zeroed; residual copies inside the UI framework are not.

#### Medium — PBKDF2 key derivation susceptible to GPU/ASIC brute-force ✅ fixed

PBKDF2-SHA256, while compliant at 200 000 iterations, is purely CPU-bound. GPU or ASIC rigs can parallelize attacks cheaply; OWASP recommends Argon2id for its memory-hardness.

**Fix:** All new key derivation (new secrets, new verifiers, password changes) now uses Argon2id with parameters: 64 MiB memory, 1 pass, 4 threads, 32-byte key. The `EncryptedSecret.KDF` and `Verifier.KDF` fields are set to `"argon2id"` on write. `decryptSecret` and `checkVerifier` dispatch on the `KDF` field so existing PBKDF2 vaults remain readable without migration. A password change re-encrypts all secrets and the verifier under Argon2id, completing the migration automatically. `golang.org/x/crypto/argon2` was already a transitive dependency.

## Database format

`otp-accounts.json` follows the same base schema as the original Node.js version of OTPVault.
Vaults created by the Node.js version (PBKDF2, no `kdf` field) can be unlocked and read by this
binary without any migration step.

Vaults created or modified by this binary include a `"kdf": "argon2id"` field on each encrypted
secret and on the verifier. The Node.js version does not support Argon2id and cannot decrypt these
vaults. A password change re-encrypts the entire vault under Argon2id in one atomic write.

The `category` field is omitted for accounts that have none.

## Development

Tests run inside the Docker builder — no local Go installation needed:

```bash
make test
```

To remove build artifacts and Docker images:

```bash
make clean
```

## License

MIT
