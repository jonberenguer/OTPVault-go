package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/google/uuid"
)

const (
	minPasswordLen = 8
	maxImportBytes = 1 << 20 // 1 MiB cap on all import inputs
)

// session holds in-memory state cleared on lock
type session struct {
	password []byte
	accounts []Account
	mu       sync.RWMutex
	secrets  map[string]string // account ID → plaintext base32; populated at unlock
}

// clearPassword unlocks and zeros the password bytes.
func (s *session) clearPassword() {
	munlockBytes(s.password)
	for i := range s.password {
		s.password[i] = 0
	}
	s.password = nil
}

// clearSecrets deletes all cached plaintext TOTP secrets from the map.
func (s *session) clearSecrets() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.secrets {
		delete(s.secrets, k)
	}
	s.secrets = nil
}

func (s *session) getSecret(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secrets[id]
}

func (s *session) setSecret(id, plain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[id] = plain
}

func (s *session) replaceSecrets(m map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = m
}

type lockoutState struct {
	FailedAttempts int       `json:"failed_attempts"`
	LockedUntil    time.Time `json:"locked_until"`
}

var (
	mainWindow fyne.Window
	fyneApp    fyne.App

	// Rate limiting
	rateMu         sync.Mutex
	failedAttempts int
	lockedUntil    time.Time

	// Session timeout
	activityMu     sync.Mutex
	lastActivity   time.Time
	sessionTimeout = 5 * time.Minute

	// Filter state (vault screen) — guarded by filterMu; written from UI and ticker goroutines
	filterMu       sync.RWMutex
	searchQuery    string
	categoryFilter string
	categorySelect *widget.Select

	// Active session — atomic so the ticker goroutine and UI goroutine can read/write safely
	activeSession atomic.Pointer[session]
)

func main() {
	if !acquireInstanceLock() {
		os.Exit(1)
	}

	fyneApp = app.NewWithID("io.otpvault.app")
	fyneApp.SetIcon(appIcon)
	fyneApp.Settings().SetTheme(theme.DarkTheme())

	// Zero sensitive memory before the process exits.
	fyneApp.Lifecycle().SetOnStopped(func() {
		if sess := activeSession.Load(); sess != nil {
			sess.clearPassword()
			sess.clearSecrets()
		}
	})

	mainWindow = fyneApp.NewWindow("OTPVault")
	mainWindow.SetIcon(appIcon)
	mainWindow.Resize(fyne.NewSize(480, 600))
	mainWindow.SetFixedSize(false)
	mainWindow.CenterOnScreen()

	// Closing the window hides to tray instead of quitting.
	mainWindow.SetCloseIntercept(func() {
		mainWindow.Hide()
	})

	// System tray — only wired when the desktop environment supports it.
	if desk, ok := fyneApp.(desktop.App); ok {
		desk.SetSystemTrayIcon(appIcon)
		desk.SetSystemTrayMenu(fyne.NewMenu("OTPVault",
			fyne.NewMenuItem("Show", func() {
				mainWindow.Show()
				mainWindow.RequestFocus()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Lock Vault", func() {
				if sess := activeSession.Load(); sess != nil {
					sess.clearPassword()
					sess.clearSecrets()
				}
				activeSession.Store(nil)
				clearFilters()
				mainWindow.Show()
				showLockScreen()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit", func() {
				fyneApp.Quit()
			}),
		))
	}

	loadLockoutState()
	showLockScreen()
	mainWindow.ShowAndRun()
}

// ── Activity / timeout helpers ─────────────────────────────────────────────

func touchActivity() {
	activityMu.Lock()
	lastActivity = time.Now()
	activityMu.Unlock()
}

func timeSinceActivity() time.Duration {
	activityMu.Lock()
	defer activityMu.Unlock()
	return time.Since(lastActivity)
}

// ── Rate-limiting helpers ──────────────────────────────────────────────────

func isLockedOut() (bool, time.Duration) {
	rateMu.Lock()
	defer rateMu.Unlock()
	if time.Now().Before(lockedUntil) {
		return true, time.Until(lockedUntil)
	}
	return false, 0
}

func recordFailure() {
	rateMu.Lock()
	failedAttempts++
	switch {
	case failedAttempts >= 10:
		lockedUntil = time.Now().Add(5 * time.Minute)
	case failedAttempts >= 5:
		lockedUntil = time.Now().Add(30 * time.Second)
	}
	a, u := failedAttempts, lockedUntil
	rateMu.Unlock()
	persistLockout(a, u)
}

func resetRateLimit() {
	rateMu.Lock()
	failedAttempts = 0
	lockedUntil = time.Time{}
	rateMu.Unlock()
	persistLockout(0, time.Time{})
}

func persistLockout(attempts int, until time.Time) {
	data, _ := json.Marshal(lockoutState{FailedAttempts: attempts, LockedUntil: until})
	os.WriteFile(lockoutPath(), data, 0600) //nolint:errcheck
}

func loadLockoutState() {
	data, err := os.ReadFile(lockoutPath())
	if err != nil {
		return
	}
	var state lockoutState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	rateMu.Lock()
	failedAttempts = state.FailedAttempts
	lockedUntil = state.LockedUntil
	rateMu.Unlock()
}

// ── Filter-state helpers ───────────────────────────────────────────────────

func getFilters() (search, category string) {
	filterMu.RLock()
	defer filterMu.RUnlock()
	return searchQuery, categoryFilter
}

func setSearchQuery(q string) {
	filterMu.Lock()
	searchQuery = q
	filterMu.Unlock()
}

func setCategoryFilter(v string) {
	filterMu.Lock()
	categoryFilter = v
	filterMu.Unlock()
}

func clearFilters() {
	filterMu.Lock()
	searchQuery = ""
	categoryFilter = ""
	filterMu.Unlock()
}

// startLockoutCountdown updates errLabel and toggles unlockBtn until the
// lockout period expires. Safe to call from any goroutine.
func startLockoutCountdown(errLabel *widget.Label, unlockBtn *widget.Button) {
	unlockBtn.Disable()
	go func() {
		for {
			time.Sleep(time.Second)
			locked, rem := isLockedOut()
			if !locked {
				errLabel.SetText("You may try again.")
				unlockBtn.Enable()
				return
			}
			errLabel.SetText(fmt.Sprintf("Too many failed attempts. Try again in %ds.", int(rem.Seconds())+1))
		}
	}()
}

// ── Lock screen ────────────────────────────────────────────────────────────

func showLockScreen() {
	db, _ := loadDB()
	isNew := db.Verifier == nil && len(db.Accounts) == 0

	title := canvas.NewText("OTPVault", theme.ForegroundColor())
	title.TextSize = 28
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	subtitle := "Enter your master password to unlock"
	if isNew {
		subtitle = "Create a master password to protect your vault"
	}
	subLabel := widget.NewLabel(subtitle)
	subLabel.Alignment = fyne.TextAlignCenter
	subLabel.Wrapping = fyne.TextWrapWord

	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Master password")

	errLabel := widget.NewLabel("")
	errLabel.Alignment = fyne.TextAlignCenter

	spinner := widget.NewProgressBarInfinite()
	spinner.Hide()

	unlockBtn := widget.NewButton("Unlock", nil)
	unlockBtn.Importance = widget.HighImportance

	// Resume any ongoing lockout
	if locked, rem := isLockedOut(); locked {
		errLabel.SetText(fmt.Sprintf("Too many failed attempts. Try again in %ds.", int(rem.Seconds())+1))
		startLockoutCountdown(errLabel, unlockBtn)
	}

	doUnlock := func() {
		if locked, rem := isLockedOut(); locked {
			errLabel.SetText(fmt.Sprintf("Too many failed attempts. Try again in %ds.", int(rem.Seconds())+1))
			return
		}
		pw := []byte(pwEntry.Text)
		if len(pw) == 0 {
			errLabel.SetText("Password cannot be empty.")
			return
		}
		if isNew && len(pw) < minPasswordLen {
			errLabel.SetText(fmt.Sprintf("Master password must be at least %d characters.", minPasswordLen))
			return
		}
		mlockBytes(pw)
		unlockBtn.Disable()
		pwEntry.Disable()
		errLabel.SetText("")
		spinner.Show()

		go func() {
			db, err := loadDB()
			if err != nil {
				munlockBytes(pw)
				for i := range pw {
					pw[i] = 0
				}
				spinner.Hide()
				errLabel.SetText("Failed to load vault: " + err.Error())
				unlockBtn.Enable()
				pwEntry.Enable()
				return
			}
			if msg := verifyPassword(db, pw); msg != "" {
				munlockBytes(pw)
				for i := range pw {
					pw[i] = 0
				}
				recordFailure()
				spinner.Hide()
				unlockBtn.Enable()
				pwEntry.Enable()
				pwEntry.SetText("")
				if locked, rem := isLockedOut(); locked {
					errLabel.SetText(fmt.Sprintf("Too many failed attempts. Try again in %ds.", int(rem.Seconds())+1))
					startLockoutCountdown(errLabel, unlockBtn)
				} else {
					errLabel.SetText(msg)
				}
				return
			}
			resetRateLimit()
			sess := &session{
				password: pw,
				accounts: db.Accounts,
				secrets:  make(map[string]string, len(db.Accounts)),
			}
			for _, acc := range db.Accounts {
				if plain, err := decryptSecret(acc.Secret, pw); err == nil {
					sess.secrets[acc.ID] = plain
				}
			}
			activeSession.Store(sess)
			spinner.Hide()
			showVault()
		}()
	}

	unlockBtn.OnTapped = doUnlock
	pwEntry.OnSubmitted = func(_ string) { doUnlock() }

	content := container.NewVBox(
		layout.NewSpacer(),
		title,
		widget.NewSeparator(),
		subLabel,
		pwEntry,
		errLabel,
		spinner,
		unlockBtn,
		layout.NewSpacer(),
	)

	mainWindow.SetContent(container.NewPadded(content))
}

// refreshSecretsCache rebuilds the plaintext-secret map from the current DB,
// reusing already-cached plaintexts and PBKDF2-decrypting only new entries.
func refreshSecretsCache() {
	sess := activeSession.Load()
	if sess == nil {
		return
	}
	db, err := loadDB()
	if err != nil {
		return
	}
	newSecrets := make(map[string]string, len(db.Accounts))
	for _, acc := range db.Accounts {
		if plain := sess.getSecret(acc.ID); plain != "" {
			newSecrets[acc.ID] = plain
		} else {
			if plain, err := decryptSecret(acc.Secret, sess.password); err == nil {
				newSecrets[acc.ID] = plain
			}
		}
	}
	sess.replaceSecrets(newSecrets)
}

// ── Vault screen ───────────────────────────────────────────────────────────

func showVault() {
	list := container.NewVBox()
	scroll := container.NewVScroll(list)

	touchActivity()

	addBtn := widget.NewButtonWithIcon("Add Account", theme.ContentAddIcon(), func() {
		touchActivity()
		showAddDialog()
	})
	manageBtn := widget.NewButtonWithIcon("", theme.SettingsIcon(), func() {
		touchActivity()
		showManageVaultDialog()
	})
	lockBtn := widget.NewButtonWithIcon("Lock", theme.LogoutIcon(), func() {
		if sess := activeSession.Load(); sess != nil {
			sess.clearPassword()
			sess.clearSecrets()
		}
		activeSession.Store(nil)
		clearFilters()
		showLockScreen()
	})

	toolbar := container.NewBorder(nil, nil, nil,
		container.NewHBox(addBtn, manageBtn, lockBtn),
		canvas.NewText("", nil),
	)

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search by name or issuer…")
	searchEntry.OnChanged = func(q string) {
		touchActivity()
		setSearchQuery(q)
		rebuildCards(list)
	}

	categorySelect = widget.NewSelect([]string{"All"}, func(v string) {
		touchActivity()
		if v == "All" {
			setCategoryFilter("")
		} else {
			setCategoryFilter(v)
		}
		rebuildCards(list)
	})
	categorySelect.SetSelected("All")

	filterBar := container.NewGridWithColumns(2, searchEntry, categorySelect)

	mainWindow.SetContent(container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator(), filterBar, widget.NewSeparator()),
		nil, nil, nil,
		scroll,
	))

	ticker := time.NewTicker(time.Second)
	go func() {
		for range ticker.C {
			if activeSession.Load() == nil {
				ticker.Stop()
				return
			}
			if timeSinceActivity() > sessionTimeout {
				if sess := activeSession.Load(); sess != nil {
					sess.clearPassword()
					sess.clearSecrets()
				}
				activeSession.Store(nil)
				ticker.Stop()
				clearFilters()
				fyneApp.SendNotification(&fyne.Notification{
					Title:   "OTPVault",
					Content: "Vault locked due to inactivity.",
				})
				showLockScreen()
				return
			}
			rebuildCards(list)
		}
	}()

	rebuildCards(list)
}

func rebuildCards(list *fyne.Container) {
	sess := activeSession.Load() // snapshot once to avoid nil-pointer race with lock
	if sess == nil {
		return
	}
	db, err := loadDB()
	if err != nil {
		return
	}

	// Refresh category select options only when they've changed
	if categorySelect != nil {
		cats := getCategories(db)
		newOpts := append([]string{"All"}, cats...)
		if !stringSlicesEqual(categorySelect.Options, newOpts) {
			categorySelect.Options = newOpts
			found := false
			for _, o := range newOpts {
				if o == categorySelect.Selected {
					found = true
					break
				}
			}
			if !found {
				categorySelect.SetSelected("All")
				setCategoryFilter("")
			}
			categorySelect.Refresh()
		}
	}

	search, catFilter := getFilters()
	hasFilter := search != "" || catFilter != ""

	var filtered []Account
	for _, acc := range db.Accounts {
		if search != "" {
			q := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(acc.Name), q) &&
				!strings.Contains(strings.ToLower(acc.Issuer), q) &&
				!strings.Contains(strings.ToLower(acc.Category), q) {
				continue
			}
		}
		if catFilter != "" && acc.Category != catFilter {
			continue
		}
		filtered = append(filtered, acc)
	}

	objects := make([]fyne.CanvasObject, 0, len(filtered)+1)

	if len(filtered) == 0 {
		msg := "No accounts yet. Press \"Add Account\" to get started."
		if hasFilter {
			msg = "No accounts match your filter."
		}
		empty := widget.NewLabel(msg)
		empty.Alignment = fyne.TextAlignCenter
		empty.Wrapping = fyne.TextWrapWord
		objects = append(objects, empty)
	}

	for i, acc := range filtered {
		i, acc := i, acc

		secret := sess.getSecret(acc.ID)

		displayName := acc.Name
		if acc.Issuer != "" {
			displayName = strings.ToUpper(acc.Issuer) + "  " + acc.Name
		}
		if acc.Category != "" {
			displayName = "[" + acc.Category + "]  " + displayName
		}
		nameLabel := widget.NewLabel(displayName)
		nameLabel.Truncation = fyne.TextTruncateEllipsis

		qrBtn := widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
			touchActivity()
			showQRDialog(acc, secret)
		})

		editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
			touchActivity()
			showEditDialog(acc)
		})

		deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
			touchActivity()
			dialog.ShowConfirm("Delete Account",
				fmt.Sprintf("Remove %q from vault?", acc.Name),
				func(ok bool) {
					if !ok {
						return
					}
					if err := deleteAccount(acc.ID); err != nil {
						dialog.ShowError(err, mainWindow)
						return
					}
					refreshSecretsCache()
				},
				mainWindow,
			)
		})
		deleteBtn.Importance = widget.DangerImportance

		upBtn := widget.NewButton("↑", func() {
			touchActivity()
			moveAccount(acc.ID, -1)
			rebuildCards(list)
		})
		downBtn := widget.NewButton("↓", func() {
			touchActivity()
			moveAccount(acc.ID, 1)
			rebuildCards(list)
		})
		if hasFilter || i == 0 {
			upBtn.Disable()
		}
		if hasFilter || i == len(filtered)-1 {
			downBtn.Disable()
		}

		var row fyne.CanvasObject
		if acc.Type == "hotp" {
			counterLabel := widget.NewLabel(fmt.Sprintf("counter: %d", acc.Counter))
			counterLabel.TextStyle = fyne.TextStyle{Italic: true}
			generateBtn := widget.NewButtonWithIcon("Generate", theme.ViewRefreshIcon(), func() {
				touchActivity()
				generateHOTPCode(acc)
			})
			row = container.NewBorder(nil, nil,
				counterLabel,
				container.NewHBox(generateBtn, qrBtn, upBtn, downBtn, editBtn, deleteBtn),
				nameLabel,
			)
		} else {
			result, totpErr := totpNow(secret, acc.Digits, acc.Period)
			codeStr := "------"
			remaining := 0
			if totpErr == nil {
				mid := len(result.Code) / 2
				codeStr = result.Code[:mid] + " " + result.Code[mid:]
				remaining = result.Remaining
			}
			circle := NewCountdownCircle(remaining, acc.Period)
			codeLabel := canvas.NewText(codeStr, theme.ForegroundColor())
			codeLabel.TextSize = 20
			codeLabel.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
			copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
				code := strings.ReplaceAll(codeStr, " ", "")
				mainWindow.Clipboard().SetContent(code)
				showToast("Copied! Clears in 30s")
				touchActivity()
				go func() {
					time.Sleep(30 * time.Second)
					if mainWindow.Clipboard().Content() == code {
						mainWindow.Clipboard().SetContent("")
					}
				}()
			})
			row = container.NewBorder(nil, nil,
				circle,
				container.NewHBox(codeLabel, copyBtn, qrBtn, upBtn, downBtn, editBtn, deleteBtn),
				nameLabel,
			)
		}

		objects = append(objects, widget.NewCard("", "", row))
	}

	list.Objects = objects
	list.Refresh()
}

// generateHOTPCode generates the next HOTP code, increments the counter in the
// DB, and shows the result in a dialog with a copy button.
func generateHOTPCode(acc Account) {
	sess := activeSession.Load()
	if sess == nil {
		return
	}
	secret := sess.getSecret(acc.ID)
	if secret == "" {
		dialog.ShowError(fmt.Errorf("secret not available for this account"), mainWindow)
		return
	}
	code, err := hotpNow(secret, acc.Counter, acc.Digits)
	if err != nil {
		dialog.ShowError(fmt.Errorf("failed to generate code: %w", err), mainWindow)
		return
	}
	newCounter := acc.Counter + 1
	if err := updateCounter(acc.ID, newCounter); err != nil {
		dialog.ShowError(fmt.Errorf("failed to save counter: %w", err), mainWindow)
		return
	}

	mid := len(code) / 2
	displayCode := code[:mid] + " " + code[mid:]
	codeText := canvas.NewText(displayCode, theme.ForegroundColor())
	codeText.TextSize = 32
	codeText.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	codeText.Alignment = fyne.TextAlignCenter

	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		mainWindow.Clipboard().SetContent(code)
		showToast("Copied! Clears in 30s")
		go func() {
			time.Sleep(30 * time.Second)
			if mainWindow.Clipboard().Content() == code {
				mainWindow.Clipboard().SetContent("")
			}
		}()
	})

	counterInfo := widget.NewLabel(fmt.Sprintf("Counter advanced to %d", newCounter))
	counterInfo.Alignment = fyne.TextAlignCenter

	content := container.NewVBox(
		container.NewCenter(codeText),
		counterInfo,
		container.NewCenter(copyBtn),
	)

	title := acc.Name
	if acc.Issuer != "" {
		title = acc.Issuer + " — " + acc.Name
	}
	d := dialog.NewCustom(title, "Close", content, mainWindow)
	d.Resize(fyne.NewSize(300, 200))
	d.Show()
}

func moveAccount(id string, delta int) error {
	db, err := loadDB()
	if err != nil {
		return err
	}
	idx := -1
	for i, a := range db.Accounts {
		if a.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("account not found")
	}
	newIdx := idx + delta
	if newIdx < 0 || newIdx >= len(db.Accounts) {
		return nil
	}
	db.Accounts[idx], db.Accounts[newIdx] = db.Accounts[newIdx], db.Accounts[idx]
	return saveDB(db)
}

func deleteAccount(id string) error {
	db, err := loadDB()
	if err != nil {
		return err
	}
	before := len(db.Accounts)
	kept := db.Accounts[:0]
	for _, a := range db.Accounts {
		if a.ID != id {
			kept = append(kept, a)
		}
	}
	if len(kept) == before {
		return fmt.Errorf("account not found")
	}
	db.Accounts = kept
	return saveDB(db)
}

func getCategories(db DB) []string {
	seen := make(map[string]bool)
	var cats []string
	for _, a := range db.Accounts {
		if a.Category != "" && !seen[a.Category] {
			seen[a.Category] = true
			cats = append(cats, a.Category)
		}
	}
	sort.Strings(cats)
	return cats
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Add account dialog ─────────────────────────────────────────────────────

func showAddDialog() {
	tabs := container.NewAppTabs(
		container.NewTabItem("Manual Entry", buildManualForm()),
		container.NewTabItem("URI / Google Auth", buildURIForm()),
		container.NewTabItem("Aegis", buildAegisForm()),
		container.NewTabItem("Bitwarden", buildBitwardenForm()),
		container.NewTabItem("Restore Backup", buildBackupImportForm()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	d := dialog.NewCustom("Add Account", "Close", tabs, mainWindow)
	d.Resize(fyne.NewSize(440, 460))
	d.Show()
}

func buildManualForm() fyne.CanvasObject {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("e.g. john@example.com")

	issuerEntry := widget.NewEntry()
	issuerEntry.SetPlaceHolder("e.g. GitHub")

	categoryEntry := widget.NewEntry()
	categoryEntry.SetPlaceHolder("e.g. Work")

	secretEntry := widget.NewPasswordEntry()
	secretEntry.SetPlaceHolder("Base32 secret key")

	typeSelect := widget.NewSelect([]string{"TOTP", "HOTP"}, nil)
	typeSelect.SetSelected("TOTP")

	digitsSelect := widget.NewSelect([]string{"6", "7", "8"}, nil)
	digitsSelect.SetSelected("6")

	periodSelect := widget.NewSelect([]string{"30", "60"}, nil)
	periodSelect.SetSelected("30")

	counterEntry := widget.NewEntry()
	counterEntry.SetText("0")
	counterEntry.SetPlaceHolder("Initial counter value")

	errLabel := widget.NewLabel("")

	saveBtn := widget.NewButton("Save Account", func() {
		name := strings.TrimSpace(nameEntry.Text)
		secret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secretEntry.Text), " ", ""))
		issuer := strings.TrimSpace(issuerEntry.Text)
		category := strings.TrimSpace(categoryEntry.Text)

		if name == "" || secret == "" {
			errLabel.SetText("Name and secret are required.")
			return
		}
		if _, err := base32Decode(secret); err != nil {
			errLabel.SetText("Invalid base32 secret: " + err.Error())
			return
		}

		digits := 6
		fmt.Sscanf(digitsSelect.Selected, "%d", &digits)
		period := 30
		fmt.Sscanf(periodSelect.Selected, "%d", &period)

		otpType := strings.ToLower(typeSelect.Selected)
		var counter uint64
		if otpType == "hotp" {
			counter, _ = strconv.ParseUint(strings.TrimSpace(counterEntry.Text), 10, 64)
		}

		if err := saveAccount(name, issuer, category, secret, otpType, counter, digits, period); err != nil {
			errLabel.SetText(err.Error())
			return
		}
		nameEntry.SetText("")
		issuerEntry.SetText("")
		categoryEntry.SetText("")
		secretEntry.SetText("")
		counterEntry.SetText("0")
		errLabel.SetText("Account saved!")
	})
	saveBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Account Name *", nameEntry),
			widget.NewFormItem("Issuer", issuerEntry),
			widget.NewFormItem("Category", categoryEntry),
			widget.NewFormItem("Secret *", secretEntry),
			widget.NewFormItem("Type", typeSelect),
			widget.NewFormItem("Digits", digitsSelect),
			widget.NewFormItem("Period/s (TOTP)", periodSelect),
			widget.NewFormItem("Counter (HOTP)", counterEntry),
		),
		errLabel,
		saveBtn,
	)
}

func buildURIForm() fyne.CanvasObject {
	uriEntry := widget.NewMultiLineEntry()
	uriEntry.SetPlaceHolder("otpauth://totp/...\n\notpauth-migration://offline?data=... (Google Authenticator)")
	uriEntry.SetMinRowsVisible(4)

	categoryEntry := widget.NewEntry()
	categoryEntry.SetPlaceHolder("e.g. Work (optional)")

	errLabel := widget.NewLabel("")

	importBtn := widget.NewButton("Import", func() {
		raw := strings.TrimSpace(uriEntry.Text)
		if raw == "" {
			errLabel.SetText("Please paste a URI.")
			return
		}
		if len(raw) > maxImportBytes {
			errLabel.SetText("Input too large (max 1 MiB).")
			return
		}
		category := strings.TrimSpace(categoryEntry.Text)

		if strings.HasPrefix(raw, "otpauth-migration://") {
			entries, err := parseGoogleAuthMigration(raw)
			if err != nil {
				errLabel.SetText("Invalid migration URI: " + err.Error())
				return
			}
			if len(entries) == 0 {
				errLabel.SetText("No TOTP accounts found in migration data.")
				return
			}
			imported := 0
			for _, e := range entries {
				if saveAccount(e.Name, e.Issuer, category, e.Secret, e.Type, e.Counter, e.Digits, e.Period) == nil {
					imported++
				}
			}
			uriEntry.SetText("")
			categoryEntry.SetText("")
			errLabel.SetText(fmt.Sprintf("Imported %d of %d accounts.", imported, len(entries)))
			return
		}

		parsed, err := parseOtpAuthURI(raw)
		if err != nil {
			errLabel.SetText("Invalid URI: " + err.Error())
			return
		}
		if err := saveAccount(parsed.Name, parsed.Issuer, category, parsed.Secret, parsed.Type, parsed.Counter, parsed.Digits, parsed.Period); err != nil {
			errLabel.SetText(err.Error())
			return
		}
		uriEntry.SetText("")
		categoryEntry.SetText("")
		errLabel.SetText(fmt.Sprintf("Imported %q successfully!", parsed.Name))
	})
	importBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabel("Paste an otpauth:// or otpauth-migration:// URI:"),
		uriEntry,
		widget.NewForm(
			widget.NewFormItem("Category", categoryEntry),
		),
		errLabel,
		importBtn,
	)
}

func saveAccount(name, issuer, category, secret, otpType string, counter uint64, digits, period int) error {
	if otpType == "" {
		otpType = "totp"
	}
	s := activeSession.Load()
	if s == nil {
		return fmt.Errorf("vault is locked")
	}
	db, err := loadDB()
	if err != nil {
		return err
	}
	if msg := verifyPassword(db, s.password); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	if db.Verifier == nil {
		v, err := buildVerifier(s.password)
		if err != nil {
			return fmt.Errorf("failed to build verifier: %w", err)
		}
		db.Verifier = &v
	}
	enc, err := encryptSecret(secret, s.password)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	id := uuid.New().String()
	db.Accounts = append(db.Accounts, Account{
		ID:       id,
		Name:     name,
		Issuer:   issuer,
		Category: category,
		Secret:   enc,
		Digits:   digits,
		Period:   period,
		Type:     otpType,
		Counter:  counter,
	})
	if err := saveDB(db); err != nil {
		return err
	}
	s.setSecret(id, secret)
	return nil
}

// ── Edit account dialog ────────────────────────────────────────────────────

func showEditDialog(acc Account) {
	s := activeSession.Load()
	if s == nil {
		return
	}
	currentSecret, _ := decryptSecret(acc.Secret, s.password)

	nameEntry := widget.NewEntry()
	nameEntry.SetText(acc.Name)

	issuerEntry := widget.NewEntry()
	issuerEntry.SetText(acc.Issuer)

	categoryEntry := widget.NewEntry()
	categoryEntry.SetText(acc.Category)
	categoryEntry.SetPlaceHolder("e.g. Work")

	secretEntry := widget.NewPasswordEntry()
	secretEntry.SetText(currentSecret)
	secretEntry.SetPlaceHolder("Base32 secret key")

	initialType := acc.Type
	if initialType == "" {
		initialType = "totp"
	}
	typeSelect := widget.NewSelect([]string{"TOTP", "HOTP"}, nil)
	typeSelect.SetSelected(strings.ToUpper(initialType))

	digitsSelect := widget.NewSelect([]string{"6", "7", "8"}, nil)
	digitsSelect.SetSelected(fmt.Sprintf("%d", acc.Digits))

	periodSelect := widget.NewSelect([]string{"30", "60"}, nil)
	periodSelect.SetSelected(fmt.Sprintf("%d", acc.Period))

	counterEntry := widget.NewEntry()
	counterEntry.SetText(fmt.Sprintf("%d", acc.Counter))

	errLabel := widget.NewLabel("")

	var d dialog.Dialog

	saveBtn := widget.NewButton("Save Changes", func() {
		name := strings.TrimSpace(nameEntry.Text)
		secret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secretEntry.Text), " ", ""))
		issuer := strings.TrimSpace(issuerEntry.Text)
		category := strings.TrimSpace(categoryEntry.Text)

		if name == "" || secret == "" {
			errLabel.SetText("Name and secret are required.")
			return
		}
		if _, err := base32Decode(secret); err != nil {
			errLabel.SetText("Invalid base32 secret: " + err.Error())
			return
		}

		digits := 6
		fmt.Sscanf(digitsSelect.Selected, "%d", &digits)
		period := 30
		fmt.Sscanf(periodSelect.Selected, "%d", &period)

		otpType := strings.ToLower(typeSelect.Selected)
		var counter uint64
		if otpType == "hotp" {
			counter, _ = strconv.ParseUint(strings.TrimSpace(counterEntry.Text), 10, 64)
		}

		if err := updateAccount(acc.ID, name, issuer, category, secret, otpType, counter, digits, period, s.password); err != nil {
			errLabel.SetText(err.Error())
			return
		}
		s.setSecret(acc.ID, secret)
		d.Hide()
	})
	saveBtn.Importance = widget.HighImportance

	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Account Name *", nameEntry),
			widget.NewFormItem("Issuer", issuerEntry),
			widget.NewFormItem("Category", categoryEntry),
			widget.NewFormItem("Secret *", secretEntry),
			widget.NewFormItem("Type", typeSelect),
			widget.NewFormItem("Digits", digitsSelect),
			widget.NewFormItem("Period/s (TOTP)", periodSelect),
			widget.NewFormItem("Counter (HOTP)", counterEntry),
		),
		errLabel,
		saveBtn,
	)

	d = dialog.NewCustom("Edit Account", "Cancel", form, mainWindow)
	d.Resize(fyne.NewSize(420, 420))
	d.Show()
}

// ── Aegis import tab ──────────────────────────────────────────────────────

func buildAegisForm() fyne.CanvasObject {
	jsonEntry := widget.NewMultiLineEntry()
	jsonEntry.SetPlaceHolder("Paste Aegis unencrypted JSON export here…")
	jsonEntry.SetMinRowsVisible(5)

	categoryEntry := widget.NewEntry()
	categoryEntry.SetPlaceHolder("e.g. Work (optional)")

	errLabel := widget.NewLabel("")

	importBtn := widget.NewButton("Import Aegis Export", func() {
		raw := strings.TrimSpace(jsonEntry.Text)
		if raw == "" {
			errLabel.SetText("Please paste an Aegis JSON export.")
			return
		}
		if len(raw) > maxImportBytes {
			errLabel.SetText("Input too large (max 1 MiB).")
			return
		}
		entries, err := parseAegisExport([]byte(raw))
		if err != nil {
			errLabel.SetText(err.Error())
			return
		}
		if len(entries) == 0 {
			errLabel.SetText("No TOTP accounts found in export.")
			return
		}
		category := strings.TrimSpace(categoryEntry.Text)
		imported := 0
		for _, e := range entries {
			if saveAccount(e.Name, e.Issuer, category, e.Secret, e.Type, e.Counter, e.Digits, e.Period) == nil {
				imported++
			}
		}
		jsonEntry.SetText("")
		errLabel.SetText(fmt.Sprintf("Imported %d of %d accounts.", imported, len(entries)))
	})
	importBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabel("Paste an Aegis unencrypted JSON export below:"),
		jsonEntry,
		widget.NewForm(widget.NewFormItem("Category", categoryEntry)),
		errLabel,
		importBtn,
	)
}

// ── Bitwarden import tab ───────────────────────────────────────────────────

func buildBitwardenForm() fyne.CanvasObject {
	jsonEntry := widget.NewMultiLineEntry()
	jsonEntry.SetPlaceHolder("Paste Bitwarden unencrypted JSON export here…")
	jsonEntry.SetMinRowsVisible(5)

	categoryEntry := widget.NewEntry()
	categoryEntry.SetPlaceHolder("e.g. Work (optional)")

	errLabel := widget.NewLabel("")

	importBtn := widget.NewButton("Import Bitwarden Export", func() {
		raw := strings.TrimSpace(jsonEntry.Text)
		if raw == "" {
			errLabel.SetText("Please paste a Bitwarden JSON export.")
			return
		}
		if len(raw) > maxImportBytes {
			errLabel.SetText("Input too large (max 1 MiB).")
			return
		}
		entries, err := parseBitwardenExport([]byte(raw))
		if err != nil {
			errLabel.SetText(err.Error())
			return
		}
		if len(entries) == 0 {
			errLabel.SetText("No TOTP accounts found in export.")
			return
		}
		category := strings.TrimSpace(categoryEntry.Text)
		imported := 0
		for _, e := range entries {
			if saveAccount(e.Name, e.Issuer, category, e.Secret, e.Type, e.Counter, e.Digits, e.Period) == nil {
				imported++
			}
		}
		jsonEntry.SetText("")
		errLabel.SetText(fmt.Sprintf("Imported %d of %d accounts.", imported, len(entries)))
	})
	importBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabel("Paste a Bitwarden unencrypted JSON export below:"),
		jsonEntry,
		widget.NewForm(widget.NewFormItem("Category", categoryEntry)),
		errLabel,
		importBtn,
	)
}

// ── Backup import tab ──────────────────────────────────────────────────────

func buildBackupImportForm() fyne.CanvasObject {
	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Backup password")

	errLabel := widget.NewLabel("")
	statusLabel := widget.NewLabel("")

	importBtn := widget.NewButton("Choose Backup File…", func() {
		pw := pwEntry.Text
		if pw == "" {
			errLabel.SetText("Backup password is required.")
			return
		}
		errLabel.SetText("")
		fd := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil || rc == nil {
				return
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				errLabel.SetText("Failed to read file: " + err.Error())
				return
			}
			if len(data) > maxImportBytes {
				errLabel.SetText("Backup file too large (max 1 MiB).")
				return
			}
			accounts, err := importBackup(data, pw)
			if err != nil {
				errLabel.SetText(err.Error())
				return
			}
			imported, skipped := 0, 0
			for _, ba := range accounts {
				if saveAccount(ba.Name, ba.Issuer, ba.Category, ba.Secret, ba.Type, ba.Counter, ba.Digits, ba.Period) == nil {
					imported++
				} else {
					skipped++
				}
			}
			errLabel.SetText("")
			statusLabel.SetText(fmt.Sprintf("Imported %d accounts, skipped %d.", imported, skipped))
		}, mainWindow)
		fd.Show()
	})
	importBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabel("Restore accounts from an OTPVault backup file:"),
		widget.NewForm(widget.NewFormItem("Backup Password", pwEntry)),
		errLabel,
		importBtn,
		statusLabel,
	)
}

// ── Vault management dialog ────────────────────────────────────────────────

func showManageVaultDialog() {
	exportBtn := widget.NewButton("Export Vault Backup", func() {
		showExportDialog()
	})

	changePwBtn := widget.NewButton("Change Master Password", func() {
		showChangePasswordDialog()
	})

	content := container.NewVBox(
		exportBtn,
		changePwBtn,
	)

	d := dialog.NewCustom("Manage Vault", "Close", content, mainWindow)
	d.Resize(fyne.NewSize(300, 180))
	d.Show()
}

func showExportDialog() {
	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Backup password")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm backup password")

	errLabel := widget.NewLabel("")

	exportBtn := widget.NewButton("Choose Save Location…", func() {
		pw := pwEntry.Text
		confirm := confirmEntry.Text
		if pw == "" {
			errLabel.SetText("Backup password is required.")
			return
		}
		if pw != confirm {
			errLabel.SetText("Passwords do not match.")
			return
		}
		db, err := loadDB()
		if err != nil {
			errLabel.SetText("Failed to load vault: " + err.Error())
			return
		}
		sess := activeSession.Load()
		if sess == nil {
			errLabel.SetText("Vault is locked.")
			return
		}
		backupData, err := exportBackup(db, sess.password, pw)
		if err != nil {
			errLabel.SetText("Export failed: " + err.Error())
			return
		}
		fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			defer uc.Close()
			if _, err := uc.Write(backupData); err != nil {
				errLabel.SetText("Failed to write backup: " + err.Error())
				return
			}
			showToast("Vault exported successfully.")
		}, mainWindow)
		fd.SetFileName("otpvault-backup.otpvault")
		fd.Show()
	})
	exportBtn.Importance = widget.HighImportance

	content := container.NewVBox(
		widget.NewLabel("Set a password to protect this backup:"),
		widget.NewForm(
			widget.NewFormItem("Backup Password", pwEntry),
			widget.NewFormItem("Confirm", confirmEntry),
		),
		errLabel,
		exportBtn,
	)

	d := dialog.NewCustom("Export Vault Backup", "Cancel", content, mainWindow)
	d.Resize(fyne.NewSize(400, 280))
	d.Show()
}

func showChangePasswordDialog() {
	currentPwEntry := widget.NewPasswordEntry()
	currentPwEntry.SetPlaceHolder("Current master password")

	newPwEntry := widget.NewPasswordEntry()
	newPwEntry.SetPlaceHolder("New master password")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirm new password")

	errLabel := widget.NewLabel("")

	var d dialog.Dialog

	saveBtn := widget.NewButton("Change Password", func() {
		current := []byte(currentPwEntry.Text)
		newPw := []byte(newPwEntry.Text)
		confirm := []byte(confirmEntry.Text)

		if len(current) == 0 || len(newPw) == 0 || len(confirm) == 0 {
			errLabel.SetText("All fields are required.")
			return
		}
		if !bytes.Equal(newPw, confirm) {
			errLabel.SetText("New passwords do not match.")
			return
		}
		if bytes.Equal(newPw, current) {
			errLabel.SetText("New password must differ from current.")
			return
		}
		if len(newPw) < minPasswordLen {
			errLabel.SetText(fmt.Sprintf("New password must be at least %d characters.", minPasswordLen))
			return
		}

		db, err := loadDB()
		if err != nil {
			errLabel.SetText("Failed to load vault: " + err.Error())
			return
		}
		if msg := verifyPassword(db, current); msg != "" {
			errLabel.SetText(msg)
			return
		}

		for i, acc := range db.Accounts {
			secret, err := decryptSecret(acc.Secret, current)
			if err != nil {
				errLabel.SetText(fmt.Sprintf("Failed to decrypt %q: %v", acc.Name, err))
				return
			}
			enc, err := encryptSecret(secret, newPw)
			if err != nil {
				errLabel.SetText(fmt.Sprintf("Failed to re-encrypt %q: %v", acc.Name, err))
				return
			}
			db.Accounts[i].Secret = enc
		}

		v, err := buildVerifier(newPw)
		if err != nil {
			errLabel.SetText("Failed to build verifier: " + err.Error())
			return
		}
		db.Verifier = &v

		if err := saveDB(db); err != nil {
			errLabel.SetText("Failed to save vault: " + err.Error())
			return
		}

		if sess := activeSession.Load(); sess != nil {
			sess.clearPassword()
			sess.password = newPw
		}
		d.Hide()
		showToast("Master password changed successfully.")
	})
	saveBtn.Importance = widget.HighImportance

	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Current Password", currentPwEntry),
			widget.NewFormItem("New Password", newPwEntry),
			widget.NewFormItem("Confirm New", confirmEntry),
		),
		errLabel,
		saveBtn,
	)

	d = dialog.NewCustom("Change Master Password", "Cancel", form, mainWindow)
	d.Resize(fyne.NewSize(400, 300))
	d.Show()
}

// ── Toast notification ─────────────────────────────────────────────────────

func showToast(msg string) {
	fyneApp.SendNotification(&fyne.Notification{
		Title:   "OTPVault",
		Content: msg,
	})
}
