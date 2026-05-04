package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Verifier struct {
	KDF  string `json:"kdf,omitempty"` // "argon2id" or absent/empty for legacy PBKDF2
	Salt string `json:"salt"`
	HMAC string `json:"hmac"`
}

type EncryptedSecret struct {
	KDF  string `json:"kdf,omitempty"` // "argon2id" or absent/empty for legacy PBKDF2
	Salt string `json:"salt"`
	IV   string `json:"iv"`
	Tag  string `json:"tag"`
	Data string `json:"data"`
}

type Account struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Issuer   string          `json:"issuer"`
	Category string          `json:"category,omitempty"`
	Secret   EncryptedSecret `json:"secret"`
	Digits   int             `json:"digits"`
	Period   int             `json:"period"`
	Type     string          `json:"type,omitempty"`    // "totp" (default/empty) or "hotp"
	Counter  uint64          `json:"counter,omitempty"` // HOTP counter
}

type DB struct {
	Verifier *Verifier `json:"verifier"`
	Accounts []Account `json:"accounts"`
}

func dbPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "otp-accounts.json"
	}
	return filepath.Join(filepath.Dir(exe), "otp-accounts.json")
}

func loadDB() (DB, error) {
	p := dbPath()
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		db := DB{Accounts: []Account{}}
		return db, saveDB(db)
	}
	if err != nil {
		return DB{}, err
	}
	var db DB
	return db, json.Unmarshal(data, &db)
}

func saveDB(db DB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := dbPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, dbPath())
}

func lockoutPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "otp-lockout.json"
	}
	return filepath.Join(filepath.Dir(exe), "otp-lockout.json")
}

func updateAccount(id, name, issuer, category, secret, otpType string, counter uint64, digits, period int, password []byte) error {
	db, err := loadDB()
	if err != nil {
		return err
	}
	for i, acc := range db.Accounts {
		if acc.ID == id {
			enc, err := encryptSecret(secret, password)
			if err != nil {
				return err
			}
			db.Accounts[i].Name = name
			db.Accounts[i].Issuer = issuer
			db.Accounts[i].Category = category
			db.Accounts[i].Secret = enc
			db.Accounts[i].Type = otpType
			db.Accounts[i].Counter = counter
			db.Accounts[i].Digits = digits
			db.Accounts[i].Period = period
			return saveDB(db)
		}
	}
	return fmt.Errorf("account not found")
}

func updateCounter(id string, counter uint64) error {
	db, err := loadDB()
	if err != nil {
		return err
	}
	for i, acc := range db.Accounts {
		if acc.ID == id {
			db.Accounts[i].Counter = counter
			return saveDB(db)
		}
	}
	return fmt.Errorf("account not found")
}

// verifyPassword returns "" on success, or an error string.
func verifyPassword(db DB, password []byte) string {
	if db.Verifier == nil && len(db.Accounts) == 0 {
		return ""
	}
	switch checkVerifier(password, db.Verifier) {
	case "missing":
		return "Vault integrity check failed — verifier record is missing or the file was tampered with."
	case "wrong":
		return "Wrong master password."
	}
	return ""
}
