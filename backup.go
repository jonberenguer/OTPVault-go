package main

import (
	"encoding/json"
	"fmt"
)

// backupAccount holds decrypted account data inside a backup file.
type backupAccount struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Category string `json:"category,omitempty"`
	Secret   string `json:"secret"` // plaintext base32
	Digits   int    `json:"digits"`
	Period   int    `json:"period"`
	Type     string `json:"type,omitempty"`
	Counter  uint64 `json:"counter,omitempty"`
}

type backupPayload struct {
	Version  int             `json:"version"`
	Accounts []backupAccount `json:"accounts"`
}

// backupFile is the on-disk encrypted container.
type backupFile struct {
	Type string `json:"type"` // "otpvault-backup"
	Ver  int    `json:"ver"`
	Salt string `json:"salt"`
	IV   string `json:"iv"`
	Tag  string `json:"tag"`
	Data string `json:"data"`
}

// exportBackup decrypts every account secret, wraps them into a JSON
// payload, then re-encrypts the whole thing with backupPassword.
func exportBackup(db DB, masterPassword []byte, backupPassword string) ([]byte, error) {
	payload := backupPayload{Version: 1}
	for _, acc := range db.Accounts {
		secret, err := decryptSecret(acc.Secret, masterPassword)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %q: %w", acc.Name, err)
		}
		payload.Accounts = append(payload.Accounts, backupAccount{
			Name:     acc.Name,
			Issuer:   acc.Issuer,
			Category: acc.Category,
			Secret:   secret,
			Digits:   acc.Digits,
			Period:   acc.Period,
			Type:     acc.Type,
			Counter:  acc.Counter,
		})
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Reuse the existing per-secret encryption — the backup password becomes
	// the "password" and the entire JSON blob becomes the "secret".
	enc, err := encryptSecret(string(plaintext), []byte(backupPassword))
	if err != nil {
		return nil, err
	}

	bf := backupFile{
		Type: "otpvault-backup",
		Ver:  1,
		Salt: enc.Salt,
		IV:   enc.IV,
		Tag:  enc.Tag,
		Data: enc.Data,
	}
	return json.MarshalIndent(bf, "", "  ")
}

// importBackup decrypts a backup file and returns the plaintext accounts.
// Callers are responsible for re-encrypting each secret under the current
// master password via saveAccount.
func importBackup(data []byte, backupPassword string) ([]backupAccount, error) {
	var bf backupFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("invalid backup file: %w", err)
	}
	if bf.Type != "otpvault-backup" {
		return nil, fmt.Errorf("not an OTPVault backup file (type=%q)", bf.Type)
	}

	enc := EncryptedSecret{Salt: bf.Salt, IV: bf.IV, Tag: bf.Tag, Data: bf.Data}
	plaintext, err := decryptSecret(enc, []byte(backupPassword))
	if err != nil {
		return nil, fmt.Errorf("wrong backup password or corrupted file")
	}

	var payload backupPayload
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		return nil, fmt.Errorf("corrupted backup data: %w", err)
	}

	return payload.Accounts, nil
}
