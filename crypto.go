package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iterations  = 200_000
	pbkdf2KeyLen      = 32
	saltBytes         = 16
	ivBytes           = 12
	verifierSentinel  = "OTPVault-v1-verifier"
	argon2Memory      = uint32(64 * 1024) // 64 MiB
	argon2Time        = uint32(1)
	argon2Threads     = uint8(4)
)

// deriveKey uses PBKDF2-SHA256. Used only for decrypting legacy secrets.
func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New)
}

// deriveKeyArgon2id uses Argon2id. Used for all new secrets and verifiers.
func deriveKeyArgon2id(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, pbkdf2KeyLen)
}

func buildVerifier(password []byte) (Verifier, error) {
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Verifier{}, err
	}
	key := deriveKeyArgon2id(password, salt)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(verifierSentinel))
	return Verifier{
		KDF:  "argon2id",
		Salt: base64.StdEncoding.EncodeToString(salt),
		HMAC: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}, nil
}

// checkVerifier returns "ok", "wrong", or "missing".
// Dispatches on v.KDF so existing PBKDF2 vaults continue to work.
func checkVerifier(password []byte, v *Verifier) string {
	if v == nil || v.Salt == "" || v.HMAC == "" {
		return "missing"
	}
	salt, err := base64.StdEncoding.DecodeString(v.Salt)
	if err != nil {
		return "missing"
	}
	stored, err := base64.StdEncoding.DecodeString(v.HMAC)
	if err != nil {
		return "missing"
	}
	var key []byte
	if v.KDF == "argon2id" {
		key = deriveKeyArgon2id(password, salt)
	} else {
		key = deriveKey(password, salt)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(verifierSentinel))
	computed := mac.Sum(nil)
	if len(stored) != len(computed) {
		return "wrong"
	}
	if subtle.ConstantTimeCompare(stored, computed) == 1 {
		return "ok"
	}
	return "wrong"
}

func encryptSecret(plaintext string, password []byte) (EncryptedSecret, error) {
	salt := make([]byte, saltBytes)
	iv := make([]byte, ivBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return EncryptedSecret{}, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return EncryptedSecret{}, err
	}
	key := deriveKeyArgon2id(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedSecret{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedSecret{}, err
	}
	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), nil)
	// GCM appends the 16-byte tag at the end of ciphertext
	tagOffset := len(ciphertext) - gcm.Overhead()
	data := ciphertext[:tagOffset]
	tag := ciphertext[tagOffset:]
	return EncryptedSecret{
		KDF:  "argon2id",
		Salt: base64.StdEncoding.EncodeToString(salt),
		IV:   base64.StdEncoding.EncodeToString(iv),
		Tag:  base64.StdEncoding.EncodeToString(tag),
		Data: base64.StdEncoding.EncodeToString(data),
	}, nil
}

func decryptSecret(enc EncryptedSecret, password []byte) (string, error) {
	salt, err := base64.StdEncoding.DecodeString(enc.Salt)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(enc.IV)
	if err != nil {
		return "", err
	}
	tag, err := base64.StdEncoding.DecodeString(enc.Tag)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(enc.Data)
	if err != nil {
		return "", err
	}
	var key []byte
	if enc.KDF == "argon2id" {
		key = deriveKeyArgon2id(password, salt)
	} else {
		key = deriveKey(password, salt)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Reassemble ciphertext + tag for GCM Open
	combined := append(data, tag...)
	plain, err := gcm.Open(nil, iv, combined, nil)
	if err != nil {
		return "", errors.New("decryption failed: wrong password or corrupted data")
	}
	return string(plain), nil
}
