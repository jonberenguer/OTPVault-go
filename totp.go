package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Decode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimRight(strings.ReplaceAll(s, " ", ""), "="))
	var bits, value int
	var out []byte
	for _, ch := range s {
		idx := strings.IndexRune(base32Alphabet, ch)
		if idx == -1 {
			return nil, fmt.Errorf("invalid base32 character: %c", ch)
		}
		value = (value << 5) | idx
		bits += 5
		if bits >= 8 {
			out = append(out, byte((value>>(bits-8))&0xff))
			bits -= 8
		}
	}
	return out, nil
}

func hotp(key []byte, counter uint64, digits int) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)
	off := h[len(h)-1] & 0x0f
	code := (uint32(h[off]&0x7f)<<24 |
		uint32(h[off+1]&0xff)<<16 |
		uint32(h[off+2]&0xff)<<8 |
		uint32(h[off+3]&0xff)) % uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code)
}

type TOTPResult struct {
	Code      string
	Remaining int
}

func totpNow(secret string, digits, period int) (TOTPResult, error) {
	key, err := base32Decode(secret)
	if err != nil {
		return TOTPResult{}, err
	}
	now := time.Now().Unix()
	counter := uint64(now / int64(period))
	remaining := period - int(now%int64(period))
	return TOTPResult{
		Code:      hotp(key, counter, digits),
		Remaining: remaining,
	}, nil
}

// hotpNow generates an HOTP code for the given counter value.
func hotpNow(secret string, counter uint64, digits int) (string, error) {
	key, err := base32Decode(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, counter, digits), nil
}

type ParsedURI struct {
	Name    string
	Issuer  string
	Secret  string
	Digits  int
	Period  int
	Type    string // "totp" (default/empty) or "hotp"
	Counter uint64 // HOTP counter
}

// formatOtpAuthURI builds a standard otpauth:// URI suitable for QR encoding.
func formatOtpAuthURI(name, issuer, secret, otpType string, counter uint64, digits, period int) string {
	if otpType == "" {
		otpType = "totp"
	}
	label := name
	if issuer != "" {
		label = issuer + ":" + name
	}
	u := url.URL{
		Scheme: "otpauth",
		Host:   otpType,
		Path:   "/" + url.PathEscape(label),
	}
	q := url.Values{}
	q.Set("secret", strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	if otpType == "hotp" {
		q.Set("counter", strconv.FormatUint(counter, 10))
	} else if period != 30 {
		q.Set("period", strconv.Itoa(period))
	}
	if digits != 6 {
		q.Set("digits", strconv.Itoa(digits))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func parseOtpAuthURI(raw string) (ParsedURI, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "otpauth" {
		return ParsedURI{}, errors.New("invalid otpauth URI")
	}
	otpType := u.Host
	if otpType != "totp" && otpType != "hotp" {
		return ParsedURI{}, fmt.Errorf("unsupported OTP type: %s", otpType)
	}
	q := u.Query()
	secret := strings.ToUpper(strings.ReplaceAll(q.Get("secret"), " ", ""))
	if secret == "" {
		return ParsedURI{}, errors.New("missing secret in URI")
	}
	issuer := q.Get("issuer")
	name := strings.TrimPrefix(u.Path, "/")
	name, _ = url.PathUnescape(name)
	if strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if issuer == "" {
			issuer = strings.TrimSpace(parts[0])
		}
		name = strings.TrimSpace(parts[1])
	}
	digits := 6
	if d, err := strconv.Atoi(q.Get("digits")); err == nil && d > 0 {
		digits = d
	}
	period := 30
	if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 {
		period = p
	}
	var counter uint64
	if otpType == "hotp" {
		if c, err := strconv.ParseUint(q.Get("counter"), 10, 64); err == nil {
			counter = c
		}
	}
	return ParsedURI{
		Name: name, Issuer: issuer, Secret: secret,
		Digits: digits, Period: period,
		Type: otpType, Counter: counter,
	}, nil
}
