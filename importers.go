package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ── Google Authenticator migration URI ────────────────────────────────────
//
// Format: otpauth-migration://offline?data=<base64-encoded-protobuf>
// The protobuf schema (field numbers match Google's implementation):
//   MigrationPayload.otp_parameters (field 1, repeated embedded message)
//     OtpParameters.secret   (field 1, bytes  — raw secret, not base32)
//     OtpParameters.name     (field 2, string)
//     OtpParameters.issuer   (field 3, string)
//     OtpParameters.algorithm(field 4, varint — 1=SHA1)
//     OtpParameters.digits   (field 5, varint — 1=six, 2=eight)
//     OtpParameters.type     (field 6, varint — 1=HOTP, 2=TOTP)

func parseGoogleAuthMigration(uri string) ([]ParsedURI, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}
	if u.Scheme != "otpauth-migration" {
		return nil, fmt.Errorf("expected otpauth-migration:// URI")
	}
	rawData := u.Query().Get("data")
	if rawData == "" {
		return nil, fmt.Errorf("missing data parameter")
	}
	protoBytes, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		// Some QR scanners strip padding
		protoBytes, err = base64.RawStdEncoding.DecodeString(rawData)
		if err != nil {
			return nil, fmt.Errorf("invalid base64: %w", err)
		}
	}
	return decodeMigrationProto(protoBytes)
}

func decodeMigrationProto(data []byte) ([]ParsedURI, error) {
	var results []ParsedURI
	pos := 0
	for pos < len(data) {
		tag, next := readVarint(data, pos)
		if next < 0 {
			break
		}
		pos = next
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0: // varint — skip
			_, pos = readVarint(data, pos)
		case 2: // length-delimited
			length, next := readVarint(data, pos)
			if next < 0 {
				return nil, fmt.Errorf("invalid protobuf length")
			}
			pos = next
			if length > uint64(len(data)-pos) {
				return nil, fmt.Errorf("protobuf length overflows data")
			}
			end := pos + int(length)
			if fieldNum == 1 { // otp_parameters
				entry, err := decodeOtpParameters(data[pos:end])
				if err == nil && entry != nil {
					results = append(results, *entry)
				}
			}
			pos = end
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", wireType)
		}
	}
	return results, nil
}

func decodeOtpParameters(data []byte) (*ParsedURI, error) {
	var secret []byte
	var name, issuer string
	digits := 1  // 1=six, 2=eight
	otpType := 0 // 1=HOTP, 2=TOTP
	var counter uint64

	pos := 0
	for pos < len(data) {
		tag, next := readVarint(data, pos)
		if next < 0 {
			break
		}
		pos = next
		fieldNum := tag >> 3
		wireType := tag & 0x7

		switch wireType {
		case 0:
			val, next := readVarint(data, pos)
			if next < 0 {
				return nil, fmt.Errorf("invalid varint in OtpParameters")
			}
			pos = next
			switch fieldNum {
			case 5:
				digits = int(val)
			case 6:
				otpType = int(val)
			case 7:
				counter = val
			}
		case 2:
			length, next := readVarint(data, pos)
			if next < 0 {
				return nil, fmt.Errorf("invalid length in OtpParameters")
			}
			pos = next
			if length > uint64(len(data)-pos) {
				return nil, fmt.Errorf("length overflows OtpParameters")
			}
			end := pos + int(length)
			switch fieldNum {
			case 1:
				secret = data[pos:end]
			case 2:
				name = string(data[pos:end])
			case 3:
				issuer = string(data[pos:end])
			}
			pos = end
		default:
			return nil, fmt.Errorf("unsupported wire type %d in OtpParameters", wireType)
		}
	}

	if otpType != 1 && otpType != 2 {
		return nil, nil // skip unknown types
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("missing secret")
	}

	// Google Auth names are often "Issuer:account@example.com"
	if issuer == "" && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		issuer = strings.TrimSpace(parts[0])
		name = strings.TrimSpace(parts[1])
	}

	numDigits := 6
	if digits == 2 {
		numDigits = 8
	}

	typeStr := "totp"
	if otpType == 1 {
		typeStr = "hotp"
	}

	return &ParsedURI{
		Name:    name,
		Issuer:  issuer,
		Secret:  base32.StdEncoding.EncodeToString(secret),
		Digits:  numDigits,
		Period:  30,
		Type:    typeStr,
		Counter: counter,
	}, nil
}

func readVarint(data []byte, pos int) (uint64, int) {
	var result uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		pos++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, pos
		}
		shift += 7
		if shift >= 64 {
			return 0, -1
		}
	}
	return 0, -1
}

// ── Aegis JSON export ─────────────────────────────────────────────────────

type aegisExport struct {
	DB struct {
		Entries []struct {
			Type   string `json:"type"`
			Name   string `json:"name"`
			Issuer string `json:"issuer"`
			Info   struct {
				Secret  string `json:"secret"`
				Digits  int    `json:"digits"`
				Period  int    `json:"period"`
				Counter uint64 `json:"counter"` // HOTP only
			} `json:"info"`
		} `json:"entries"`
	} `json:"db"`
}

func parseAegisExport(data []byte) ([]ParsedURI, error) {
	var export aegisExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("invalid Aegis JSON: %w", err)
	}
	var results []ParsedURI
	for _, e := range export.DB.Entries {
		typ := strings.ToLower(e.Type)
		if typ != "totp" && typ != "hotp" {
			continue
		}
		if e.Info.Secret == "" {
			continue
		}
		digits := e.Info.Digits
		if digits == 0 {
			digits = 6
		}
		period := e.Info.Period
		if period == 0 {
			period = 30
		}
		results = append(results, ParsedURI{
			Name:    e.Name,
			Issuer:  e.Issuer,
			Secret:  strings.ToUpper(strings.ReplaceAll(e.Info.Secret, " ", "")),
			Digits:  digits,
			Period:  period,
			Type:    typ,
			Counter: e.Info.Counter,
		})
	}
	return results, nil
}

// ── Bitwarden JSON export ─────────────────────────────────────────────────

type bitwardenExport struct {
	Encrypted bool `json:"encrypted"`
	Items     []struct {
		Name  string `json:"name"`
		Login struct {
			Totp     string `json:"totp"`
			Username string `json:"username"`
		} `json:"login"`
	} `json:"items"`
}

func parseBitwardenExport(data []byte) ([]ParsedURI, error) {
	var export bitwardenExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("invalid Bitwarden JSON: %w", err)
	}
	if export.Encrypted {
		return nil, fmt.Errorf("encrypted Bitwarden exports are not supported — export without encryption first")
	}
	var results []ParsedURI
	for _, item := range export.Items {
		totp := strings.TrimSpace(item.Login.Totp)
		if totp == "" {
			continue
		}
		if strings.HasPrefix(totp, "otpauth://") {
			parsed, err := parseOtpAuthURI(totp)
			if err != nil {
				continue
			}
			if parsed.Name == "" {
				parsed.Name = item.Login.Username
			}
			if parsed.Issuer == "" {
				parsed.Issuer = item.Name
			}
			results = append(results, parsed)
		} else {
			// Raw base32 secret
			name := item.Login.Username
			if name == "" {
				name = item.Name
			}
			results = append(results, ParsedURI{
				Name:   name,
				Issuer: item.Name,
				Secret: strings.ToUpper(strings.ReplaceAll(totp, " ", "")),
				Digits: 6,
				Period: 30,
			})
		}
	}
	return results, nil
}
