// Package revocation defines a revocation entry as stored by an operator and
// how it is validated.
package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Entry is one revocation. Exactly one of KeyID, Serial or PublicKey is set.
type Entry struct {
	// Name identifies the entry in its source, for logs.
	Name string

	// KeyID revokes certificates with this key ID, under CA if set or under
	// any CA otherwise.
	KeyID string
	// Serial revokes the certificate with this serial number under CA.
	Serial *uint64
	// CA references the certificate authority for KeyID or Serial: either a
	// public key in authorized_keys format or a name the source resolves.
	CA string
	// PublicKey revokes a plain key, or the key a certificate was issued for.
	// Revoking a CA key revokes every certificate it signed.
	PublicKey ssh.PublicKey

	Reason    string
	RevokedBy string
	RevokedAt string
	// ExpiresAt, when set, drops the entry from the KRL after that time,
	// typically once every certificate it targets has expired anyway.
	ExpiresAt *time.Time
}

// Expired reports whether the entry should no longer be published.
func (e Entry) Expired(now time.Time) bool {
	return e.ExpiresAt != nil && !now.Before(*e.ExpiresAt)
}

// FromMap builds an Entry from the key/value data of a stored entry.
func FromMap(name string, data map[string]any) (Entry, error) {
	e := Entry{Name: name}
	str := func(key string) (string, error) {
		v, ok := data[key]
		if !ok || v == nil {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%s must be a string", key)
		}
		return strings.TrimSpace(s), nil
	}

	var err error
	if e.KeyID, err = str("key_id"); err != nil {
		return e, err
	}
	if e.CA, err = str("ca"); err != nil {
		return e, err
	}
	if e.Reason, err = str("reason"); err != nil {
		return e, err
	}
	if e.RevokedBy, err = str("revoked_by"); err != nil {
		return e, err
	}
	if e.RevokedAt, err = str("revoked_at"); err != nil {
		return e, err
	}

	if v, ok := data["serial"]; ok && v != nil {
		serial, err := parseSerial(v)
		if err != nil {
			return e, err
		}
		e.Serial = &serial
	}

	pub, err := str("public_key")
	if err != nil {
		return e, err
	}
	if pub != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			return e, fmt.Errorf("public_key: %w", err)
		}
		e.PublicKey = key
	}

	expires, err := str("expires_at")
	if err != nil {
		return e, err
	}
	if expires != "" {
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return e, fmt.Errorf("expires_at: %w", err)
		}
		e.ExpiresAt = &t
	}

	set := 0
	for _, ok := range []bool{e.KeyID != "", e.Serial != nil, e.PublicKey != nil} {
		if ok {
			set++
		}
	}
	switch {
	case set == 0:
		return e, errors.New("one of key_id, serial or public_key is required")
	case set > 1:
		return e, errors.New("only one of key_id, serial or public_key may be set")
	case e.Serial != nil && e.CA == "":
		return e, errors.New("serial requires ca")
	case e.PublicKey != nil && e.CA != "":
		return e, errors.New("ca does not apply to public_key")
	}
	return e, nil
}

// parseSerial accepts a JSON number, a decimal string or a 0x-prefixed
// hexadecimal string (the form OpenBao and Vault report serials in).
func parseSerial(v any) (uint64, error) {
	var s string
	switch t := v.(type) {
	case json.Number:
		s = t.String()
	case string:
		s = strings.TrimSpace(t)
	case float64:
		if t < 0 || t != float64(uint64(t)) || t > 1<<53 {
			return 0, errors.New("serial must be a whole number; use a string for large serials")
		}
		return uint64(t), nil
	case int:
		if t < 0 {
			return 0, errors.New("serial must not be negative")
		}
		return uint64(t), nil
	default:
		return 0, fmt.Errorf("serial has unsupported type %T", v)
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		n, err := strconv.ParseUint(rest, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("serial: %w", err)
		}
		return n, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("serial: %w (prefix hexadecimal serials with 0x)", err)
	}
	return n, nil
}

// ParseCAKey returns the key when ref is a public key in authorized_keys
// format, or nil when ref is a name to be resolved by a source.
func ParseCAKey(ref string) ssh.PublicKey {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ref))
	if err != nil {
		return nil
	}
	return key
}
