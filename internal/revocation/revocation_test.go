package revocation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFR31e1Tpwaea4uROyuIthMz+P8FbyABfrG7cM6W6qUD test"

func TestFromMap(t *testing.T) {
	cases := []struct {
		name    string
		data    map[string]any
		serial  uint64
		wantErr string
	}{
		{name: "key id", data: map[string]any{"key_id": "alice@example.com", "reason": "left"}},
		{name: "key id under ca", data: map[string]any{"key_id": "alice", "ca": "users"}},
		{name: "decimal serial", data: map[string]any{"serial": "4812", "ca": "users"}, serial: 4812},
		{name: "json number serial", data: map[string]any{"serial": json.Number("18446744073709551615"), "ca": "users"}, serial: 18446744073709551615},
		{name: "hex serial", data: map[string]any{"serial": "0xc73f26d2340276aa", "ca": "users"}, serial: 0xc73f26d2340276aa},
		{name: "public key", data: map[string]any{"public_key": testKey}},
		{name: "nothing", data: map[string]any{"reason": "x"}, wantErr: "one of"},
		{name: "two targets", data: map[string]any{"key_id": "a", "public_key": testKey}, wantErr: "only one"},
		{name: "serial without ca", data: map[string]any{"serial": "1"}, wantErr: "requires ca"},
		{name: "ca with public key", data: map[string]any{"public_key": testKey, "ca": "users"}, wantErr: "does not apply"},
		{name: "hex without prefix", data: map[string]any{"serial": "c73f26d2340276aa", "ca": "users"}, wantErr: "0x"},
		{name: "bad public key", data: map[string]any{"public_key": "nope"}, wantErr: "public_key"},
		{name: "bad expiry", data: map[string]any{"key_id": "a", "expires_at": "tomorrow"}, wantErr: "expires_at"},
		{name: "non-string key id", data: map[string]any{"key_id": 3}, wantErr: "must be a string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := FromMap(tc.name, tc.data)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.serial != 0 && (e.Serial == nil || *e.Serial != tc.serial) {
				t.Fatalf("serial = %v, want %d", e.Serial, tc.serial)
			}
		})
	}
}

func TestExpired(t *testing.T) {
	e, err := FromMap("x", map[string]any{"key_id": "a", "expires_at": "2030-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Expired(time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expired before expires_at")
	}
	if !e.Expired(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("not expired at expires_at")
	}
}

func TestParseCAKey(t *testing.T) {
	if ParseCAKey(testKey) == nil {
		t.Fatal("literal key not parsed")
	}
	if ParseCAKey("ssh-client-signer") != nil {
		t.Fatal("mount name parsed as key")
	}
}
