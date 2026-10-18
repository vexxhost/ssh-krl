package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFR31e1Tpwaea4uROyuIthMz+P8FbyABfrG7cM6W6qUD"

func TestFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.yaml")
	content := `cas:
  users: ` + testCA + `
  bad: nope
revocations:
  alice:
    key_id: alice
  bob:
    serial: 42
    ca: users
  broken:
    reason: missing target
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &File{Path: path}
	ctx := context.Background()
	entries, invalid, err := f.Entries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "alice" || *entries[1].Serial != 42 {
		t.Fatalf("entries = %+v", entries)
	}
	if len(invalid) != 1 || !strings.Contains(invalid[0].Error(), "broken") {
		t.Fatalf("invalid = %v", invalid)
	}
	if _, err := f.ResolveCA(ctx, "users"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ResolveCA(ctx, testCA); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ResolveCA(ctx, "bad"); err == nil {
		t.Fatal("resolved an invalid CA")
	}
	if _, err := f.ResolveCA(ctx, "missing"); err == nil {
		t.Fatal("resolved an unknown CA")
	}
	if _, _, err := (&File{Path: path + ".missing"}).Entries(ctx); err == nil {
		t.Fatal("read a missing file")
	}
}
