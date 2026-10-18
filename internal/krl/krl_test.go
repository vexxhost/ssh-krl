package krl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshKeygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("REQUIRE_SSH_KEYGEN") != "" {
			t.Fatal("ssh-keygen is required but not found")
		}
		t.Skip("ssh-keygen not found")
	}
	return path
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func genKey(t *testing.T, bin, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	run(t, bin, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path)
	return path
}

func signCert(t *testing.T, bin, ca, key, id, serial string) string {
	t.Helper()
	run(t, bin, "-q", "-s", ca, "-I", id, "-z", serial, "-n", "root", key+".pub")
	return key + "-cert.pub"
}

func loadPub(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// revoked asks ssh-keygen whether OpenSSH considers the key revoked by the KRL.
func revoked(t *testing.T, bin, krlPath, keyPath string) bool {
	t.Helper()
	out, _ := exec.Command(bin, "-Q", "-f", krlPath, keyPath).CombinedOutput()
	switch {
	case strings.Contains(string(out), "REVOKED"):
		return true
	case strings.Contains(string(out), ": ok"):
		return false
	}
	t.Fatalf("unexpected ssh-keygen -Q output for %s: %s", keyPath, out)
	return false
}

func TestKRLAgainstOpenSSH(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()

	ca1 := genKey(t, bin, dir, "ca1")
	ca2 := genKey(t, bin, dir, "ca2")
	user := genKey(t, bin, dir, "user")
	other := genKey(t, bin, dir, "other")
	leaked := genKey(t, bin, dir, "leaked")
	ca3 := genKey(t, bin, dir, "ca3")

	certs := map[string]string{
		"ca1-serial-42":    signCert(t, bin, ca1, genKey(t, bin, dir, "a"), "carol", "42"),
		"ca1-serial-43":    signCert(t, bin, ca1, genKey(t, bin, dir, "b"), "carol", "43"),
		"ca2-serial-42":    signCert(t, bin, ca2, genKey(t, bin, dir, "c"), "carol", "42"),
		"ca2-alice":        signCert(t, bin, ca2, genKey(t, bin, dir, "d"), "alice", "7"),
		"ca1-bob":          signCert(t, bin, ca1, genKey(t, bin, dir, "e"), "bob", "8"),
		"ca2-bob":          signCert(t, bin, ca2, genKey(t, bin, dir, "f"), "bob", "9"),
		"ca1-on-leaked":    signCert(t, bin, ca1, leaked, "dave", "10"),
		"ca1-serial-2^63+": signCert(t, bin, ca1, genKey(t, bin, dir, "g"), "erin", "9223372036854775809"),
		"ca3-any":          signCert(t, bin, ca3, genKey(t, bin, dir, "h"), "frank", "11"),
	}

	b := NewBuilder("test")
	b.RevokeSerial(loadPub(t, ca1+".pub"), 42)
	b.RevokeSerial(loadPub(t, ca1+".pub"), 9223372036854775809)
	b.RevokeKeyID(nil, "alice")
	b.RevokeKeyID(loadPub(t, ca1+".pub"), "bob")
	b.RevokeKey(loadPub(t, leaked+".pub"))
	b.RevokeKey(loadPub(t, ca3+".pub"))
	if b.Len() != 6 {
		t.Fatalf("Len() = %d, want 6", b.Len())
	}

	krlPath := filepath.Join(dir, "revoked.krl")
	if err := os.WriteFile(krlPath, b.Marshal(1234, time.Unix(1700000000, 0)), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, bin, "-Q", "-l", "-f", krlPath)

	cases := map[string]bool{
		certs["ca1-serial-42"]:    true,
		certs["ca1-serial-43"]:    false,
		certs["ca2-serial-42"]:    false,
		certs["ca2-alice"]:        true,
		certs["ca1-bob"]:          true,
		certs["ca2-bob"]:          false,
		certs["ca1-on-leaked"]:    true,
		certs["ca1-serial-2^63+"]: true,
		certs["ca3-any"]:          true,
		leaked + ".pub":           true,
		ca3 + ".pub":              true,
		ca2 + ".pub":              false,
		ca1 + ".pub":              false,
		user + ".pub":             false,
		other + ".pub":            false,
	}
	for path, want := range cases {
		if got := revoked(t, bin, krlPath, path); got != want {
			t.Errorf("%s: revoked = %v, want %v", filepath.Base(path), got, want)
		}
	}
}

func TestEmptyKRLParses(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	key := genKey(t, bin, dir, "key")
	krlPath := filepath.Join(dir, "empty.krl")
	if err := os.WriteFile(krlPath, NewBuilder("").Marshal(0, time.Unix(0, 0)), 0o644); err != nil {
		t.Fatal(err)
	}
	if revoked(t, bin, krlPath, key+".pub") {
		t.Fatal("empty KRL revoked a key")
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	ca := loadPub(t, genKey(t, bin, dir, "ca")+".pub")
	key := loadPub(t, genKey(t, bin, dir, "key")+".pub")

	build := func(order int) []byte {
		b := NewBuilder("c")
		ops := []func(){
			func() { b.RevokeSerial(ca, 3) },
			func() { b.RevokeSerial(ca, 1) },
			func() { b.RevokeKeyID(nil, "z") },
			func() { b.RevokeKeyID(nil, "a") },
			func() { b.RevokeKey(key) },
		}
		if order == 1 {
			for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
				ops[i], ops[j] = ops[j], ops[i]
			}
		}
		for _, op := range ops {
			op()
		}
		return b.Marshal(5, time.Unix(1700000000, 0))
	}
	if string(build(0)) != string(build(1)) {
		t.Fatal("Marshal output depends on insertion order")
	}
}
