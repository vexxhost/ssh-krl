package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/ssh-krl/internal/revocation"
)

type fakeSource struct {
	mu      sync.Mutex
	entries []map[string]any
	err     error
	cas     map[string]ssh.PublicKey
}

func (f *fakeSource) set(entries ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries, f.err = entries, nil
}

func (f *fakeSource) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeSource) Entries(context.Context) ([]revocation.Entry, []error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, nil, f.err
	}
	var out []revocation.Entry
	var invalid []error
	for i, data := range f.entries {
		e, err := revocation.FromMap(fmt.Sprint(i), data)
		if err != nil {
			invalid = append(invalid, err)
			continue
		}
		out = append(out, e)
	}
	return out, invalid, nil
}

func (f *fakeSource) ResolveCA(_ context.Context, ref string) (ssh.PublicKey, error) {
	if key, ok := f.cas[ref]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown CA %q", ref)
}

func (f *fakeSource) String() string { return "fake" }

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, signer
}

func newCert(t *testing.T, ca ssh.Signer, keyID string, serial uint64) *ssh.Certificate {
	t.Helper()
	pub, _ := newKey(t)
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{"root"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func authorized(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func get(t *testing.T, h http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// revokedBy asks ssh-keygen whether OpenSSH rejects the key with this KRL.
func revokedBy(t *testing.T, krlData []byte, key ssh.PublicKey) bool {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("REQUIRE_SSH_KEYGEN") != "" {
			t.Fatal("ssh-keygen is required but not found")
		}
		t.Skip("ssh-keygen not found")
	}
	dir := t.TempDir()
	krlPath := filepath.Join(dir, "krl")
	keyPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(krlPath, krlData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, ssh.MarshalAuthorizedKey(key), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(bin, "-Q", "-f", krlPath, keyPath).CombinedOutput()
	switch {
	case strings.Contains(string(out), "REVOKED"):
		return true
	case strings.Contains(string(out), ": ok"):
		return false
	}
	t.Fatalf("unexpected ssh-keygen output: %s", out)
	return false
}

func TestServer(t *testing.T) {
	caPub, caSigner := newKey(t)
	otherPub, otherSigner := newKey(t)
	leakedPub, _ := newKey(t)

	src := &fakeSource{cas: map[string]ssh.PublicKey{"users": caPub}}
	clk := &clock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	srv := New(Config{Source: src, Interval: time.Minute, Now: clk.now, Logger: discard()})
	h := srv.Handler()
	ctx := context.Background()

	if rec := get(t, h, "/readyz", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before first refresh = %d", rec.Code)
	}
	if rec := get(t, h, "/krl", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("krl before first refresh = %d", rec.Code)
	}
	if rec := get(t, h, "/healthz", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}

	src.set(
		map[string]any{"key_id": "alice"},
		map[string]any{"serial": "42", "ca": "users"},
		map[string]any{"public_key": authorized(leakedPub)},
		map[string]any{"key_id": "old", "expires_at": "2029-12-31T00:00:00Z"},
	)
	if err := srv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/krl", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("krl = %d", rec.Code)
	}
	first := rec.Body.Bytes()
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}

	checks := []struct {
		name string
		key  ssh.PublicKey
		want bool
	}{
		{"alice under any CA", newCert(t, otherSigner, "alice", 1), true},
		{"serial 42 under users", newCert(t, caSigner, "bob", 42), true},
		{"serial 42 under another CA", newCert(t, otherSigner, "bob", 42), false},
		{"serial 43 under users", newCert(t, caSigner, "bob", 43), false},
		{"leaked key", leakedPub, true},
		{"expired entry", newCert(t, caSigner, "old", 5), false},
		{"other CA key", otherPub, false},
	}
	for _, c := range checks {
		if got := revokedBy(t, first, c.key); got != c.want {
			t.Errorf("%s: revoked = %v, want %v", c.name, got, c.want)
		}
	}

	if rec := get(t, h, "/krl", map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified {
		t.Fatalf("conditional GET = %d, want 304", rec.Code)
	}

	clk.add(time.Minute)
	if err := srv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := get(t, h, "/krl", nil).Header().Get("ETag"); got != etag {
		t.Fatal("ETag changed although revocations did not")
	}

	src.fail(errors.New("source down"))
	clk.add(time.Minute)
	if err := srv.Refresh(ctx); err == nil {
		t.Fatal("refresh succeeded with a failing source")
	}
	rec = get(t, h, "/krl", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(first) {
		t.Fatal("last good KRL not served while the source fails")
	}
	var st Status
	if err := json.Unmarshal(get(t, h, "/status", nil).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.LastError == "" || !st.Published {
		t.Fatalf("status = %+v", st)
	}

	src.set(map[string]any{"key_id": "alice"}, map[string]any{"serial": "nope", "ca": "users"})
	if err := srv.Refresh(ctx); err == nil {
		t.Fatal("refresh succeeded with an invalid entry")
	}
	if get(t, h, "/krl", nil).Body.String() != string(first) {
		t.Fatal("KRL changed although an entry was invalid")
	}

	src.set(map[string]any{"key_id": "carol"})
	clk.add(time.Minute)
	if err := srv.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	rec = get(t, h, "/krl", nil)
	if rec.Header().Get("ETag") == etag {
		t.Fatal("ETag did not change")
	}
	second := rec.Body.Bytes()
	if revokedBy(t, second, newCert(t, caSigner, "alice", 1)) {
		t.Fatal("removed revocation still applies")
	}
	if !revokedBy(t, second, newCert(t, caSigner, "carol", 1)) {
		t.Fatal("new revocation not applied")
	}
	st = Status{}
	if err := json.Unmarshal(get(t, h, "/status", nil).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.LastError != "" {
		t.Fatalf("last error not cleared: %q", st.LastError)
	}

	metrics, _ := io.ReadAll(get(t, h, "/metrics", nil).Body)
	for _, want := range []string{`ssh_krl_refreshes_total{result="error"} 2`, "ssh_krl_entries 1", "ssh_krl_last_success_timestamp_seconds"} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestSkipInvalid(t *testing.T) {
	src := &fakeSource{}
	srv := New(Config{Source: src, SkipInvalid: true, Logger: discard()})
	src.set(map[string]any{"key_id": "alice"}, map[string]any{"reason": "no target"})
	if err := srv.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := srv.status(); !st.Published {
		t.Fatal("not published with skip-invalid")
	}
}

func TestVersionIncreases(t *testing.T) {
	src := &fakeSource{}
	clk := &clock{t: time.Unix(1000, 0)}
	srv := New(Config{Source: src, Now: clk.now, Logger: discard()})
	var last uint64
	for i := range 3 {
		src.set(map[string]any{"key_id": fmt.Sprint(i)})
		if err := srv.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		v := srv.status().Version
		if v <= last {
			t.Fatalf("version %d after %d", v, last)
		}
		last = v
	}
}

func TestUnknownCA(t *testing.T) {
	src := &fakeSource{}
	srv := New(Config{Source: src, Logger: discard()})
	src.set(map[string]any{"serial": "1", "ca": "missing"})
	if err := srv.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v", err)
	}
}

func TestETagIndependentOfGenerationTime(t *testing.T) {
	src := &fakeSource{}
	src.set(map[string]any{"key_id": "alice"})
	a := New(Config{Source: src, Now: func() time.Time { return time.Unix(1000, 0) }, Logger: discard()})
	b := New(Config{Source: src, Now: func() time.Time { return time.Unix(2000, 0) }, Logger: discard()})
	for _, s := range []*Server{a, b} {
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if a.status().ETag != b.status().ETag {
		t.Fatal("replicas with the same revocations publish different ETags")
	}
	rec := get(t, b.Handler(), "/krl", map[string]string{"If-None-Match": a.status().ETag})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("conditional GET across replicas = %d, want 304", rec.Code)
	}
}
