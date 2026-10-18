package source

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
)

const rootToken = "integration-root"

// devServer starts `bao server -dev` (BAO_BIN) or `vault server -dev`
// (VAULT_BIN). The test is skipped when neither is set.
func devServer(t *testing.T) *api.Client {
	t.Helper()
	bin, kind := os.Getenv("BAO_BIN"), "bao"
	if bin == "" {
		bin, kind = os.Getenv("VAULT_BIN"), "vault"
	}
	if bin == "" {
		t.Skip("set BAO_BIN or VAULT_BIN to run against a dev server")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+rootToken, "-dev-listen-address="+addr)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	logPath := filepath.Join(t.TempDir(), kind+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		logFile.Close()
		if t.Failed() {
			out, _ := os.ReadFile(logPath)
			t.Logf("%s log:\n%s", kind, out)
		}
	})

	t.Setenv("BAO_ADDR", "http://"+addr)
	t.Setenv("VAULT_ADDR", "http://"+addr)
	t.Setenv("BAO_TOKEN", rootToken)
	t.Setenv("VAULT_TOKEN", rootToken)

	conf := api.DefaultConfig()
	conf.Address = "http://" + addr
	client, err := api.NewClient(conf)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(rootToken)
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return client
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s dev server did not become healthy: %v", kind, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, c *api.Client, path string, data map[string]any) *api.Secret {
	t.Helper()
	s, err := c.Logical().Write(path, data)
	must(t, err)
	return s
}

func TestKVSource(t *testing.T) {
	root := devServer(t)
	ctx := context.Background()
	sys := root.Sys()

	must(t, sys.Mount("ssh-users", &api.MountInput{Type: "ssh"}))
	ca := write(t, root, "ssh-users/config/ca", map[string]any{"generate_signing_key": true, "key_type": "ssh-ed25519"})
	caKey := strings.TrimSpace(fmt.Sprint(ca.Data["public_key"]))

	must(t, sys.Mount("krl-v2", &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}))
	must(t, sys.Mount("krl-v1", &api.MountInput{Type: "kv", Options: map[string]string{"version": "1"}}))

	write(t, root, "krl-v2/data/revocations/alice", map[string]any{"data": map[string]any{"key_id": "alice", "reason": "left"}})
	write(t, root, "krl-v2/data/revocations/team/bob", map[string]any{"data": map[string]any{"serial": "0x2a", "ca": "ssh-users"}})
	write(t, root, "krl-v2/data/revocations/broken", map[string]any{"data": map[string]any{"reason": "no target"}})
	write(t, root, "krl-v2/data/revocations/gone", map[string]any{"data": map[string]any{"key_id": "gone"}})
	_, err := root.Logical().Delete("krl-v2/data/revocations/gone")
	must(t, err)
	write(t, root, "krl-v2/data/other/ignored", map[string]any{"data": map[string]any{"key_id": "ignored"}})
	write(t, root, "krl-v1/revocations/carol", map[string]any{"key_id": "carol"})

	t.Run("v2 with token", func(t *testing.T) {
		kv, err := NewKV(KVConfig{Mount: "krl-v2", Version: 2, Prefix: "revocations"})
		must(t, err)
		entries, invalid, err := kv.Entries(ctx)
		must(t, err)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name)
		}
		if strings.Join(names, ",") != "alice,team/bob" {
			t.Fatalf("entries = %v", names)
		}
		if len(invalid) != 1 || !strings.Contains(invalid[0].Error(), "broken") {
			t.Fatalf("invalid = %v", invalid)
		}
		if *entries[1].Serial != 42 {
			t.Fatalf("serial = %d", *entries[1].Serial)
		}
		key, err := kv.ResolveCA(ctx, "ssh-users")
		must(t, err)
		if got := strings.TrimSpace(string(sshAuthorized(key))); !strings.HasPrefix(caKey, got) {
			t.Fatalf("resolved CA %q, want %q", got, caKey)
		}
		if _, err := kv.ResolveCA(ctx, "krl-v1"); err == nil {
			t.Fatal("resolved a CA from a mount that is not an SSH engine")
		}
	})

	t.Run("v1", func(t *testing.T) {
		kv, err := NewKV(KVConfig{Mount: "krl-v1", Version: 1, Prefix: "revocations"})
		must(t, err)
		entries, _, err := kv.Entries(ctx)
		must(t, err)
		if len(entries) != 1 || entries[0].KeyID != "carol" {
			t.Fatalf("entries = %+v", entries)
		}
	})

	t.Run("empty prefix", func(t *testing.T) {
		kv, err := NewKV(KVConfig{Mount: "krl-v2", Version: 2, Prefix: "missing"})
		must(t, err)
		entries, invalid, err := kv.Entries(ctx)
		must(t, err)
		if len(entries) != 0 || len(invalid) != 0 {
			t.Fatalf("entries = %v, invalid = %v", entries, invalid)
		}
	})

	t.Run("approle with relogin", func(t *testing.T) {
		must(t, sys.EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}))
		must(t, sys.PutPolicy("krl-read", `
path "krl-v2/metadata/revocations/*" { capabilities = ["list"] }
path "krl-v2/metadata/revocations" { capabilities = ["list"] }
path "krl-v2/data/revocations/*" { capabilities = ["read"] }
`))
		write(t, root, "auth/approle/role/ssh-krl", map[string]any{"token_policies": "krl-read", "token_ttl": "1h"})
		roleID, err := root.Logical().Read("auth/approle/role/ssh-krl/role-id")
		must(t, err)
		secretID := write(t, root, "auth/approle/role/ssh-krl/secret-id", nil)

		dir := t.TempDir()
		roleIDPath := filepath.Join(dir, "role-id")
		secretIDPath := filepath.Join(dir, "secret-id")
		must(t, os.WriteFile(roleIDPath, []byte(fmt.Sprint(roleID.Data["role_id"])), 0o600))
		must(t, os.WriteFile(secretIDPath, []byte(fmt.Sprint(secretID.Data["secret_id"])), 0o600))

		t.Setenv("BAO_TOKEN", "")
		t.Setenv("VAULT_TOKEN", "")
		os.Unsetenv("BAO_TOKEN")
		os.Unsetenv("VAULT_TOKEN")
		kv, err := NewKV(KVConfig{Mount: "krl-v2", Version: 2, Prefix: "revocations",
			AuthMethod: AuthAppRole, RoleIDPath: roleIDPath, SecretIDPath: secretIDPath})
		must(t, err)
		entries, _, err := kv.Entries(ctx)
		must(t, err)
		if len(entries) != 2 {
			t.Fatalf("entries = %d", len(entries))
		}

		// Revoke the service's token behind its back: the next read must log in again.
		must(t, root.Auth().Token().RevokeTree(kv.client.Token()))
		entries, _, err = kv.Entries(ctx)
		must(t, err)
		if len(entries) != 2 {
			t.Fatalf("entries after relogin = %d", len(entries))
		}
	})

	t.Run("config errors", func(t *testing.T) {
		for _, cfg := range []KVConfig{
			{Version: 2},
			{Mount: "m", Version: 3},
			{Mount: "m", Version: 2, AuthMethod: AuthKubernetes},
			{Mount: "m", Version: 2, AuthMethod: AuthAppRole},
			{Mount: "m", Version: 2, AuthMethod: "ldap"},
		} {
			if _, err := NewKV(cfg); err == nil {
				t.Errorf("NewKV(%+v) succeeded", cfg)
			}
		}
	})
}
