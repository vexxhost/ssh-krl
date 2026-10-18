package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/ssh-krl/internal/revocation"
)

// Auth methods for KV.
const (
	AuthToken      = "token"
	AuthKubernetes = "kubernetes"
	AuthAppRole    = "approle"
)

// KVConfig configures a KV source.
type KVConfig struct {
	// Mount is the KV secrets engine mount, e.g. "ssh-krl".
	Mount string
	// Version is the KV engine version, 1 or 2.
	Version int
	// Prefix is the path under the mount holding one entry per secret.
	Prefix string

	// AuthMethod is token, kubernetes or approle. With token, the client
	// reads BAO_TOKEN or VAULT_TOKEN.
	AuthMethod string
	// AuthMount is the auth method mount path; defaults to the method name.
	AuthMount string
	// Role is the Kubernetes auth role.
	Role string
	// JWTPath is the service account token for Kubernetes auth.
	JWTPath string
	// RoleIDPath and SecretIDPath hold AppRole credentials.
	RoleIDPath   string
	SecretIDPath string
}

// KV reads entries from an OpenBao or HashiCorp Vault KV engine.
type KV struct {
	cfg    KVConfig
	client *api.Client

	mu      sync.Mutex
	expires time.Time
}

// NewKV returns a KV source. The client reads its address and TLS settings
// from the usual BAO_* or VAULT_* environment variables.
func NewKV(cfg KVConfig) (*KV, error) {
	if cfg.Mount == "" {
		return nil, errors.New("kv mount is required")
	}
	if cfg.Version != 1 && cfg.Version != 2 {
		return nil, fmt.Errorf("kv version must be 1 or 2, got %d", cfg.Version)
	}
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = AuthToken
	}
	if cfg.AuthMount == "" {
		cfg.AuthMount = cfg.AuthMethod
	}
	switch cfg.AuthMethod {
	case AuthToken:
	case AuthKubernetes:
		if cfg.Role == "" {
			return nil, errors.New("kubernetes auth requires a role")
		}
		if cfg.JWTPath == "" {
			cfg.JWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
	case AuthAppRole:
		if cfg.RoleIDPath == "" || cfg.SecretIDPath == "" {
			return nil, errors.New("approle auth requires role id and secret id files")
		}
	default:
		return nil, fmt.Errorf("unknown auth method %q", cfg.AuthMethod)
	}
	cfg.Prefix = strings.Trim(cfg.Prefix, "/")

	conf := api.DefaultConfig()
	if conf.Error != nil {
		return nil, conf.Error
	}
	if os.Getenv("BAO_CLIENT_TIMEOUT") == "" && os.Getenv("VAULT_CLIENT_TIMEOUT") == "" {
		conf.Timeout = 10 * time.Second
	}
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	if cfg.AuthMethod == AuthToken && client.Token() == "" {
		return nil, errors.New("token auth requires BAO_TOKEN or VAULT_TOKEN")
	}
	return &KV{cfg: cfg, client: client}, nil
}

// String implements Source.
func (k *KV) String() string {
	return fmt.Sprintf("kv%d:%s/%s (%s)", k.cfg.Version, k.client.Address(), path.Join(k.cfg.Mount, k.cfg.Prefix), k.cfg.AuthMethod)
}

// login obtains a token for kubernetes and approle auth, renewing it once a
// third of its lifetime remains.
func (k *KV) login(ctx context.Context, force bool) error {
	if k.cfg.AuthMethod == AuthToken {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !force && k.client.Token() != "" && time.Until(k.expires) > 0 {
		return nil
	}

	data := map[string]any{}
	switch k.cfg.AuthMethod {
	case AuthKubernetes:
		jwt, err := os.ReadFile(k.cfg.JWTPath)
		if err != nil {
			return err
		}
		data["role"] = k.cfg.Role
		data["jwt"] = strings.TrimSpace(string(jwt))
	case AuthAppRole:
		roleID, err := os.ReadFile(k.cfg.RoleIDPath)
		if err != nil {
			return err
		}
		secretID, err := os.ReadFile(k.cfg.SecretIDPath)
		if err != nil {
			return err
		}
		data["role_id"] = strings.TrimSpace(string(roleID))
		data["secret_id"] = strings.TrimSpace(string(secretID))
	}

	k.client.ClearToken()
	secret, err := k.client.Logical().WriteWithContext(ctx, "auth/"+k.cfg.AuthMount+"/login", data)
	if err != nil {
		return fmt.Errorf("%s login: %w", k.cfg.AuthMethod, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return fmt.Errorf("%s login returned no token", k.cfg.AuthMethod)
	}
	k.client.SetToken(secret.Auth.ClientToken)
	ttl := time.Duration(secret.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	k.expires = time.Now().Add(ttl * 2 / 3)
	return nil
}

// call runs fn with a valid token, logging in again once if it is refused.
func (k *KV) call(ctx context.Context, fn func() error) error {
	if err := k.login(ctx, false); err != nil {
		return err
	}
	err := fn()
	var respErr *api.ResponseError
	if err != nil && k.cfg.AuthMethod != AuthToken && errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
		if err := k.login(ctx, true); err != nil {
			return err
		}
		err = fn()
	}
	return err
}

func (k *KV) listPath(p string) string {
	if k.cfg.Version == 2 {
		return path.Join(k.cfg.Mount, "metadata", p)
	}
	return path.Join(k.cfg.Mount, p)
}

func (k *KV) readPath(p string) string {
	if k.cfg.Version == 2 {
		return path.Join(k.cfg.Mount, "data", p)
	}
	return path.Join(k.cfg.Mount, p)
}

// names lists entry names under the prefix, recursing into sub-paths.
func (k *KV) names(ctx context.Context, dir string) ([]string, error) {
	var secret *api.Secret
	err := k.call(ctx, func() error {
		var err error
		secret, err = k.client.Logical().ListWithContext(ctx, k.listPath(path.Join(k.cfg.Prefix, dir)))
		return err
	})
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	raw, _ := secret.Data["keys"].([]any)
	var names []string
	for _, item := range raw {
		key := fmt.Sprint(item)
		if strings.HasSuffix(key, "/") {
			sub, err := k.names(ctx, path.Join(dir, key))
			if err != nil {
				return nil, err
			}
			names = append(names, sub...)
			continue
		}
		names = append(names, path.Join(dir, key))
	}
	return names, nil
}

// Entries implements Source.
func (k *KV) Entries(ctx context.Context) ([]revocation.Entry, []error, error) {
	names, err := k.names(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(names)
	var entries []revocation.Entry
	var invalid []error
	for _, name := range names {
		var secret *api.Secret
		err := k.call(ctx, func() error {
			var err error
			secret, err = k.client.Logical().ReadWithContext(ctx, k.readPath(path.Join(k.cfg.Prefix, name)))
			return err
		})
		if err != nil {
			return nil, nil, err
		}
		if secret == nil || secret.Data == nil {
			continue
		}
		data := secret.Data
		if k.cfg.Version == 2 {
			inner, ok := data["data"].(map[string]any)
			if !ok {
				continue // deleted version
			}
			data = inner
		}
		e, err := revocation.FromMap(name, data)
		if err != nil {
			invalid = append(invalid, fmt.Errorf("%s: %w", name, err))
			continue
		}
		entries = append(entries, e)
	}
	return entries, invalid, nil
}

// ResolveCA accepts a literal public key or the mount path of an SSH secrets
// engine, whose CA public key is read from its unauthenticated public_key
// endpoint.
func (k *KV) ResolveCA(ctx context.Context, ref string) (ssh.PublicKey, error) {
	if key := revocation.ParseCAKey(ref); key != nil {
		return key, nil
	}
	resp, err := k.client.Logical().ReadRawWithContext(ctx, path.Join(strings.Trim(ref, "/"), "public_key"))
	if err != nil {
		return nil, fmt.Errorf("CA %q: %w", ref, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("CA %q: %w", ref, err)
	}
	key := revocation.ParseCAKey(string(body))
	if key == nil {
		return nil, fmt.Errorf("CA %q: %s/public_key did not return a public key", ref, ref)
	}
	return key, nil
}
