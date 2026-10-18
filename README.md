# ssh-krl

[![CI](https://github.com/vexxhost/ssh-krl/actions/workflows/ci.yml/badge.svg)](https://github.com/vexxhost/ssh-krl/actions/workflows/ci.yml)

Publish an OpenSSH **key revocation list (KRL)** built from revocations stored
in [OpenBao](https://openbao.org) or HashiCorp Vault.

OpenBao and Vault sign SSH certificates but have no way to revoke one, and
OpenSSH has no way to distribute a revocation list: `sshd` only reads a local
file through `RevokedKeys`. `ssh-krl` closes that gap. Operators write
revocations to a KV path; `ssh-krl` turns them into a KRL and serves it over
HTTP; hosts fetch it every minute with a small systemd timer.

```
 operator ──► KV: ssh-krl/revocations/*  ──►  ssh-krl  ──► GET /krl ──► host timer ──► /etc/ssh/revoked_keys ──► sshd
```

- Revoke by **key ID** (every certificate issued to someone), by **serial**
  under a given CA, or by **public key** (including a whole CA key).
- CAs are referenced by the mount path of an SSH secrets engine; the public key
  is read from its `public_key` endpoint.
- Keeps serving the **last good KRL** if the source becomes unreachable or an
  entry is invalid, and reports it in `/status` and metrics.
- Conditional requests (`ETag`, `If-Modified-Since`), so an idle fleet costs a
  304 per host per minute.
- Authenticates with a token, Kubernetes service account, or AppRole.
- Pure Go, no dependency on `ssh-keygen` at runtime; output is checked against
  OpenSSH's `ssh-keygen` and a real `sshd` in CI.

## Revocation entries

Each entry is one secret under the prefix (default `revocations/`) of a KV
mount (default `ssh-krl`). Exactly one of `key_id`, `serial` or `public_key` is
required.

| Field | Meaning |
| --- | --- |
| `key_id` | Revoke certificates with this key ID. Under `ca` if set, otherwise under any CA. |
| `serial` | Revoke the certificate with this serial under `ca`. Decimal, or hexadecimal with `0x` (the form OpenBao and Vault report). |
| `public_key` | Revoke a key in `authorized_keys` format: a user key, or a CA key to revoke everything it signed. |
| `ca` | SSH secrets engine mount (e.g. `ssh-client-signer`) or a public key. |
| `expires_at` | Optional RFC 3339 time after which the entry is dropped, e.g. once the certificates it targets have expired. |
| `reason`, `revoked_by`, `revoked_at` | Free text kept for humans. |

```sh
# Everything issued to someone, under any CA
bao kv put -mount=ssh-krl revocations/alice key_id=alice@example.com reason="left the company"

# One certificate, by serial
bao kv put -mount=ssh-krl revocations/laptop-4812 serial=0xc73f26d2340276aa ca=ssh-client-signer reason="lost laptop"

# A key, wherever it appears
bao kv put -mount=ssh-krl revocations/leaked public_key="ssh-ed25519 AAAA..." reason="leaked"

# Undo
bao kv metadata delete -mount=ssh-krl revocations/alice
```

The serial and key ID of an issued certificate are in the audit log of the
signing request. Tune the SSH mount so they are logged in clear:

```sh
bao secrets tune -audit-non-hmac-response-keys=serial_number ssh-client-signer
```

Revocation only stops new logins. Also prevent new certificates from being
issued (remove the user from the group, disable their entity) and terminate
existing sessions if needed.

## Running

```sh
ssh-krl -auth-method=kubernetes -auth-role=ssh-krl      # in Kubernetes
ssh-krl -auth-method=approle -auth-role-id-path=... -auth-secret-id-path=...
BAO_TOKEN=... ssh-krl                                   # token
ssh-krl -source=file -file=revocations.yaml             # no OpenBao: a YAML file
```

The address and TLS settings come from the standard `BAO_ADDR`, `BAO_CACERT`,
… variables (or their `VAULT_*` equivalents). Every flag can also be set with
an environment variable:

| Flag | Environment | Default |
| --- | --- | --- |
| `-listen` | `SSH_KRL_LISTEN` | `:8080` |
| `-source` | `SSH_KRL_SOURCE` | `kv` |
| `-kv-mount` | `SSH_KRL_KV_MOUNT` | `ssh-krl` |
| `-kv-version` | `SSH_KRL_KV_VERSION` | `2` |
| `-kv-prefix` | `SSH_KRL_KV_PREFIX` | `revocations` |
| `-auth-method` | `SSH_KRL_AUTH_METHOD` | `token` |
| `-auth-mount` | `SSH_KRL_AUTH_MOUNT` | the method name |
| `-auth-role` | `SSH_KRL_AUTH_ROLE` | |
| `-auth-jwt-path` | `SSH_KRL_AUTH_JWT_PATH` | the service account token |
| `-auth-role-id-path`, `-auth-secret-id-path` | `SSH_KRL_AUTH_ROLE_ID_PATH`, `SSH_KRL_AUTH_SECRET_ID_PATH` | |
| `-interval` | `SSH_KRL_INTERVAL` | `30s` |
| `-skip-invalid` | `SSH_KRL_SKIP_INVALID` | `false` |
| `-file` | `SSH_KRL_FILE` | |
| `-log-format` | `SSH_KRL_LOG_FORMAT` | `text` |

### OpenBao / Vault setup

```sh
bao secrets enable -path=ssh-krl -version=2 kv

bao policy write ssh-krl - <<'EOF'
path "ssh-krl/metadata/revocations"   { capabilities = ["list"] }
path "ssh-krl/metadata/revocations/*" { capabilities = ["list"] }
path "ssh-krl/data/revocations/*"     { capabilities = ["read"] }
EOF

# Kubernetes auth, for the manifests in deploy/kubernetes
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao write auth/kubernetes/role/ssh-krl \
  bound_service_account_names=ssh-krl bound_service_account_namespaces=ssh-krl \
  token_policies=ssh-krl token_ttl=1h
```

Reading a CA's `public_key` needs no token.

### Kubernetes

`deploy/kubernetes` holds a Kustomize base (Deployment with two replicas,
Service, ServiceAccount). Set `BAO_ADDR` and expose the Service to your hosts.

### Container image

`ghcr.io/vexxhost/ssh-krl`, multi-arch (amd64, arm64), distroless, non-root.

## Hosts

`contrib/systemd` contains a fetcher that replaces the KRL only with a
download OpenSSH can parse and leaves the last good file in place otherwise.

```sh
install -m 0755 contrib/systemd/ssh-krl-fetch /usr/local/sbin/
install -m 0644 contrib/systemd/ssh-krl-fetch.{service,timer} /etc/systemd/system/
echo SSH_KRL_URL=https://krl.example.com/krl > /etc/default/ssh-krl-fetch

# sshd refuses every public key login if RevokedKeys points at a missing file
ssh-keygen -k -f /etc/ssh/revoked_keys
echo 'RevokedKeys /etc/ssh/revoked_keys' > /etc/ssh/sshd_config.d/50-revoked-keys.conf
sshd -t && systemctl reload ssh
systemctl enable --now ssh-krl-fetch.timer
```

`sshd` reads the file on every authentication; no reload is needed when it
changes.

## Endpoints

| Path | |
| --- | --- |
| `/krl` | The KRL (`application/octet-stream`). 503 until the first successful refresh. |
| `/readyz` | 200 once a KRL is published, including while serving a stale one. |
| `/healthz` | Process liveness. |
| `/status` | JSON: version, size, last success, last error. |
| `/metrics` | Prometheus: `ssh_krl_last_success_timestamp_seconds`, `ssh_krl_refreshes_total`, `ssh_krl_entries`, `ssh_krl_invalid_entries`, … |

Alert when `time() - ssh_krl_last_success_timestamp_seconds` exceeds a few
minutes: hosts keep enforcing the last list, but new revocations are not
reaching them.

## Development

```sh
go test ./...                               # unit tests, checked against ssh-keygen
BAO_BIN=$(command -v bao) go test ./...     # plus integration tests against an OpenBao dev server
BAO_BIN=$(command -v bao) ./test/e2e.sh     # OpenBao + ssh-krl + a real sshd
```

## License

Apache 2.0
