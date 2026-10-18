#!/usr/bin/env bash
# End-to-end test: OpenBao signs SSH certificates, ssh-krl publishes the KRL,
# and a real sshd accepts or refuses logins accordingly.
#
# Requires: bao (or BAO_BIN), sshd, ssh, ssh-keygen, curl, jq, go.
# Runs unprivileged; sshd listens on a high port and logs in as the current user.
set -euo pipefail

BAO_BIN=${BAO_BIN:-bao}
SSHD_BIN=${SSHD_BIN:-$(command -v sshd || echo /usr/sbin/sshd)}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "${KEEP_WORK:-}" = "" ]; then rm -rf "$WORK"; else echo "work dir kept: $WORK"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  for f in "$WORK"/*.log; do echo "--- $f" >&2; tail -n 40 "$f" >&2; done
  exit 1
}

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

wait_http() {
  for _ in $(seq 1 100); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.1; done
  fail "timed out waiting for $1"
}

BAO_PORT=$(free_port)
KRL_PORT=$(free_port)
SSH_PORT=$(free_port)
export BAO_ADDR="http://127.0.0.1:$BAO_PORT"
export BAO_TOKEN=e2e-root
USER_NAME=$(id -un)

echo "== building ssh-krl"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/ssh-krl" ./cmd/ssh-krl)

echo "== starting OpenBao dev server"
HOME="$WORK" "$BAO_BIN" server -dev -dev-root-token-id="$BAO_TOKEN" \
  -dev-listen-address="127.0.0.1:$BAO_PORT" >"$WORK/bao.log" 2>&1 &
BAO_PID=$!
PIDS+=($BAO_PID)
wait_http "$BAO_ADDR/v1/sys/health"

bao() { HOME="$WORK" "$BAO_BIN" "$@"; }

echo "== configuring SSH CA, KV and AppRole"
bao secrets enable -path=ssh-users ssh >/dev/null
bao write -field=public_key ssh-users/config/ca generate_signing_key=true key_type=ssh-ed25519 >"$WORK/ca.pub"
jq -n --arg u "$USER_NAME" '{key_type: "ca", allow_user_certificates: true, allowed_users: $u,
  default_user: $u, ttl: "1h", default_extensions: {"permit-pty": ""},
  key_id_format: "{{token_display_name}}"}' | bao write ssh-users/roles/user - >/dev/null
bao secrets enable -path=ssh-krl -version=2 kv >/dev/null
bao policy write ssh-krl - >/dev/null <<'EOF'
path "ssh-krl/metadata/revocations" { capabilities = ["list"] }
path "ssh-krl/metadata/revocations/*" { capabilities = ["list"] }
path "ssh-krl/data/revocations/*" { capabilities = ["read"] }
EOF
bao auth enable approle >/dev/null
bao write auth/approle/role/ssh-krl token_policies=ssh-krl token_ttl=1h >/dev/null
bao read -field=role_id auth/approle/role/ssh-krl/role-id >"$WORK/role-id"
bao write -f -field=secret_id auth/approle/role/ssh-krl/secret-id >"$WORK/secret-id"

echo "== starting ssh-krl (AppRole, no token in its environment)"
env -u BAO_TOKEN "$WORK/ssh-krl" -listen "127.0.0.1:$KRL_PORT" -interval 1s \
  -auth-method approle -auth-role-id-path "$WORK/role-id" -auth-secret-id-path "$WORK/secret-id" \
  >"$WORK/ssh-krl.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$KRL_PORT/readyz"

fetch_krl() { curl -fsS -o "$WORK/revoked.krl.new" "http://127.0.0.1:$KRL_PORT/krl" && mv "$WORK/revoked.krl.new" "$WORK/revoked.krl"; }
fetch_krl

echo "== starting sshd"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/host_key"
cat >"$WORK/sshd_config" <<EOF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $WORK/host_key
PidFile $WORK/sshd.pid
TrustedUserCAKeys $WORK/ca.pub
RevokedKeys $WORK/revoked.krl
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
LogLevel VERBOSE
EOF
"$SSHD_BIN" -D -e -f "$WORK/sshd_config" >"$WORK/sshd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$SSH_PORT") 2>/dev/null && break; sleep 0.1; done

sign() {
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/$1"
  bao token create -display-name="$1" -policy=root -field=token >"$WORK/$1.token"
  BAO_TOKEN=$(cat "$WORK/$1.token") bao write -field=signed_key ssh-users/sign/user \
    public_key=@"$WORK/$1.pub" >"$WORK/$1-cert.pub"
  ssh-keygen -L -f "$WORK/$1-cert.pub" | awk '/Serial:/{print $2}'
}

try_ssh() {
  ssh -F /dev/null -p "$SSH_PORT" -i "$WORK/$1" -o CertificateFile="$WORK/$1-cert.pub" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o LogLevel=ERROR "$USER_NAME@127.0.0.1" true
}

ALICE_SERIAL=$(sign alice)
BOB_SERIAL=$(sign bob)
CAROL_SERIAL=$(sign carol)
echo "   alice serial $ALICE_SERIAL, bob serial $BOB_SERIAL, carol serial $CAROL_SERIAL"

echo "== everyone can log in with an empty KRL"
for u in alice bob carol; do try_ssh $u || fail "$u refused with an empty KRL"; done

echo "== revoking alice by key ID and bob by serial"
bao kv put -mount=ssh-krl revocations/alice key_id=token-alice reason="e2e" >/dev/null
bao kv put -mount=ssh-krl revocations/bob serial="$BOB_SERIAL" ca=ssh-users reason="e2e" >/dev/null
ETAG=$(curl -fsS -D - -o /dev/null "http://127.0.0.1:$KRL_PORT/krl" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r')
for _ in $(seq 1 50); do
  NEW=$(curl -fsS -D - -o /dev/null "http://127.0.0.1:$KRL_PORT/krl" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r')
  [ "$NEW" != "$ETAG" ] && break; sleep 0.2
done
[ "$NEW" != "$ETAG" ] || fail "KRL did not change after revocations were written"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $NEW" "http://127.0.0.1:$KRL_PORT/krl")
[ "$CODE" = 304 ] || fail "conditional GET returned $CODE, want 304"
fetch_krl

try_ssh alice && fail "alice (revoked by key ID) could log in"
try_ssh bob && fail "bob (revoked by serial) could log in"
try_ssh carol || fail "carol (not revoked) was refused"
grep -q "revoked" "$WORK/sshd.log" || fail "sshd did not log a revocation"

echo "== a broken entry keeps the last good KRL"
bao kv put -mount=ssh-krl revocations/broken reason="no target" >/dev/null
bao kv delete -mount=ssh-krl revocations/alice >/dev/null
sleep 3
fetch_krl
try_ssh alice && fail "alice regained access while an entry was invalid"
curl -fsS "http://127.0.0.1:$KRL_PORT/status" | jq -e '.last_error | contains("invalid")' >/dev/null \
  || fail "status does not report the invalid entry"

echo "== fixing the entry publishes the new list"
bao kv metadata delete -mount=ssh-krl revocations/broken >/dev/null
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$KRL_PORT/status" | jq -e '.last_error == null' >/dev/null && break; sleep 0.2
done
fetch_krl
try_ssh alice || fail "alice still refused after her revocation was removed"
try_ssh bob && fail "bob regained access"

echo "== the last good KRL survives an OpenBao outage"
kill "$BAO_PID"
OUTAGE=""
for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$KRL_PORT/status" | jq -e '.last_error != null' >/dev/null && OUTAGE=1 && break
  sleep 0.2
done
[ -n "$OUTAGE" ] || fail "status does not report the outage"
curl -fsS -o /dev/null "http://127.0.0.1:$KRL_PORT/krl" || fail "KRL not served while OpenBao is down"
curl -fsS -o /dev/null "http://127.0.0.1:$KRL_PORT/readyz" || fail "not ready while OpenBao is down"
fetch_krl
try_ssh bob && fail "bob could log in during the outage"
try_ssh carol || fail "carol refused during the outage"

echo "PASS"
