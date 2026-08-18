#!/usr/bin/env bash
# Opt-in live HTTPS-credential-helper and SSH-agent acquisition acceptance.
# Everything is synthetic and disposable; no external network is used.

set -euo pipefail

die() {
  printf 'Git transport acceptance: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required command is not installed: $1"
}

for command in docker git jq openssl ssh ssh-add ssh-agent ssh-keygen; do
  need "$command"
done

BINARY=${FG_TRANSPORT_ACCEPTANCE_BINARY:-target/release/file-guardian}
CONFIG=${FG_TRANSPORT_ACCEPTANCE_CONFIG:-}
PROFILE=${FG_TRANSPORT_ACCEPTANCE_PROFILE:-}
RETAIN_PROFILE=${FG_TRANSPORT_ACCEPTANCE_RETAIN_PROFILE:-}
IMAGE=${FG_TRANSPORT_ACCEPTANCE_IMAGE:-aw-gateway/ubuntu-base:latest}
[[ -x "$BINARY" ]] || die "binary is not executable: $BINARY"
[[ -n "$CONFIG" && "$CONFIG" = /* && -r "$CONFIG" ]] || \
  die 'FG_TRANSPORT_ACCEPTANCE_CONFIG must be a readable absolute path'
[[ -n "$PROFILE" ]] || die 'FG_TRANSPORT_ACCEPTANCE_PROFILE is required'
[[ -n "$RETAIN_PROFILE" ]] || \
  die 'FG_TRANSPORT_ACCEPTANCE_RETAIN_PROFILE is required'
docker image inspect "$IMAGE" >/dev/null 2>&1 || \
  die "container image is not already installed locally: $IMAGE"

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/file-guardian-git-transport.XXXXXXXX")
chmod 0700 "$ROOT"
HTTPS_CONTAINER="fg-https-$$-$RANDOM"
SSH_CONTAINER="fg-ssh-$$-$RANDOM"
AGENT_PID=
KEEP=${FG_TRANSPORT_ACCEPTANCE_KEEP:-0}

cleanup() {
  if [[ "$KEEP" == 1 ]]; then
    docker logs "$HTTPS_CONTAINER" >"$ROOT/https-container.log" 2>&1 || true
    docker logs "$SSH_CONTAINER" >"$ROOT/ssh-container.log" 2>&1 || true
  fi
  docker rm -f "$HTTPS_CONTAINER" "$SSH_CONTAINER" >/dev/null 2>&1 || true
  if [[ -n "$AGENT_PID" ]]; then
    kill "$AGENT_PID" >/dev/null 2>&1 || true
    wait "$AGENT_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$KEEP" == 1 ]]; then
    printf 'Git transport acceptance retained at %s\n' "$ROOT" >&2
  else
    rm -rf -- "$ROOT"
  fi
}
trap cleanup EXIT

SOURCE=$ROOT/source
REMOTE_ROOT=$ROOT/remotes
RESULTS=$ROOT/results
CLIENT_HOME=$ROOT/client-home
HTTPS_ROOT=$ROOT/https
SSH_ROOT=$ROOT/ssh
SSH_SERVER=$SSH_ROOT/server
SSH_CLIENT=$SSH_ROOT/client
install -d -m 0700 \
  "$SOURCE" "$REMOTE_ROOT" "$RESULTS" "$CLIENT_HOME" \
  "$HTTPS_ROOT/tls" "$SSH_ROOT" "$SSH_CLIENT"
install -d -m 0755 "$SSH_SERVER"

printf -v SYNTHETIC_SECRET '%s-%s-%s' xoxb 65677559833 9613778673399u
git init -q -b main "$SOURCE"
git -C "$SOURCE" config user.name 'File Guardian Transport Fixture'
git -C "$SOURCE" config user.email fixture@example.invalid
git -C "$SOURCE" config commit.gpgSign false
printf 'public fixture\n' >"$SOURCE/README.txt"
printf 'token=%s\n' "$SYNTHETIC_SECRET" >"$SOURCE/deleted-secret.env"
git -C "$SOURCE" add README.txt deleted-secret.env
GIT_AUTHOR_DATE='2026-03-01T00:00:00+00:00' \
GIT_COMMITTER_DATE='2026-03-01T00:00:00+00:00' \
  git -C "$SOURCE" commit -q -m 'add synthetic secret fixture'
git -C "$SOURCE" rm -q deleted-secret.env
GIT_AUTHOR_DATE='2026-03-02T00:00:00+00:00' \
GIT_COMMITTER_DATE='2026-03-02T00:00:00+00:00' \
  git -C "$SOURCE" commit -q -m 'remove synthetic secret fixture'
git clone -q --bare "$SOURCE" "$REMOTE_ROOT/repo.git"
chmod -R a+rX "$REMOTE_ROOT"

# Authenticated HTTPS smart Git with a private disposable CA.
openssl genpkey -quiet -algorithm ED25519 -out "$HTTPS_ROOT/tls/ca.key"
openssl req -x509 -new -key "$HTTPS_ROOT/tls/ca.key" \
  -subj '/CN=File Guardian Acceptance CA' -days 1 \
  -out "$HTTPS_ROOT/tls/ca.crt"
openssl genpkey -quiet -algorithm ED25519 -out "$HTTPS_ROOT/tls/server.key"
openssl req -new -key "$HTTPS_ROOT/tls/server.key" -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -out "$HTTPS_ROOT/tls/server.csr"
openssl x509 -req -in "$HTTPS_ROOT/tls/server.csr" \
  -CA "$HTTPS_ROOT/tls/ca.crt" -CAkey "$HTTPS_ROOT/tls/ca.key" \
  -CAcreateserial -days 1 -copy_extensions copy \
  -out "$HTTPS_ROOT/tls/server.crt" >/dev/null 2>&1
HTTP_USER=file-guardian
HTTP_PASSWORD='synthetic-transport-password'
docker run -d --rm --name "$HTTPS_CONTAINER" \
  -p 127.0.0.1::8443 \
  -e FG_GIT_HTTP_USER="$HTTP_USER" \
  -e FG_GIT_HTTP_PASSWORD="$HTTP_PASSWORD" \
  -v "$REMOTE_ROOT:/srv/git:ro" \
  -v "$HTTPS_ROOT/tls:/srv/tls:ro" \
  -v "$PWD/scripts/support/git_https_server.py:/support/git_https_server.py:ro" \
  "$IMAGE" python3 /support/git_https_server.py \
    --git-root /srv/git \
    --certificate /srv/tls/server.crt --private-key /srv/tls/server.key \
    --port 8443 >/dev/null
HTTPS_PORT=$(docker port "$HTTPS_CONTAINER" 8443/tcp | awk -F: 'END {print $NF}')
[[ "$HTTPS_PORT" =~ ^[0-9]+$ ]] || die 'could not determine HTTPS port'

HELPER=$CLIENT_HOME/credential-helper
HELPER_MARKER=$CLIENT_HOME/credential-helper-used
{
  printf '#!/bin/sh\n'
  printf 'test "$1" = get || exit 0\n'
  printf ': > %q\n' "$HELPER_MARKER"
  printf "printf 'username=%%s\\npassword=%%s\\n' %q %q\n" "$HTTP_USER" "$HTTP_PASSWORD"
} >"$HELPER"
chmod 0700 "$HELPER"
git config --file "$CLIENT_HOME/.gitconfig" credential.helper "$HELPER"
git config --file "$CLIENT_HOME/.gitconfig" credential.useHttpPath true
git config --file "$CLIENT_HOME/.gitconfig" http.sslCAInfo "$HTTPS_ROOT/tls/ca.crt"
HTTPS_REMOTE="https://localhost:$HTTPS_PORT/repo.git"
HTTPS_READY=0
for _ in $(seq 1 100); do
  if HOME="$CLIENT_HOME" \
    GIT_TERMINAL_PROMPT=0 git ls-remote "$HTTPS_REMOTE" \
      >"$RESULTS/https-preflight.stdout" 2>"$RESULTS/https-preflight.stderr"; then
    HTTPS_READY=1
    break
  fi
  sleep 0.05
done
[[ "$HTTPS_READY" == 1 ]] || die 'authenticated smart-HTTPS server did not become ready'

# Real SSH server with a one-use key held only by a disposable ssh-agent.
ssh-keygen -q -t ed25519 -N '' -f "$SSH_SERVER/host-key"
ssh-keygen -q -t ed25519 -N '' -f "$SSH_CLIENT/client-key"
cp "$SSH_CLIENT/client-key.pub" "$SSH_SERVER/authorized_keys"
chmod 0600 "$SSH_SERVER/host-key" "$SSH_CLIENT/client-key"
chmod 0644 "$SSH_SERVER/host-key.pub" "$SSH_SERVER/authorized_keys"
{
  printf 'Port 2222\nListenAddress 0.0.0.0\n'
  printf 'HostKey /config/host-key\nPidFile /tmp/sshd.pid\n'
  printf 'AuthorizedKeysFile /config/authorized_keys\nStrictModes no\n'
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
  printf 'PermitRootLogin no\nAllowUsers git\nPrintMotd no\nLogLevel ERROR\n'
} >"$SSH_SERVER/sshd_config"
chmod 0644 "$SSH_SERVER/sshd_config"
docker run -d --rm --name "$SSH_CONTAINER" \
  -p 127.0.0.1::2222 \
  -v "$REMOTE_ROOT:/srv/git:ro" \
  -v "$SSH_SERVER:/config:ro" \
  "$IMAGE" sh -lc \
    'id git >/dev/null 2>&1 || useradd -m -s /bin/sh git; printf "git:unused-acceptance-password\n" | chpasswd; su -s /bin/sh git -c "git config --global --add safe.directory /srv/git/repo.git"; mkdir -p /run/sshd; exec /usr/sbin/sshd -D -e -f /config/sshd_config' \
  >/dev/null
SSH_PORT=$(docker port "$SSH_CONTAINER" 2222/tcp | awk -F: 'END {print $NF}')
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die 'could not determine SSH port'
printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$(cat "$SSH_SERVER/host-key.pub")" \
  >"$SSH_CLIENT/known_hosts"
{
  printf 'Host localhost\n'
  printf '  HostName 127.0.0.1\n  Port %s\n' "$SSH_PORT"
  printf '  UserKnownHostsFile %s\n' "$SSH_CLIENT/known_hosts"
  printf '  StrictHostKeyChecking yes\n  BatchMode yes\n'
} >"$SSH_CLIENT/ssh_config"
{
  printf '#!/bin/sh\nexec /usr/bin/ssh -F %q "$@"\n' "$SSH_CLIENT/ssh_config"
} >"$SSH_CLIENT/ssh-wrapper"
chmod 0700 "$SSH_CLIENT/ssh-wrapper"

SSH_AUTH_SOCK=$SSH_CLIENT/agent.sock ssh-agent -D -a "$SSH_CLIENT/agent.sock" \
  >/dev/null 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 100); do
  [[ -S "$SSH_CLIENT/agent.sock" ]] && break
  sleep 0.05
done
[[ -S "$SSH_CLIENT/agent.sock" ]] || die 'ssh-agent did not start'
SSH_AUTH_SOCK=$SSH_CLIENT/agent.sock ssh-add "$SSH_CLIENT/client-key" >/dev/null 2>&1
rm -f -- "$SSH_CLIENT/client-key"
[[ ! -e "$SSH_CLIENT/client-key" ]] || die 'could not remove the disposable SSH key file'

SSH_REMOTE="ssh://git@localhost:$SSH_PORT/srv/git/repo.git"
SSH_READY=0
for _ in $(seq 1 100); do
  if GIT_SSH="$SSH_CLIENT/ssh-wrapper" SSH_AUTH_SOCK="$SSH_CLIENT/agent.sock" \
    GIT_TERMINAL_PROMPT=0 git ls-remote "$SSH_REMOTE" \
      >"$RESULTS/ssh-preflight.stdout" 2>"$RESULTS/ssh-preflight.stderr"; then
    SSH_READY=1
    break
  fi
  sleep 0.05
done
[[ "$SSH_READY" == 1 ]] || die 'SSH-agent Git server did not become ready'

run_history() {
  local label=$1
  local remote=$2
  shift 2
  local report=$RESULTS/$label.json
  local stderr=$RESULTS/$label.stderr
  local status
  set +e
  env "$@" "$BINARY" --config "$CONFIG" process --profile "$PROFILE" \
    git --ref refs/heads/main "$remote" >"$report" 2>"$stderr"
  status=$?
  set -e
  [[ "$status" == 20 ]] || die "$label returned $status instead of 20"
  [[ $(wc -l <"$report") == 1 ]] || die "$label did not emit one report"
  jq -e --argjson status "$status" '
    .schema_version == "2" and .exit_code == $status and .outcome == "deny" and
    .source.kind == "git" and .acquisition.status == "complete" and
    (.phases.initial.findings | length) > 0
  ' "$report" >/dev/null || die "$label report does not prove history denial"
  if grep -Fq -- "$remote" "$report" "$stderr" || \
     grep -Fq -- "$SYNTHETIC_SECRET" "$report" "$stderr" || \
     grep -Fq -- "$HTTP_PASSWORD" "$report" "$stderr"; then
    die "$label leaked a locator, credential, or matched value"
  fi
  printf '%-12s transport=%s outcome=deny\n' "$label" "$(jq -r .source.transport "$report")"
}

run_retain() {
  local label=$1
  local remote=$2
  shift 2
  local report=$RESULTS/$label-retain.json
  local stderr=$RESULTS/$label-retain.stderr
  local destination=$RESULTS/$label-stage
  local receipt=$RESULTS/$label-handoff.json
  local status
  set +e
  env "$@" "$BINARY" --config "$CONFIG" process --profile "$RETAIN_PROFILE" \
    git --ref refs/heads/main "$remote" >"$report" 2>"$stderr"
  status=$?
  set -e
  [[ "$status" == 0 ]] || die "$label retained clone returned $status instead of 0"
  local run_id
  run_id=$(jq -er '
    select(.schema_version == "2" and .exit_code == 0 and .outcome == "allow") |
    select(.source.kind == "git" and .acquisition.status == "complete") |
    select(.stage.handoff_status == "available" and .stage.reference != null) |
    .run_id
  ' "$report") || die "$label retained-clone report is invalid"
  "$BINARY" --config "$CONFIG" stage handoff "$run_id" \
    --destination "$destination" --mode copy >"$receipt"
  [[ -d "$destination/.git" ]] || die "$label handoff omitted .git"
  [[ -f "$destination/README.txt" && ! -e "$destination/deleted-secret.env" ]] || \
    die "$label handoff does not match the selected HEAD"
  [[ $(git -C "$destination" rev-list --count HEAD) == 2 ]] || \
    die "$label handoff does not retain the complete two-commit clone"
  [[ -z $(git -C "$destination" status --porcelain) ]] || \
    die "$label handoff has an index or working-tree mismatch"
  [[ -z $(git -C "$destination" for-each-ref \
    --format='%(refname)' refs/file-guardian/) ]] || \
    die "$label handoff retains private acquisition refs"
  if grep -Fq -- "$remote" "$report" "$stderr" "$receipt" || \
     grep -Fq -- "$SYNTHETIC_SECRET" "$report" "$stderr" "$receipt" || \
     grep -Fq -- "$HTTP_PASSWORD" "$report" "$stderr" "$receipt"; then
    die "$label retained clone leaked a locator, credential, or matched value"
  fi
  printf '%-12s retained exact clone with .git\n' "$label"
}

run_history https "$HTTPS_REMOTE" \
  HOME="$CLIENT_HOME"
[[ -f "$HELPER_MARKER" ]] || die 'HTTPS credential helper was not invoked'
run_retain https "$HTTPS_REMOTE" \
  HOME="$CLIENT_HOME"

run_history ssh "$SSH_REMOTE" \
  GIT_SSH="$SSH_CLIENT/ssh-wrapper" SSH_AUTH_SOCK="$SSH_CLIENT/agent.sock"
run_retain ssh "$SSH_REMOTE" \
  GIT_SSH="$SSH_CLIENT/ssh-wrapper" SSH_AUTH_SOCK="$SSH_CLIENT/agent.sock"

printf 'Git transport acceptance passed\n'
