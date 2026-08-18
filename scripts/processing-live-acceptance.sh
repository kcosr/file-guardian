#!/usr/bin/env bash
# Opt-in end-to-end processing acceptance using disposable synthetic inputs.
#
# This script never downloads tools, creates remote repositories, pushes data,
# or reads a production source. It requires a release binary and an operator-
# supplied schema-3 configuration whose roots are disposable and private.
# Profile expectations:
#   CLEAN_PROFILE: clean path -> allow, retained for handoff
#   BLOCK_PROFILE: documented synthetic credential -> deny
#   HEAD_PROFILE: current HEAD only -> allow when old/other-ref fixtures differ
#   REACHABLE_PROFILE: configured main ref history -> deny for deleted history,
#                      allow when the only finding is on another branch
#   ALL_REFS_PROFILE: every frozen ref -> deny for the other-branch fixture
# Optional:
#   REMEDIATE_PROFILE: apply whole-file action -> allow_modified and retain
#   PI_ADVISORY_PROFILE: fixture false positive -> deny with advisory row
#   PI_AUTHORITATIVE_PROFILE: trusted Pi override -> allow only for the
#                             explicitly documented fixture; unmarked match -> deny
#   HTTPS_REMOTE / SSH_REMOTE: disposable clones of the history fixture -> deny

set -euo pipefail

die() {
  printf 'processing acceptance: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required command is not installed: $1"
}

need git
need jq
need sha256sum

MODE=${1:-}
if [[ -n "$MODE" && "$MODE" != "--fixtures-only" ]]; then
  die "usage: $0 [--fixtures-only]"
fi

BINARY=${FG_ACCEPTANCE_BINARY:-target/release/file-guardian}
CONFIG=${FG_ACCEPTANCE_CONFIG:-}
CLEAN_PROFILE=${FG_ACCEPTANCE_CLEAN_PROFILE:-}
BLOCK_PROFILE=${FG_ACCEPTANCE_BLOCK_PROFILE:-}
HEAD_PROFILE=${FG_ACCEPTANCE_HEAD_PROFILE:-}
REACHABLE_PROFILE=${FG_ACCEPTANCE_REACHABLE_PROFILE:-}
ALL_REFS_PROFILE=${FG_ACCEPTANCE_ALL_REFS_PROFILE:-}
GITLEAKS_ID=${FG_ACCEPTANCE_GITLEAKS_ID:-gitleaks}
TRUFFLEHOG_ID=${FG_ACCEPTANCE_TRUFFLEHOG_ID:-trufflehog}

if [[ "$MODE" != "--fixtures-only" ]]; then
  [[ -x "$BINARY" ]] || die "FG_ACCEPTANCE_BINARY is not executable: $BINARY"
  [[ -n "$CONFIG" && "$CONFIG" = /* && -r "$CONFIG" ]] || \
    die "FG_ACCEPTANCE_CONFIG must be a readable absolute path"
  for required_profile in \
    "$CLEAN_PROFILE" "$BLOCK_PROFILE" "$HEAD_PROFILE" \
    "$REACHABLE_PROFILE" "$ALL_REFS_PROFILE"; do
    [[ -n "$required_profile" ]] || die "all five required profile variables must be set"
  done
fi

if [[ -n ${FG_ACCEPTANCE_ROOT:-} ]]; then
  ROOT=$FG_ACCEPTANCE_ROOT
  [[ "$ROOT" = /* ]] || die "FG_ACCEPTANCE_ROOT must be absolute"
  [[ ! -e "$ROOT" ]] || die "FG_ACCEPTANCE_ROOT must not already exist"
  install -d -m 0700 "$ROOT"
  KEEP=1
else
  ROOT=$(mktemp -d "${TMPDIR:-/tmp}/file-guardian-acceptance.XXXXXXXX")
  chmod 0700 "$ROOT"
  KEEP=${FG_ACCEPTANCE_KEEP:-0}
fi

cleanup() {
  if [[ "$KEEP" == 1 ]]; then
    printf 'processing acceptance fixtures retained at %s\n' "$ROOT" >&2
  else
    rm -rf -- "$ROOT"
  fi
}
trap cleanup EXIT

FIXTURES=$ROOT/fixtures
RESULTS=$ROOT/results
HANDOFFS=$ROOT/handoffs
install -d -m 0700 "$FIXTURES" "$RESULTS" "$HANDOFFS"

# These are public documentation/test values, not live credentials. Configured
# acceptance rules should recognize them without credential verification.
SYNTHETIC_AWS='AKIAIOSFODNN7EXAMPLE'
printf -v SYNTHETIC_GITHUB '%s_%s%s' ghp ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghij
printf -v SYNTHETIC_SLACK '%s-%s-%s' xoxb 65677559833 9613778673399u
PI_SYNTHETIC='FG_LIVE_SECRET_0123456789abcdefghijklmn'

mkdir "$FIXTURES/clean-tree" "$FIXTURES/blocked-tree" \
  "$FIXTURES/false-positive-tree" "$FIXTURES/pi-blocking-tree" \
  "$FIXTURES/remediation-tree"
printf 'This fixture contains no credential.\n' >"$FIXTURES/clean-tree/README.txt"
printf 'slack token = %s\n' "$SYNTHETIC_SLACK" \
  >"$FIXTURES/blocked-tree/synthetic-credential.txt"
printf '# FILE_GUARDIAN_DOCUMENTED_SYNTHETIC_FIXTURE\nEXAMPLE_TOKEN=%s\n' \
  "$PI_SYNTHETIC" \
  >"$FIXTURES/false-positive-tree/example.env"
printf 'PRODUCTION_SERVICE_TOKEN=%s\n' "$PI_SYNTHETIC" \
  >"$FIXTURES/pi-blocking-tree/application.env"
cp "$FIXTURES/clean-tree/README.txt" "$FIXTURES/remediation-tree/README.txt"
printf 'GITHUB_TOKEN=%s\n' "$SYNTHETIC_GITHUB" \
  >"$FIXTURES/remediation-tree/synthetic-credential.txt"

git_env=(
  env
  GIT_AUTHOR_NAME='File Guardian Fixture'
  GIT_AUTHOR_EMAIL='fixture@example.invalid'
  GIT_COMMITTER_NAME='File Guardian Fixture'
  GIT_COMMITTER_EMAIL='fixture@example.invalid'
)

git_init() {
  local repo=$1
  git init -q -b main "$repo"
  git -C "$repo" config core.autocrlf false
  git -C "$repo" config commit.gpgSign false
}

git_commit() {
  local repo=$1
  local date=$2
  local message=$3
  "${git_env[@]}" \
    GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
    git -C "$repo" commit -q -m "$message"
}

# History fixture: credential exists in main's parent but is deleted at HEAD.
HISTORY_REPO=$FIXTURES/history-repo
git_init "$HISTORY_REPO"
printf 'public fixture\n' >"$HISTORY_REPO/README.txt"
printf 'SLACK_BOT_TOKEN=%s\n' "$SYNTHETIC_SLACK" \
  >"$HISTORY_REPO/deleted-secret.env"
git -C "$HISTORY_REPO" add README.txt deleted-secret.env
git_commit "$HISTORY_REPO" '2026-01-01T00:00:00+00:00' 'add synthetic history fixture'
git -C "$HISTORY_REPO" rm -q deleted-secret.env
git_commit "$HISTORY_REPO" '2026-01-02T00:00:00+00:00' 'remove synthetic history fixture'

# Branch fixture: main is clean; the credential is reachable only from side.
BRANCH_REPO=$FIXTURES/branch-repo
git_init "$BRANCH_REPO"
printf 'public fixture\n' >"$BRANCH_REPO/README.txt"
git -C "$BRANCH_REPO" add README.txt
git_commit "$BRANCH_REPO" '2026-02-01T00:00:00+00:00' 'add clean main fixture'
git -C "$BRANCH_REPO" switch -q -c synthetic-side-ref
printf 'SLACK_BOT_TOKEN=%s\n' "$SYNTHETIC_SLACK" \
  >"$BRANCH_REPO/side-secret.env"
git -C "$BRANCH_REPO" add side-secret.env
git_commit "$BRANCH_REPO" '2026-02-02T00:00:00+00:00' 'add side-ref fixture'
git -C "$BRANCH_REPO" tag synthetic-secret-tag
git -C "$BRANCH_REPO" switch -q main

tree_digest() {
  local tree=$1
  find "$tree" -type f -print0 | LC_ALL=C sort -z | \
    xargs -0 sha256sum | sha256sum | cut -d' ' -f1
}

HISTORY_BEFORE=$(tree_digest "$HISTORY_REPO")
BRANCH_BEFORE=$(tree_digest "$BRANCH_REPO")

if [[ "$MODE" == "--fixtures-only" ]]; then
  KEEP=1
  [[ $(git -C "$HISTORY_REPO" rev-list --count main) == 2 ]] || \
    die 'history fixture does not contain two commits'
  [[ $(git -C "$BRANCH_REPO" rev-list --count main) == 1 ]] || \
    die 'branch fixture main is not the clean root commit'
  git -C "$BRANCH_REPO" show-ref --verify --quiet refs/heads/synthetic-side-ref || \
    die 'branch fixture side ref is absent'
  git -C "$BRANCH_REPO" show-ref --verify --quiet refs/tags/synthetic-secret-tag || \
    die 'branch fixture tag is absent'
  printf 'deterministic processing fixtures created at %s\n' "$FIXTURES"
  exit 0
fi

assert_private() {
  local stdout_file=$1
  local stderr_file=$2
  local value
  for value in \
    "$SYNTHETIC_AWS" "$SYNTHETIC_GITHUB" "$SYNTHETIC_SLACK" \
    "$PI_SYNTHETIC" "$ROOT"; do
    if grep -Fq -- "$value" "$stdout_file" "$stderr_file"; then
      die "private canary leaked in $(basename "$stdout_file")"
    fi
  done
}

run_process() {
  local label=$1
  local expected_exit=$2
  shift 2
  local stdout_file=$RESULTS/$label.json
  local stderr_file=$RESULTS/$label.stderr
  local status

  set +e
  "$BINARY" --config "$CONFIG" "$@" >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e

  [[ "$status" == "$expected_exit" ]] || \
    die "$label returned $status, expected $expected_exit (see $stderr_file)"
  [[ $(wc -l <"$stdout_file") == 1 ]] || die "$label did not emit one JSON line"
  jq -e --argjson status "$status" '
    .schema_version == "2" and
    .exit_code == $status and
    (.outcome == "allow" or .outcome == "allow_modified" or
     .outcome == "deny" or .outcome == "error") and
    (.omissions.details_omitted == false or .outcome == "error")
  ' "$stdout_file" >/dev/null || die "$label emitted an invalid report/status pair"
  assert_private "$stdout_file" "$stderr_file"
  printf '%-28s exit=%s outcome=%s\n' \
    "$label" "$status" "$(jq -r .outcome "$stdout_file")"
}

run_process clean-path 0 \
  process --profile "$CLEAN_PROFILE" --request-id acceptance-clean \
  path "$FIXTURES/clean-tree"
run_process blocked-path 20 \
  process --profile "$BLOCK_PROFILE" --request-id acceptance-block \
  path "$FIXTURES/blocked-tree"
jq -e --arg gitleaks "$GITLEAKS_ID" --arg trufflehog "$TRUFFLEHOG_ID" '
  (any(.phases.initial.analyzer_runs[];
    .analyzer_id == $gitleaks and .status == "complete")) and
  (any(.phases.initial.analyzer_runs[];
    .analyzer_id == $trufflehog and .status == "complete")) and
  (any(.phases.initial.occurrences[]; .analyzer_id == $gitleaks)) and
  (any(.phases.initial.occurrences[]; .analyzer_id == $trufflehog))
' "$RESULTS/blocked-path.json" >/dev/null || \
  die 'blocked fixture was not found by both completed scanner adapters'

run_process history-head 0 \
  process --profile "$HEAD_PROFILE" path "$HISTORY_REPO"
run_process history-reachable 20 \
  process --profile "$REACHABLE_PROFILE" path "$HISTORY_REPO"
run_process branch-head 0 \
  process --profile "$HEAD_PROFILE" path "$BRANCH_REPO"
run_process branch-reachable 0 \
  process --profile "$REACHABLE_PROFILE" path "$BRANCH_REPO"
run_process branch-all-refs 20 \
  process --profile "$ALL_REFS_PROFILE" path "$BRANCH_REPO"

[[ $(tree_digest "$HISTORY_REPO") == "$HISTORY_BEFORE" ]] || \
  die 'history repository was modified'
[[ $(tree_digest "$BRANCH_REPO") == "$BRANCH_BEFORE" ]] || \
  die 'branch repository was modified'

handoff() {
  local label=$1
  local report=$2
  local destination=$3
  local run_id status
  run_id=$(jq -er '.run_id' "$report")
  jq -e '.stage.handoff_status == "available" and .stage.reference == .run_id' \
    "$report" >/dev/null || die "$label report did not retain an available stage"
  set +e
  "$BINARY" --config "$CONFIG" stage handoff "$run_id" \
    --destination "$destination" --mode copy \
    >"$RESULTS/$label-handoff.json" 2>"$RESULTS/$label-handoff.stderr"
  status=$?
  set -e
  [[ "$status" == 0 ]] || die "$label handoff failed with exit $status"
  [[ $(wc -l <"$RESULTS/$label-handoff.json") == 1 ]] || \
    die "$label handoff did not emit one JSON line"
  jq -e . "$RESULTS/$label-handoff.json" >/dev/null || \
    die "$label handoff receipt is not JSON"
  assert_private "$RESULTS/$label-handoff.json" "$RESULTS/$label-handoff.stderr"
}

handoff clean "$RESULTS/clean-path.json" "$HANDOFFS/clean"
cmp "$FIXTURES/clean-tree/README.txt" "$HANDOFFS/clean/README.txt" >/dev/null || \
  die 'clean handoff content differs from its source'

if [[ -n ${FG_ACCEPTANCE_REMEDIATE_PROFILE:-} ]]; then
  REMEDIATION_BEFORE=$(tree_digest "$FIXTURES/remediation-tree")
  run_process remediation 10 \
    process --profile "$FG_ACCEPTANCE_REMEDIATE_PROFILE" --action-mode apply \
    path "$FIXTURES/remediation-tree"
  jq -e '.modified == true and (.actions | length) > 0 and .phases.verification != null' \
    "$RESULTS/remediation.json" >/dev/null || die 'remediation report lacks verified actions'
  [[ $(tree_digest "$FIXTURES/remediation-tree") == "$REMEDIATION_BEFORE" ]] || \
    die 'remediation changed the caller-owned source'
  handoff remediation "$RESULTS/remediation.json" "$HANDOFFS/remediated"
  [[ ! -e "$HANDOFFS/remediated/synthetic-credential.txt" ]] || \
    die 'remediated handoff still contains the action target'
fi

if [[ -n ${FG_ACCEPTANCE_PI_ADVISORY_PROFILE:-} ]]; then
  run_process pi-advisory 20 \
    process --profile "$FG_ACCEPTANCE_PI_ADVISORY_PROFILE" \
    path "$FIXTURES/false-positive-tree"
  jq -e '
    (.phases.initial.findings | length) > 0 and
    any(.phases.initial.resolutions[]; .state == "active") and
    any(.adjudications[]; .state == "advisory")
  ' \
    "$RESULTS/pi-advisory.json" >/dev/null || die 'Pi advisory row is absent'
fi

if [[ -n ${FG_ACCEPTANCE_PI_AUTHORITATIVE_PROFILE:-} ]]; then
  run_process pi-authoritative 0 \
    process --profile "$FG_ACCEPTANCE_PI_AUTHORITATIVE_PROFILE" \
    path "$FIXTURES/false-positive-tree"
  jq -e '
    (.phases.initial.findings | length) > 0 and
    any(.phases.initial.resolutions[]; .state == "cleared") and
    any(.adjudications[]; .state == "applied")
  ' \
    "$RESULTS/pi-authoritative.json" >/dev/null || die 'authoritative Pi override was not applied'

  run_process pi-authoritative-blocking 20 \
    process --profile "$FG_ACCEPTANCE_PI_AUTHORITATIVE_PROFILE" \
    path "$FIXTURES/pi-blocking-tree"
  jq -e '
    (.phases.initial.findings | length) > 0 and
    any(.phases.initial.resolutions[]; .state == "active") and
    any(.adjudications[];
      .state == "rejected" and .assessment != "false_positive")
  ' "$RESULTS/pi-authoritative-blocking.json" >/dev/null || \
    die 'authoritative Pi incorrectly cleared the unmarked credential fixture'
fi

if [[ -n ${FG_ACCEPTANCE_HTTPS_REMOTE:-} ]]; then
  run_process remote-https 20 \
    process --profile "$REACHABLE_PROFILE" git --ref refs/heads/main \
    "$FG_ACCEPTANCE_HTTPS_REMOTE"
  grep -Fq -- "$FG_ACCEPTANCE_HTTPS_REMOTE" \
    "$RESULTS/remote-https.json" "$RESULTS/remote-https.stderr" && \
    die 'HTTPS locator leaked into process output'
fi

if [[ -n ${FG_ACCEPTANCE_SSH_REMOTE:-} ]]; then
  run_process remote-ssh 20 \
    process --profile "$REACHABLE_PROFILE" git --ref refs/heads/main \
    "$FG_ACCEPTANCE_SSH_REMOTE"
  grep -Fq -- "$FG_ACCEPTANCE_SSH_REMOTE" \
    "$RESULTS/remote-ssh.json" "$RESULTS/remote-ssh.stderr" && \
    die 'SSH locator leaked into process output'
fi

printf 'processing acceptance passed; reports: %s\n' "$RESULTS"
