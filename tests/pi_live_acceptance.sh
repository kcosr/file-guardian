#!/usr/bin/env bash
set -euo pipefail

# Explicit opt-in integration check. This contacts the provider configured in
# FILE_GUARDIAN_PI_LIVE_CONFIG and is never run by the default test suite.
: "${FILE_GUARDIAN_PI_LIVE_CONFIG:?set an absolute Pi-enabled schema-v2 config path}"
: "${FILE_GUARDIAN_PI_LIVE_INPUT:?set an absolute synthetic private staging path}"

case "$FILE_GUARDIAN_PI_LIVE_CONFIG:$FILE_GUARDIAN_PI_LIVE_INPUT" in
  /*:/*) ;;
  *) echo "config and input must be absolute paths" >&2; exit 2 ;;
esac

fg_bin=${FILE_GUARDIAN_BIN:-target/release/file-guardian}
test -x "$fg_bin"
command -v jq >/dev/null
command -v sha256sum >/dev/null
command -v tar >/dev/null

snapshot() {
  local target=$1
  if test -d "$target"; then
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      -cf - -C "$target" . | sha256sum | cut -d' ' -f1
  else
    sha256sum "$target" | cut -d' ' -f1
  fi
}

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
before=$(snapshot "$FILE_GUARDIAN_PI_LIVE_INPUT")

set +e
"$fg_bin" --config "$FILE_GUARDIAN_PI_LIVE_CONFIG" authorize \
  --action-mode evaluate "$FILE_GUARDIAN_PI_LIVE_INPUT" \
  >"$tmp_dir/report.json" 2>"$tmp_dir/diagnostic.log"
status=$?
set -e

test "$status" -eq 0
test "$(wc -l <"$tmp_dir/report.json")" -eq 1
jq -e --argjson status "$status" '
  .schema_version == "1" and
  .exit_code == $status and
  .outcome == "allow" and
  .modified == false and
  .coverage.initial.status == "complete"
' "$tmp_dir/report.json" >/dev/null
if grep -F -- "$FILE_GUARDIAN_PI_LIVE_INPUT" "$tmp_dir/report.json" >/dev/null; then
  echo "report exposed the absolute staging path" >&2
  exit 1
fi

after=$(snapshot "$FILE_GUARDIAN_PI_LIVE_INPUT")
test "$before" = "$after"
echo "Pi live acceptance passed with an unchanged input and schema-valid allow report."
