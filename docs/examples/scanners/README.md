# First-party external scanner policy

File Guardian discovers configured scanner executable names through the
startup `PATH`, pins the opened executable identity for the invocation, and
runs only reviewed first-party command shapes. It never downloads or updates a
scanner. Install and version-pin scanners using the host's normal package or
image-management process.

The initial adapters are Gitleaks 8.19.x through 8.x and TruffleHog 3.90.x
through 3.x. Unsupported or malformed versions fail required analysis closed.
Both adapters accept immutable working-tree views and host-materialized Git
history views. They do not receive a repository's `.git` directory or its
authentication environment.

Before every scan, the runner invokes the same descriptor-pinned executable
inside the sandbox with `version` for Gitleaks or `--version` for TruffleHog.
The preflight has a two-second, 128-byte output limit and requires a normal
zero exit, empty stderr, and a strictly parsed supported semantic version. The
typed version is retained with the private run result; raw version bytes are
zeroed and never become report prose.

## Gitleaks

Copy `gitleaks.toml` and `gitleaks.ignore` to administrator-owned absolute
paths. Staged `.gitleaks.toml` and `.gitleaksignore` files are ordinary scan
inputs, not trusted policy.

The reviewed invocation inside the networkless sandbox is equivalent to:

```text
/scanner dir
  --config /scanner-config/gitleaks.toml
  --gitleaks-ignore-path /scanner-config/gitleaks.ignore
  --report-format json
  --report-path /output/findings.json
  --redact=100
  --exit-code 42
  --no-banner
  --no-color
  --log-level error
  --max-target-megabytes 0
  /input
```

Exit `0` is accepted only with an empty JSON report. Exit `42` is accepted only
with a nonempty report. Every other exit, malformed output, an unknown path,
Git-native metadata, or unredacted `Secret` value is an analyzer failure.

## TruffleHog

The initial profile disables credential verification and updates, and the
sandbox denies network access:

```text
/scanner
  --json
  --no-update
  --no-verification
  --results=unverified
  --fail
  --fail-on-scan-errors
  --no-color
  filesystem
  /input
```

Exit `0` is accepted only with no NDJSON findings. Exit `183` is accepted only
with one or more valid findings. Other exits and scan errors fail closed.
TruffleHog's native JSON contains secret-bearing `Raw`, `RawV2`,
`SecretParts`, and potentially `ExtraData` fields. Those private bytes are
consumed only by the first-party adapter and are never copied into normalized
observations, diagnostics, reports, or Pi context.

## Coverage and privacy

Native paths must map exactly to a host-assigned candidate. Completion counts,
artifact IDs, candidate IDs, working-tree/history surfaces, and finding IDs are
host-owned. Findings are canonically sorted and exact duplicates are collapsed
without treating the scanner's exit code as a coverage claim.

Scanner stdout, stderr, and report files are byte-bounded private data. They
are removed with the invocation workspace. Reports expose only normalized
analyzer/rule IDs, category, severity, artifact/candidate identity, and a
validated location.
