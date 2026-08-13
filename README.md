# file-guardian

File Guardian is a fail-closed file authorization service. A caller can stage
one file tree, run a one-shot policy evaluation, and use the process status and
machine-readable report to decide whether that exact tree may be published. It
can also run configured policy scans as explicit daemon jobs.

The current implementation is evaluate-only: it inspects an immutable private
copy through a compiled, ordered analyzer pipeline, applies built-in filename
and content rules, and never modifies the caller-owned staging tree.

> File Guardian is a policy gate, not a filesystem access-control boundary. The
> caller must prevent every other writer from changing a staging tree while it
> is being authorized and must atomically promote or consume that same tree
> after a successful decision.

## Current features

- One-shot authorization of exactly one literal regular file or directory.
- Descriptor-anchored capture into a private, invocation-scoped workspace.
- Immutable SHA-256-addressed objects shared by all analysis in the run.
- Built-in filename glob and text-content regex matching.
- Compiled multi-stage pipelines with serial or bounded-parallel stage
  execution and deterministic aggregation.
- Per-analyzer, byte-safe include/exclude selectors over immutable logical
  paths, with explicit eligible/assigned/completed/excluded coverage.
- Bounded projections of prior normalized observations for later stages.
- Strict schema-v2 configuration and action-free TOML rule files.
- Policy bindings that resolve findings independently of rule detection.
- Exactly one compact JSON report on stdout for a recognized authorization
  request; diagnostics and logs stay on stderr or in protected log files.
- Explicit asynchronous `policy_scan` daemon jobs with configured targets and
  schedules, using the same pipeline engine as one-shot authorization.

Pi classifier and external-tool definitions are parse-ready but are not yet
executable; selecting either kind fails the authorization closed with exit
`30`. Deterministic password and secret scanner delegates, delete/quarantine
actions, recursive archive inspection, and exact fingerprint indexes remain
planned. See [Roadmap](#roadmap).

## Install

Download the latest archive for your platform from
[GitHub Releases](https://github.com/kcosr/file-guardian/releases). Supported
release platforms are currently:

- `linux-x86_64`
- `macos-arm64`

The archive contains the optimized binary, sample schema-v2 configuration,
TOML rule examples, and project documentation.

```bash
RELEASE_ROOT=/path/to/file-guardian-VERSION-PLATFORM

sudo install -m 0755 "$RELEASE_ROOT/bin/file-guardian" /usr/local/bin/file-guardian
sudo install -d -m 0755 /etc/file-guardian/rules.d
sudo cp "$RELEASE_ROOT/config/config.toml" /etc/file-guardian/config.toml
sudo cp "$RELEASE_ROOT/config/rules.d/"*.toml /etc/file-guardian/rules.d/
sudo install -d -m 0700 /var/lib/file-guardian/runs
sudo install -d -m 0750 /var/log/file-guardian
```

Run File Guardian under an account that can read the configured inputs and
create private workspaces. Root is only necessary when those inputs require
root access.

## One-shot authorization

```text
file-guardian [--config FILE] authorize
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    PATH
```

`PATH` is one literal regular file or directory and represents one publication
transaction. It is not glob-expanded, and a symlink or special file cannot be
the transaction root.

```bash
file-guardian \
  --config /etc/file-guardian/config.toml \
  authorize \
  --profile publication \
  --request-id build-4821 \
  --action-mode evaluate \
  /srv/build-service/private-staging/upload-4821
```

For a syntactically valid `authorize` command, stdout contains exactly one
compact JSON document followed by a newline. The caller must parse the document
and verify that its `exit_code` equals the process status. Logs and diagnostics
are never mixed into stdout.

| Exit | Report outcome | Caller meaning |
| ---: | --- | --- |
| `0` | `allow` | Required analysis completed; the tree is allowed and unchanged. |
| `10` | `allow_modified` | Reserved until safe actions and verification are implemented. |
| `20` | `deny` | Required analysis completed; policy rejects the transaction. |
| `30` | `error` | Capture, analysis, policy, configuration, or reporting is incomplete or untrustworthy. |

CLI syntax and help errors conventionally exit `2`. A publisher must fail
closed on malformed, missing, truncated, or exit-inconsistent JSON and must
publish only exits `0` and, once supported, `10`.

### Safe caller pattern

1. Copy selected artifacts into a private staging directory.
2. Stop all other writers to that directory.
3. Invoke File Guardian once for the entire staged tree.
4. Require valid JSON and matching process/report exit codes.
5. Publish only an allowed result by atomically promoting or consuming the
   exact staged tree.

Scan staged copies, never an active build workspace. A manifest hash identifies
the captured transaction for audit; it does not authorize a later copy or a
tree changed after the run.

## Configuration and rules

Configuration schema `2` is a deliberate break from the old implicit scanner
configuration. Configuration path precedence is `--config`, then
`FILE_GUARDIAN_CONFIG`, then `/etc/file-guardian/config.toml`. Unknown fields, duplicate IDs,
unresolved references, unsupported analyzers, invalid modes, relative
administrator paths, and unsafe root overlap are rejected.

Schema v2 defines:

- authorization workspace settings and named profiles;
- ordered analyzer pipelines and stages;
- analyzer definitions and immutable-content applicability limits;
- policy bindings from observations to `audit`, `deny`, `delete`, or
  `quarantine` directives;
- explicit daemon jobs and logging settings.

Each stage chooses `serial` or bounded `parallel` execution. An analyzer's
`selection.include`, `selection.exclude`, and `selection.artifact_kinds`
compile its assignment from the immutable manifest before execution. Matching
uses canonical raw logical-path bytes with `/` separators, so non-UTF-8 path
segments do not require lossy conversion; exclusions win. Artifacts outside a
selector are not eligible and do not count as analyzer exclusions.

Later stages may request `prior_observations = "none"`,
`"findings_summary"`, or `"all_normalized"`. The host constructs a canonical,
safe projection before the stage starts and enforces the stage's
`prior_limits.max_observations` and `prior_limits.max_serialized_bytes`.
Exceeding either limit is incomplete required analysis and therefore exit
`30`.

The shipped [sample configuration](config/config.toml) is the source of truth
for an executable built-in pipeline. A broader schema-v2 example is in
[docs/examples/active-authorization-v2.toml](docs/examples/active-authorization-v2.toml).
Pi and external-tool definitions in that example parse and validate, but a
selected unsupported analyzer is never skipped: its run is incomplete and the
authorization returns exit `30`.

Rules are strict TOML documents. They describe detection only: rule IDs,
filename globs, and content regexes. Rules do not contain actions. Policy
bindings in the main configuration determine what a finding means for a
profile, keeping detection reusable and policy resolution centralized. See the
shipped [rule examples](config/rules.d/).

Built-in content inspection fails closed by default when an assigned file is
invalid UTF-8 or larger than its configured content ceiling. A configuration
may explicitly make either case inapplicable; object read failures and digest
or length disagreement are always errors.

## Daemon jobs

Passive operation is explicit rather than an implicit default:

```text
file-guardian [--config FILE] daemon [--job JOB_ID ...]
```

Each configured `policy_scan` job names its profile, targets, and schedule. With
one or more `--job` options, only those jobs run; otherwise all enabled daemon
jobs run. Scheduled jobs execute asynchronously and each target uses the same
compiled, evaluate-only pipeline engine and immutable-workspace guarantees as
the one-shot command. It reports decisions through protected logging and does
not mutate its targets.

The shipped example job is disabled intentionally. Set a deployment-specific
target and enable at least one job before starting the systemd service.

Example systemd unit:

```ini
[Unit]
Description=File Guardian policy scans
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/file-guardian --config /etc/file-guardian/config.toml daemon
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now file-guardian
```

## Security model

- The caller retains exclusive ownership of live staging throughout a run.
- Capture rejects symlinks, hardlinks, special files, cross-filesystem
  traversal, unstable metadata, and unsafe input/workspace overlap.
- All analyzers read captured immutable objects, never live staging paths.
- Reports contain artifact-relative paths and safe reason codes, not matched
  secrets, raw content, prompts, native scanner output, absolute staging or
  workspace paths, credentials, or environment values.
- Required capture or analyzer uncertainty becomes exit `30`, never allow.
- Evaluate-only mode never deletes, quarantines, redacts, or rewrites input.

## Roadmap

Implementation proceeds in this order:

1. Contract, immutable inspection, and read-only one-shot authorization.
2. Compiled ordered pipelines, bounded parallelism, artifact selectors, prior
   observation projections, and shared one-shot/daemon execution.
3. Internal, read-only Pi LLM classification, initially audit-only.
4. Sandboxed deterministic password and secret scanner delegates.
5. Centralized, journaled delete and invocation-scoped quarantine with complete
   post-action verification; this introduces exit `10`.
6. Bounded recursive archive inspection.
7. Manual then incremental exact-hash fingerprint indexes with concurrent
   SQLite readers and optional per-index daemon schedules.
8. Narrow deterministic redaction, followed separately by similarity
   fingerprints.

The full technical contract and sequencing are documented in
[docs/active-authorization-analyzer-pipeline.md](docs/active-authorization-analyzer-pipeline.md).

## Development

Run build commands from the cloned repository root:

```bash
cargo fmt
cargo clippy
cargo test
cargo build --release
```

The release binary is `target/release/file-guardian`.

## Release

Releases are driven from `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`. Use
`current` when `Cargo.toml` already has the intended version, use `patch`,
`minor`, or `major`, or pass an explicit version:

```bash
node scripts/release.mjs current
node scripts/release.mjs patch
node scripts/release.mjs minor
node scripts/release.mjs major
node scripts/release.mjs 0.1.0
```

The script stamps the changelog, commits and tags the release, pushes it,
creates the GitHub release, and prepares a fresh `Unreleased` section. If
GitHub release creation fails after the commit and tag are pushed, create the
release manually for the existing tag rather than rerunning the script.

Supported archives are named:

```text
file-guardian-VERSION-linux-x86_64.tar.gz
file-guardian-VERSION-macos-arm64.tar.gz
```

Each archive has one `file-guardian-VERSION-PLATFORM` directory containing:

- `bin/file-guardian`
- `README.md`
- `LICENSE`
- `CHANGELOG.md`
- `config/`
- `requirements.md`

Build Linux x86_64 on Linux and macOS ARM64 natively on Apple Silicon. Inspect
the archive layout and verify checksums before publishing it.

Example packaging flow:

```bash
VERSION=$(sed -n '/^\[package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)
PLATFORM=linux-x86_64 # or macos-arm64
OUT=/tmp/file-guardian-release-${VERSION}
ROOT="file-guardian-${VERSION}-${PLATFORM}"

rm -rf "$OUT/$ROOT" "$OUT/${ROOT}.tar.gz"
mkdir -p "$OUT/$ROOT/bin"
install -m 755 target/release/file-guardian "$OUT/$ROOT/bin/file-guardian"
cp README.md LICENSE CHANGELOG.md requirements.md "$OUT/$ROOT/"
cp -R config "$OUT/$ROOT/"
tar -C "$OUT" -czf "$OUT/${ROOT}.tar.gz" "$ROOT"
```

## License

MIT
