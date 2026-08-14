# file-guardian

File Guardian is a fail-closed file authorization service. A caller can stage
one file tree, run a one-shot policy evaluation, and use the process status and
machine-readable report to decide whether that exact tree may be published. It
can also run configured policy scans as explicit daemon jobs.

The current implementation is evaluate-only: it inspects an immutable private
copy through a compiled, ordered analyzer pipeline, applies built-in filename
and content rules, can obtain audit-only semantic classifications from an
approved internal model through Pi on Linux, and never modifies the
caller-owned staging tree.

> File Guardian is a policy gate, not a filesystem access-control boundary. The
> caller must prevent every other writer from changing a staging tree while it
> is being authorized and must atomically promote or consume that same tree
> after a successful decision.

## Current features

- One-shot authorization of exactly one literal regular file or directory.
- Descriptor-anchored capture into a private, invocation-scoped workspace.
- Independent traversal-entry and captured-file ceilings, so directory-heavy
  or rejected-entry trees cannot bypass capture work limits.
- Immutable SHA-256-addressed objects shared by all analysis in the run.
- Built-in filename glob and text-content regex matching.
- Compiled multi-stage pipelines with serial or bounded-parallel stage
  execution and deterministic aggregation.
- Per-analyzer, byte-safe include/exclude selectors over immutable logical
  paths, with explicit `eligible`, `assigned`, `completed`, and
  `not_applicable` coverage.
- Bounded projections of prior normalized observations for later stages.
- Linux Pi classification through a required Bubblewrap sandbox, a generated
  immutable text view, a private authenticated audit proxy, strict terminal
  structured output, and a closed administrator vocabulary.
- Strict schema-v2 configuration and action-free TOML rule files.
- Policy bindings that resolve findings independently of rule detection.
- Exactly one compact JSON report on stdout for a recognized authorization
  request; diagnostics and logs stay on stderr or in protected log files.
- Explicit asynchronous `policy_scan` daemon jobs with configured targets and
  schedules, using the same pipeline engine as one-shot authorization.

Pi classification is intentionally audit-only: every configured classification
maps to `audit` and cannot suppress deterministic findings or change the final
decision. External-tool definitions are parse-ready but are not yet executable;
selecting one fails authorization closed with exit `30`. Deterministic password
and secret scanner delegates, delete/quarantine actions, recursive archive
inspection, and exact fingerprint indexes remain planned. See
[Roadmap](#roadmap).

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

On SIGINT or SIGTERM, `authorize` cancels in-flight analysis, signals supervised
Pi teardown, drops the private invocation workspace, and attempts a schema-valid
error report with exit `30`. SIGKILL, kernel OOM termination, power loss, or a
process crash cannot run cleanup; deployments should remove stale owner-only
run directories before reuse according to their retention policy.

| Exit | Report outcome | Caller meaning |
| ---: | --- | --- |
| `0` | `allow` | Required analysis completed; the tree is allowed and unchanged. |
| `10` | `allow_modified` | Reserved until safe actions and verification are implemented. |
| `20` | `deny` | Required analysis completed; policy rejects the transaction. |
| `30` | `error` | Capture, analysis, policy, configuration, or reporting is incomplete or untrustworthy. |

CLI syntax and help errors conventionally exit `2`. A publisher must fail
closed on malformed, missing, truncated, or exit-inconsistent JSON and must
publish only exits `0` and, once supported, `10`.

Report schema `1` always includes top-level `artifacts`. Each record contains a
host-generated artifact and subject ID, kind, segment-encoded relative logical
path, byte length, and content digest. The array never exposes absolute staging
or workspace paths, object-store paths, or file content. It is empty before a
trustworthy capture and may retain safely known captured records on a later
error.

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

Pipeline identity covers ordered stages, execution and prior-observation
settings, selected analyzer configurations, selectors, limits, and compiled
rule material. Profile and policy bindings/directives are covered separately by
policy identity.

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
for the default executable built-in pipeline. A broader schema-v2 example is in
[docs/examples/active-authorization-v2.toml](docs/examples/active-authorization-v2.toml).
It documents Pi's Linux runtime and audit-only bindings. External-tool
definitions parse and validate, but a selected unsupported analyzer is never
skipped: its run is incomplete and authorization returns exit `30`.

Rules are strict TOML documents. They describe detection only: rule IDs,
filename globs, and content regexes. Rules do not contain actions. Policy
bindings in the main configuration determine what a finding means for a
profile, keeping detection reusable and policy resolution centralized. See the
shipped [rule examples](config/rules.d/).

Built-in content inspection treats invalid UTF-8 or NUL-containing content as
ordinary binary `not_applicable` coverage while still applying filename rules.
Paths selected by `content_applicability.required_text_include` must be text.
Valid oversized text, object read failures, and digest or length disagreement
always fail closed.

### Pi runtime deployment

Pi is an optional Linux analyzer for an internal model that is approved to
receive sensitive staged content. Its configuration pins `platform = "linux"`,
`sandbox = "bubblewrap-v1"`, `network = "host_internal_model"`, the Bubblewrap
and Pi versions, provider, model, thinking level, closed vocabulary and complete
resource limits. It also identifies an administrator-owned `runtime_root`, a
relative runtime manifest, Node `launcher`, and `pi_entrypoint` within that
root, the reviewed File Guardian extension and instruction, and an isolated
agent directory. See the complete
[schema-v2 example](docs/examples/active-authorization-v2.toml).

Prepare those files outside the authorization workspace, owned and writable
only by the administrator. The isolated agent directory is different: it must
be owned by the File Guardian service UID and have no group/other permission
bits on any directory or file. Configure credentials as explicit mappings from
the dedicated `FILE_GUARDIAN_PI_CREDENTIAL_*` parent namespace to narrowly
accepted provider credential variables. Values are loaded only at execution,
are not configuration or pipeline identity material, and must never appear in
a report or diagnostic. Ambient Pi extensions, skills, prompts, themes,
sessions, tools, shell access, and inherited environment customization are
disabled.

The runtime manifest pins the exact Pi version and hashes of all bundle files.
The configured launcher and Pi entrypoint are normalized paths within that
bundle; File Guardian invokes the pinned Node launcher with the pinned Pi CLI
entrypoint directly, without depending on a host `/usr/bin/env node` shebang.
The bundle is self-contained: it includes the launcher, dynamic loader and
shared libraries, Pi package and dependencies, and CA/resolver material needed
by the approved model transport. Inside Bubblewrap the verified runtime,
reviewed extension, isolated Pi agent state, and private proxy endpoint are the
only persistent mounts. The isolated agent state is the sole writable
persistent mount because Pi creates credential/settings lock files and may
persist an OAuth refresh. It must be a dedicated copy containing no ambient
user configuration. Its path and security contract are compiled, but its
mutable credential/settings contents are deliberately excluded from pipeline
identity and immutable runtime stamps. Ownership and permissions are
revalidated immediately before every launch. The instruction is delivered by
the authenticated host proxy and live staging/object storage is never mounted.

The sandbox does not mount the host `/lib`, `/usr`, or `/etc`. A missing or
unmanifested runtime, loader, library, trust, or resolver asset therefore fails
closed instead of being discovered from the host.

For a dynamically linked launcher, the ELF interpreter and runtime search paths
must be patched to sandbox-visible locations below `/runtime`; merely copying a
normal host Node executable and its libraries is insufficient. The runtime
manifest must also include bundle-local `etc/resolv.conf`, `etc/hosts`,
`etc/nsswitch.conf`, and the configured CA bundle. The runner mounts those
verified files at their conventional `/etc` locations. Pi starts with
`PI_OFFLINE=1` and `PI_TELEMETRY=0`; model inference still uses the explicitly
configured provider transport, while incidental discovery and telemetry are
disabled. The illustrative
[runtime manifest](docs/examples/pi-classifier/runtime-manifest.example.json)
shows the strict file-entry shape but uses placeholder hashes.

For production, make the bundle, extension, and instruction root-owned and not
owner-writable, then run File Guardian under a dedicated service UID. Give only
that UID access to its mode-0700 isolated Pi agent-state directory. Preflight
hashing and revalidation detect ordinary changes, but the current path-based
reopen and intentionally writable agent state do not defend against hostile
concurrent mutation by that same UID.

The model sees a generated immutable, text-only `/input` view, never live
staging or the object store. Pi's built-ins are disabled; the reviewed extension
provides only `read`, `grep`, `find`, `ls`, `manifest_list`,
`prior_observations`, and `submit_classification`. Paths are confined beneath
`/input`; `grep` and `find` use pinned `rg`/`fd` with `--hidden --no-ignore`;
every native call is bounded and recorded through the authenticated
`file-guardian-pi-proxy/2` protocol. There is no model-callable bash, general
subprocess, arbitrary-path or `/proc` reader, write, or edit capability.

`manifest_list` returns byte-bounded pages containing `cursor`,
`next_cursor`, and `entries`. Its model-facing schema is an empty object: the
model calls the tool repeatedly, while the trusted extension owns and advances
the cursor until `next_cursor` is `null`. Calls after completion harmlessly
return the same empty terminal page. This supports the configured 100,000-file
view without requiring one unbounded response. Native tool completion is recorded as `completed`,
`recoverable_error`, or `fatal_error`. Invalid model-supplied search patterns
or arguments return a sanitized retryable result. Path confinement,
authentication, accounting, helper process, and other integrity failures remain
fatal. Search and listing truncation returns complete lines plus a deterministic
notice, never a partial record.

Binary assigned files are ordinary `not_applicable` Pi coverage and are omitted
from `/input`. An all-binary Pi assignment completes without a classification
and may allow only under the remaining complete policy; it is not positive
approval of binary bytes. Configured required-text paths fail closed if binary;
oversized text and immutable-object disagreement also fail closed. Archive
inspection remains deferred: archive bytes receive no recursive treatment and
normally behave as an ordinary binary physical file. Prior observations expose
only bounded normalized findings/classifications—not clean-file output,
content, matches, snippets, prompts, transcripts, or raw scanner output.

Bubblewrap must be present at the configured absolute path and match its pinned
version. File Guardian does not fall back to launching Pi directly. Because the
sandbox shares networking for the model call, restrict the service account or
approved model gateway at the deployment layer; `bubblewrap-v1` does not by
itself limit endpoint destinations.

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

Each daemon decision is emitted both as a complete schema-valid report on
stderr and as a structured event through the configured protected logger.
Scheduled intervals use delay semantics, so a slow scan does not cause a burst
of catch-up executions. An enabled daemon job requires `logging.level` to be
`info`, `debug`, or `trace`; startup fails closed if the configured filter would
drop decision events.

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
- A Pi process sees neither live staging nor File Guardian's object store. Its
  only content access is a private per-run Unix-socket protocol over opaque
  assigned IDs, with host-enforced call and byte budgets.
- Pi confinement requires Linux and Bubblewrap; there is no unsandboxed or
  non-Linux fallback. The sandbox retains network access for the configured
  model transport, so deployment networking must restrict that shared
  transport to approved internal endpoints.
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
3. Internal, read-only Pi LLM classification, audit-only (implemented on
   Linux).
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
