# File Guardian Requirements

## Product purpose

File Guardian is a reusable file-policy and authorization engine. Its primary
interface evaluates a caller-owned, private staging tree as one transaction and
returns a fail-closed decision suitable for an upload, build, or publication
workflow. Its daemon interface runs explicitly configured policy scans on a
schedule; daemon operation is not an implicit mode.

The current implementation is read-only. It captures immutable artifacts,
executes built-in analyzers and a Linux-only internal Pi classifier through a
compiled ordered pipeline, resolves policy, and reports `allow`, `deny`, or
`error` without modifying the input. Later milestones add deterministic
scanner delegates, verified actions, recursive archives, and fingerprint
indexes.

## Operating assumptions

- Linux is the primary service platform; macOS ARM64 is also a supported
  release target.
- The service account must be able to read configured inputs, create its
  workspace, and write configured logs. Root is deployment-dependent rather
  than an inherent requirement.
- The caller exclusively owns a one-shot staging tree and prevents all other
  writers from changing it from capture through the final decision.
- File Guardian is a policy gate. It does not intercept filesystem access and
  cannot protect content an unconfined process reads before authorization.

## Command-line contract

File Guardian requires an explicit subcommand:

```text
file-guardian [--config FILE] authorize
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    PATH

file-guardian [--config FILE] daemon [--job JOB_ID ...]
```

Requirements:

- `authorize` accepts exactly one literal regular file or directory.
- The transaction root must exist and must not be a symlink or special file.
- The command does not expand globs. A directory is one authorization
  transaction.
- A configured default profile is used when `--profile` is absent.
- A CLI action mode may reduce configured authority from `apply` to `evaluate`
  but must never increase it. The current runtime supports only evaluate
  execution.
- Request IDs are bounded, log-safe correlation values; they are not paths,
  credentials, or authorization tokens.
- Missing subcommands, invalid syntax, and help use conventional CLI behavior,
  including exit `2` for syntax errors.
- After recognizing a valid `authorize` shape, operational failures attempt to
  emit a schema-valid error report and exit `30`.
- Obsolete implicit invocation, `--once`, and `--dry-run` are rejected. No
  compatibility parser or environment-based semantic override is retained.

## Caller protocol

The caller must:

1. Finish writing a private staging tree.
2. Prevent any other writer from modifying it during authorization.
3. Invoke File Guardian once for the entire tree.
4. Parse exactly one supported JSON value from stdout.
5. Verify that the report's `exit_code` equals the process exit status.
6. Publish only exits `0` and, after verified actions exist, `10`.
7. Atomically promote or consume the exact authorized staging tree.

The manifest identity is for audit and correlation. It does not authorize a
separately copied or subsequently changed tree. Callers should scan staged
copies rather than active build or upload workspaces.

## Exit and report contract

Authorization report schema `1` uses these exits:

| Exit | Outcome | Meaning |
| ---: | --- | --- |
| `0` | `allow` | Complete required analysis; input is allowed and unchanged. |
| `10` | `allow_modified` | Reserved for verified actions; currently unavailable. |
| `20` | `deny` | Complete required analysis; policy rejects the transaction. |
| `30` | `error` | The authorization result is incomplete or untrustworthy. |

Required behavior:

- Required analyzer failure is `30`, including when another analyzer found a
  deny.
- Evaluate mode returns `20` when allowing the tree would require mutation.
- Exit `20` is a complete policy decision, never a substitute for operational
  uncertainty.
- File Guardian emits exactly one compact JSON document plus a newline on
  stdout. Diagnostics and logs go to stderr or protected log files.
- Missing, malformed, truncated, unsupported, or exit-inconsistent output is a
  caller-side failure.
- Reports use relative logical artifact paths and safe codes. They must not
  contain matched credentials, raw snippets, raw prompts or transcripts,
  native scanner output, absolute staging or workspace paths, environment
  values, credentials, or chain-of-thought.

The report carries run and optional request identities, outcome, exit, modified
state, phase-aware coverage, compiled policy and pipeline identities, immutable
manifest identities, mandatory artifact records, analyzer runs, normalized
observations, resolutions, centralized actions, typed issues, and bounded
statistics. Golden examples live under
[`docs/examples/reports`](docs/examples/reports).

Top-level `artifacts` is always an array. Each record contains only a
host-generated artifact ID, physical subject ID, kind, segment-encoded relative
logical path, byte length, and content digest. It never contains an absolute or
workspace object path or file bytes. A report retains safely known records from
a trustworthy initial capture even if later analysis fails; an error before
trustworthy capture uses an empty array.

Report schema `1` remains aggregate: `pipeline_runs` records phase status and
completed stage/analyzer counts, while per-analyzer coverage and normalized
observations carry stable evidence. It does not expose task scheduling,
selector candidate lists, or prior-observation projection payloads.

## Configuration schema 2

Schema `2` is a strict end-state contract rather than a migration layer.
Unknown fields are rejected. IDs must be unique, references must resolve,
administrator paths must be absolute, requested modes must be supported, and
all workspace and protected roots must be safe and disjoint.

The main configuration defines:

- a private authorization workspace and named profiles;
- ordered pipelines, serial or bounded-parallel stages, analyzer references,
  selectors, bounded prior-observation projections, and execution settings;
- built-in analyzer applicability and resource ceilings;
- policy bindings that map observations to directives;
- explicit `policy_scan` daemon jobs and schedules;
- protected stderr/file logging.

Pipeline identity covers ordered stages, execution and prior-observation
settings, selected analyzer configurations, selectors, limits, and compiled
rule material. Profile and policy bindings/directives are covered separately by
policy identity.

Configuration path precedence is `--config`, then `FILE_GUARDIAN_CONFIG`, then
`/etc/file-guardian/config.toml`. Environment variables do not override fields
inside the selected configuration or otherwise change policy, paths, analyzer
selection, or logging semantics.

The shipped [`config/config.toml`](config/config.toml) is the source of truth
for the default executable built-in schema-v2 pipeline. The broader
[`docs/examples/active-authorization-v2.toml`](docs/examples/active-authorization-v2.toml)
records the mature pipeline and Pi contract. A valid selected Pi analyzer is
executable on Linux and must be audit-only. External-tool definitions validate
but are not executable yet; selecting one produces incomplete required coverage
and exit `30`. No analyzer is skipped or reinterpreted.

## Rule sources and built-in analysis

External rule files are strict TOML and action-free. A rule has a unique ID and
at least one supported matcher: a filename glob or text-content regex. Policy
bindings in the main configuration map normalized findings to `audit`, `deny`,
`delete`, or `quarantine`; detection rules cannot directly mutate files or
choose an outcome.

Built-in analysis requirements:

- Match filename globs against the logical filename and content regexes against
  captured immutable bytes.
- Return every match in canonical order rather than stopping at the first.
- Never include the matched value or raw content in a finding or report.
- Treat invalid UTF-8 or any NUL byte as ordinary binary and count it once as
  `not_applicable` while still evaluating filename rules. A binary path matched
  by `content_applicability.required_text_include` is incomplete required
  analysis.
- Treat valid text over the configured content limit as incomplete rather than
  `not_applicable`.
- Treat object read, length, or digest disagreement as incomplete required
  coverage and exit `30`.

## Immutable inspection and workspace

Every run owns a private workspace below the configured root. Its internal
layout may contain manifests, content-addressed objects, analyzer views,
archive work, an action journal, invocation quarantine, and temporary state;
that layout is not a public interface.

Requirements:

- Create every run workspace with owner-only access and without symlink
  traversal.
- Reject input/workspace overlap in either direction, including ancestry that
  is searchable but not directory-readable.
- Walk capture through descriptor-anchored operations.
- Count every encountered directory entry against
  `authorization.workspace.capture.max_entries`, independently from regular
  files accepted against `max_files`.
- Copy or stream each regular file once into a SHA-256-addressed object while
  hashing it, and verify metadata before and after the read.
- Reject symlinks, hardlinks, special files, cross-filesystem traversal,
  unreadable or disappearing entries, new entries during capture, and unstable
  metadata unless an explicit later policy defines safe behavior.
- Give all analyzers the same captured manifest and objects. An analyzer must
  never reopen live staging.
- Generate artifact IDs on the host. Logical paths are root-relative segment
  arrays for matching/reporting and are never reused as unchecked OS paths.
- Keep live staging unchanged in evaluate mode. Workspace cleanup failure is an
  operational error, not an allow or deny.

## Domain and policy separation

The implementation keeps these concepts separate:

- A **finding** is a deterministic observation.
- A **classification** is a probabilistic or semantic observation.
- A **resolution** maps one observation to `audit`, `deny`, `delete`, or
  `quarantine`.
- An **action** is a centralized filesystem mutation.
- An **outcome** is `allow`, `allow_modified`, `deny`, or `error`.

Analyzers emit only observations and coverage. They cannot authorize content,
select arbitrary host paths, choose filesystem actions, or mutate staging.
Bindings must resolve deterministically; ambiguous or unbound observations fail
closed. In evaluate-only operation, an `audit` resolution permits continuation,
`deny` rejects the transaction, and a mutation directive also rejects because
the requested remediation cannot be applied.

## Coverage requirements

Coverage is phase-aware and records `eligible`, `assigned`, `completed`, and
`not_applicable` candidate counts for every analyzer.

- `completed` and `not_applicable` are disjoint.
- An explicitly inapplicable assigned artifact counts as `not_applicable`, not
  completed.
- `completed + not_applicable == assigned` is necessary but not sufficient for
  a complete analyzer row; protocol, budget, tool, or execution failure keeps
  it incomplete.
- A phase is complete only when all required analyzer rows are complete.
- Exits `0` and `20` require complete initial coverage. Exit `10` will also
  require complete post-action verification.
- Coverage failures must be typed and represented in the report rather than
  existing only in logs.

## Explicit daemon operation

The daemon runs only named, configured jobs. It supports `policy_scan` jobs
with explicit targets, a profile, and an internal schedule.
Selecting one or more `--job` values limits execution to those jobs; otherwise
all enabled jobs run.

Each policy scan asynchronously invokes the same compiled evaluate-only
pipeline engine used by one-shot authorization. It captures each configured
target independently, records the decision through protected logging, never
modifies targets, and treats capture or analysis uncertainty as an error. The
daemon configuration states what the process does; simply starting File
Guardian does not imply directory scanning.

## Logging and operations

- Human diagnostics and operational logs use stderr or configured protected
  files, never authorization stdout.
- Logging configuration is validated at startup and uses bounded file rotation
  where file logging is enabled.
- Reports and logs do not expose matched secrets or immutable object content.
- Daemon errors identify the job and target without changing authorization
  semantics.
- Unit and integration tests are deterministic and offline.

## Analyzer pipeline

The runtime compiles ordered stages with serial or bounded-parallel execution
and canonical aggregation. Candidate assignments and safe projections of prior
observations are frozen before a stage begins. A failed batch stops later
batches and stages, while aggregation remains in configured analyzer order
rather than task-completion order.

Analyzer selection is compiled from `include` and `exclude` globs plus
`artifact_kinds`. Globs match the canonical raw bytes of root-relative logical
path segments joined by `/`, without lossy UTF-8 conversion; separator matching
is explicit and exclusions win. An artifact outside the selector is not
eligible and does not increment `not_applicable`. The current capture produces
`physical_file` artifacts; `archive_member` becomes useful when archive
materialization is implemented.

A stage may choose `prior_observations = "none"`, `"findings_summary"`, or
`"all_normalized"`. `findings_summary` projects only safe normalized findings;
`all_normalized` also includes safe normalized classifications. Every
projection is canonically ordered and bounded by positive
`prior_limits.max_observations` and `prior_limits.max_serialized_bytes` values.
Limit or serialization failure stops the stage and makes required analysis
incomplete.

Schema 2 currently requires every analyzer to have `required = true`; optional
advisory coverage has not been enabled. `eligible`, `assigned`, `completed`,
and `not_applicable` counters are explicit and disjoint. Complete coverage
requires the analyzer to return valid output, no issue, and
`completed + not_applicable == assigned`; arithmetic equality alone cannot turn a
protocol, task, budget, or read failure into success.

### Internal Pi classifier

The internal Pi-based LLM may read sensitive captured content because the
selected model and transport are approved for it. It remains transaction-scoped
and read-only. File Guardian invokes an administrator-pinned Pi runtime without
a shell or discovered user customizations, exposes only the pinned
File Guardian `read`, `grep`, `find`, `ls`, `manifest_list`,
`prior_observations`, and `submit_classification` tools, requires strict
terminal structured output, and validates all classifications against an
administrator vocabulary.

On Linux, Bubblewrap confinement is mandatory and has no unsandboxed fallback.
The sandbox mounts the administrator-prepared runtime and policy material, but
neither live staging nor the invocation object store. It mounts a generated,
immutable, text-only assigned-file view at `/input`. A private per-run Unix
socket carries authenticated `file-guardian-pi-proxy/2` audit/control records,
manifest mappings, compact prior observations, and terminal output. The host
schema-validates requests and enforces tool-call, byte-read, output, view, time,
and process limits. Unsupported platforms,
missing or mismatched runtime assets, sandbox startup failure, handshake or
protocol disagreement, unavailable tools, invalid terminal output, budget
exhaustion, timeout, abnormal exit, and incomplete coverage all produce exit
`30`.

The exact grant is closed. `read` and `ls` are bounded Node implementations;
`grep` and `find` invoke only manifest-pinned `rg` and `fd` directly, without a
shell or inherited helper environment, and always use `--hidden --no-ignore`.
All native paths are relative to `/input`, every call has paired authenticated
begin/end accounting, and any native validation/execution/accounting failure
invalidates the run. There is no model-callable bash, general subprocess,
arbitrary path or `/proc` access, mutation, write/edit, quarantine, deletion,
credential, or File Guardian control tool. The sandbox keeps network access
required by Pi's configured model transport. Bubblewrap therefore provides
filesystem/process confinement, not destination-limited model egress;
deployments must restrict the shared transport to approved internal endpoints.

The runtime configuration fixes `platform = "linux"`,
`sandbox = "bubblewrap-v1"`, `network = "host_internal_model"`, absolute
administrator roots and executables, normalized runtime-relative manifest,
Node launcher and Pi entrypoint paths, expected Bubblewrap and Pi versions,
provider/model/thinking, the instruction and reviewed extension, isolated agent
state, output schema, tool grant, closed vocabulary, and exhaustive nonzero
limits. Credential values come only from explicit, dedicated
parent-environment mappings at execution; the values, run token, proxy endpoint,
and invocation paths are neither config identity nor report material. Secret
values and the run token must not appear in process arguments or other
process-list-visible command material.

The manifest-pinned runtime bundle is self-contained, including Node, its
dynamic loader and shared libraries, the Pi package and dependencies, and the
CA/resolver material required by the approved model transport. The sandbox
does not mount host `/lib`, `/usr`, or `/etc`; missing or unmanifested runtime
assets fail closed.

A dynamic launcher has a sandbox-visible interpreter and runtime search path
below `/runtime`; copying an ordinary host Node executable is insufficient.
The manifest declares bundle-local `etc/resolv.conf`, `etc/hosts`,
`etc/nsswitch.conf`, and the CA bundle, which are mounted individually at their
conventional `/etc` paths. The fixed environment includes `PI_OFFLINE=1` and
`PI_TELEMETRY=0`: approved provider inference remains available through the
shared network, while incidental discovery and telemetry are disabled.

Production runtime/policy assets are root-owned, not owner-writable, and read
by a dedicated service UID. The implementation's preflight hashing and
revalidation detect ordinary changes, but path-based reopening and acceptance
of service-UID-owned assets do not eliminate hostile same-UID mutation races;
administrative ownership is part of the deployment trust boundary.

Every classification code for every profile that selects Pi has exactly one
classification binding and its directive is `audit`. Wildcard, missing,
ambiguous, or non-audit Pi bindings are invalid configuration. Audit-only means
a successfully normalized Pi result cannot cause allow, deny, or mutation and
cannot remove any deterministic observation. It does not make Pi optional:
required Pi failure still makes the authorization result untrustworthy.

Pi applicability is text-only. Assigned content is fully re-read from the
immutable object, digest/length checked, and streamed through strict UTF-8/NUL
validation before materialization. Ordinary binary files are complete
`not_applicable` coverage and do not invoke Pi; if every assignment is binary,
the audit analyzer completes with no classification. This can participate in an
allow only because the configured Pi analyzer has no applicable text; it is not
a positive LLM approval of binary content. Paths selected by
`content_applicability.required_text_include` must be valid text or required
analysis fails closed. Valid text exceeding `max_read_bytes_per_call` (which is
capped at one MiB), object errors, or identity disagreement also fail closed.
Archive members are not currently
materialized or inspected; an archive is merely an ordinary physical file and
normally becomes `not_applicable` when its bytes are binary.

Prior observations are bounded, compact normalized DTOs only. They can contain
safe finding/classification identities, categories, severities, validated
locations, confidence, and reason codes. They never enumerate clean files and
never contain content, matched values, snippets, raw scanner output, prompts,
or transcripts.

The initial Pi rollout is audit-only. Model output cannot suppress a
deterministic finding, and any required timeout, process, tool, budget, schema,
or coverage failure produces exit `30`. Reports retain only normalized
configured codes, confidence, reason codes, relative artifact identities,
coverage, and safe issues. They never retain prompts, model prose or reasoning,
tool queries/results, raw Pi stdout/stderr, artifact bytes, proxy credentials,
socket paths, runtime paths, environment values, or transport credentials.

### Deterministic external analyzers

Password, credential, and secret scanners follow Pi. Reviewed adapters will
accept host-assigned immutable candidates and return bounded, versioned NDJSON
normalized to deterministic findings. They run without a shell, without
network, inside a required sandbox with resource ceilings and full
process-group cleanup. Raw matched values and native output never enter the
authorization report.

## Planned actions and content expansion

### Verified delete and invocation quarantine

After analyzers are established, File Guardian will add centralized actions.
Delete and invocation-scoped quarantine require target identity revalidation,
journaling, deterministic target ordering, and a complete recapture and rerun
of every required analyzer. Only that verified flow may produce exit `10`.
Evaluate mode remains non-mutating. A surviving deny suppresses all mutation.

### Recursive archives

ZIP, TAR, tar+gzip, and single gzip members will become logical immutable
artifacts inside the invocation workspace, with global depth, entry, expanded
byte, compression-ratio, and time ceilings. Attacker-controlled paths will not
be conventionally extracted. A finding on an archive member targets the outer
physical staged archive for any later action.

### Exact fingerprint indexes

Exact SHA-256 fingerprints remain a separate analyzer and administration
track. Indexes will support configured source roots, root-relative
include/exclude globs, manual `build`, `sync`, `add`, and `inspect` operations,
and optional per-index daemon schedules. Static indexes may be on-demand only.

Incremental operation may reuse a file hash when validated size, modification
time, identity, and generation metadata agree; directory modification times are
hints and never proof that descendants are unchanged. Atomic SQLite
generations, WAL, one writer, pinned concurrent readers, freshness policy, and
retention provide safe daemon/one-shot database sharing. Exact whole-file
hashes detect renamed identical copies, not excerpts or modified copies.

## Implementation sequence

1. Contract and golden examples.
2. Private workspace, immutable inspection, typed domain, and all-match
   built-in rules.
3. Strict schema-v2 read-only `authorize`, JSON/stdout protocol, exits `0`,
   `20`, and `30`, plus explicit evaluate-only daemon jobs.
4. Compiled ordered pipeline, bounded parallelism, selectors, prior-observation
   projections, and shared one-shot/daemon execution.
5. Internal Pi classifier, audit-only (implemented on Linux).
6. Sandboxed deterministic password and secret scanner adapters.
7. Centralized delete and invocation quarantine with full verification and
   exit `10`.
8. Bounded recursive archive inspection.
9. Manual exact fingerprint indexing and authorization matching.
10. Incremental SQLite index generations, concurrent readers, freshness, and
   optional per-index daemon schedules.
11. Narrow deterministic redaction, then separately versioned similarity
    fingerprints.

The normative implementation contract is
[`docs/active-authorization-analyzer-pipeline.md`](docs/active-authorization-analyzer-pipeline.md).

## Acceptance gates

- Strict TOML, JSON, and report-invariant tests run offline.
- Fixed input produces deterministic manifest and observation ordering.
- Inspection never mutates input and analyzers never reopen staging.
- Every capture, analyzer, policy, cleanup, and reporting uncertainty is typed
  and cannot produce exit `0` or `20`.
- Privacy tests reject absolute paths, secrets, snippets, prompts, transcripts,
  credentials, environment values, and raw scanner output in reports.
- Offline Pi fixtures and later fake delegate processes cover malformed output,
  crashes, timeouts, pipe floods, budget exhaustion, and incomplete coverage.
- Each behavior change updates tests and public documentation and passes
  `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release`.
