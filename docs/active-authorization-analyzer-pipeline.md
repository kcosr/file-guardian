# Active Authorization and Analyzer Pipeline

Status: implementation contract

Configuration schema: `2`

Authorization report schema: `1`

## Purpose

File Guardian supports an active, one-shot authorization workflow in addition
to explicit scheduled policy scans. A caller prepares a private staging tree,
invokes File Guardian, and publishes that exact tree only when the process exit
status and the JSON report both say it is allowed.

The implemented foundation includes the contract, immutable inspection,
read-only authorization, the generic Phase 3 pipeline engine, and the Linux Pi
classifier: compiled ordered stages, bounded parallelism, immutable artifact
selection, bounded prior-observation projections, shared one-shot/daemon
execution, and audit-only semantic classification through a confined internal
model client. Deterministic password and secret scanners follow. Safe actions,
archives, and fingerprint indexes remain later phases without changing the
core pipeline or report meanings.

## Caller contract

The caller must:

1. Finish writing a private staging tree before authorization begins.
2. Prevent every other writer from changing it through capture, analysis,
   action, and verification.
3. Invoke File Guardian with one literal file or directory operand.
4. Parse exactly one supported JSON value from stdout.
5. Verify that `exit_code` in the report equals the process exit status.
6. Publish only exits `0` and `10`.
7. Atomically promote or consume the exact authorized staging tree.

The manifest identity is an audit and correlation value. It does not authorize
a separately copied or subsequently changed tree.

## Command contract

```text
file-guardian [--config FILE] authorize
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    PATH

file-guardian [--config FILE] daemon [--job JOB_ID ...]
```

`authorize` accepts exactly one literal regular file or directory. It does not
expand globs, does not follow a symlink transaction root, and rejects missing or
special roots. A directory is one publication transaction.

The selected profile grants maximum action authority. A CLI option may reduce
`apply` to `evaluate`, but cannot upgrade an evaluate-only profile. Syntax and
help errors use conventional CLI exit `2`. After a valid `authorize` shape is
recognized, operational failures attempt to emit an error report and exit
`30`.

## Exit contract

| Exit | Outcome | Meaning |
| ---: | --- | --- |
| `0` | `allow` | Complete required pipeline; staging is allowed and unchanged. |
| `10` | `allow_modified` | Authorized mutations completed and a full verification pipeline allows the result. |
| `20` | `deny` | Complete required pipeline; policy rejects the transaction. |
| `30` | `error` | Capture, required analysis, policy, action, verification, configuration, or reporting is incomplete or untrustworthy. |

Rules:

- Required analyzer failure is `30`, even when another analyzer found a deny.
- Evaluate mode is `20` if allowing the tree would require mutation.
- Exit `10` is reserved until safe actions and post-action verification exist.
- Missing, malformed, truncated, or exit-inconsistent stdout is failure.
- File Guardian writes exactly one compact JSON document plus a newline to
  stdout; diagnostics and logs go to stderr or protected files.

Golden reports are checked in under [`examples/reports`](examples/reports).

## Authorization report

Report schema `1` contains these top-level fields:

- `schema_version`, `run_id`, optional `request_id`, `outcome`, `exit_code`,
  and `modified`.
- Phase-aware `coverage.initial` and `coverage.verification`.
- The compiled policy and pipeline identities in `policy`.
- Initial and final immutable manifest identities in `input`.
- `pipeline_runs`, normalized `observations`, policy `resolutions`, centralized
  `actions`, typed `issues`, and bounded `statistics`.

Schema `1` deliberately remains an aggregate authorization report. Its
`pipeline_runs` entries summarize phase status and completed stage/analyzer
counts; it does not expose internal task scheduling, selector candidates, or
prior-observation projection payloads. Per-analyzer coverage and normalized
observations remain the stable evidence surfaces.

Issues discovered before capture or analyzer execution use the `initial` phase;
the typed issue code distinguishes configuration, input, workspace, policy, and
pipeline failures. This keeps the two-phase report vocabulary closed while
still permitting startup error reports with null `policy` and `input` fields.

Invariants:

- Exits `0`, `10`, and `20` require complete initial coverage.
- Exit `10` requires complete verification, at least one applied mutation, and
  final allow.
- Exit `0` requires `modified = false`.
- Exit `20` represents a complete policy decision, not operational ambiguity.
- Exit `30` has an unknown final decision and may retain safely known partial
  state.
- `input.final_manifest_identity` is null when initial capture succeeded but
  final live-input revalidation could not produce a trustworthy manifest. An
  error report may retain a differing final identity when it proves the input
  changed. Allow and deny require equal initial and final identities.
- Initial observations remain visible after successful remediation.

Reports never contain matched passwords, credentials, raw content snippets,
raw model prompts or transcripts, native scanner output, absolute staging or
workspace paths, credentials, environment values, or chain-of-thought. They may
contain safe rule/reason codes, relative logical paths, artifact IDs, validated
locations, component identities, and opaque quarantine IDs.

## Invocation workspace and immutable inspection

Every run owns a private workspace beneath the configured workspace root:

```text
<workspace-root>/<run-id>/
  manifest/
  objects/
  analyzer-views/
  archive-work/
  action-journal/
  quarantine/
  tmp/
```

The layout is private and not part of the public API. The workspace must be
created with owner-only permissions, without symlink traversal, and must be
disjoint from the input, quarantine, journal, log, configuration, and later
fingerprint roots.

Capture walks the staged tree using descriptor-anchored operations. Regular
files are copied or streamed once into content-addressed workspace objects while
hashing. Metadata is checked before and after reading. Symlinks, hardlinks,
special files, cross-filesystem traversal, unreadable entries, disappearing
files, new entries during capture, and unstable metadata are governed by
explicit policy and otherwise become typed coverage failures.

All analyzers read the same captured objects. They never reopen live staging.
Artifact IDs are host-generated; logical paths are root-relative segment arrays
for selector matching and reporting and are never reused as unchecked
operating-system paths.

## Domain separation

The engine keeps five concepts distinct:

- A **finding** is a deterministic observation.
- A **classification** is a probabilistic or semantic observation from an
  allowed vocabulary.
- A **resolution** maps an observation to `audit`, `deny`, `delete`, or
  `quarantine`.
- An **action** is a centralized filesystem mutation.
- An **outcome** is `allow`, `allow_modified`, `deny`, or `error`.

Analyzers return observations and coverage only. They cannot select arbitrary
host paths, mutate staging, choose actions, or authorize content.

## Analyzer pipeline

An authorization profile selects exactly one compiled pipeline. A pipeline is
an ordered list of stages. A stage runs analyzers serially or in bounded
parallel; later stages may receive a bounded, host-produced projection of prior
normalized observations.

```text
immutable manifest
  -> built-in policy stage
  -> deterministic security stage (later)
  -> semantic Pi stage
  -> coverage validation
  -> policy resolution
  -> outcome or centralized actions
```

Initial stage rules:

- Each analyzer appears at most once.
- Applicability is compiled from configuration, not analyzer output. Each
  analyzer has include/exclude globs and artifact-kind selectors.
- Candidate assignments and prior-observation projections are frozen before a
  stage starts.
- Parallel completion order never changes report order or policy resolution.
- Serial stages execute one analyzer at a time. Parallel stages execute
  configured-order batches no larger than `max_concurrency`; a failed batch
  prevents later batches and stages from starting.
- `required = true` is the default and the only accepted setting in the
  current schema. A failure stops the pipeline and yields `30` before actions.
- Optional advisory coverage is reserved but is not currently enabled.
- Once actions exist, every required analyzer reruns during post-action
  verification.

Selector globs operate on canonical raw logical-path bytes: path segments are
joined with `/`, glob separators remain literal, and no lossy UTF-8 conversion
is used. This permits wildcard selection of non-UTF-8 names without changing
their identity. An artifact must match an include and no exclude; exclusions
win. Artifacts outside the selected kinds or globs are outside the eligible set
and do not increment `excluded`. The current capture creates
`physical_file` artifacts; `archive_member` selection becomes active with the
archive phase.

`prior_observations` has three closed values:

- `none` supplies an empty projection.
- `findings_summary` supplies canonically ordered, explicitly safe normalized
  finding fields and omits classifications.
- `all_normalized` supplies those findings plus safe normalized classification
  fields.

The projection is built from completed earlier stages before any analyzer in
the next stage starts. `prior_limits.max_observations` and
`prior_limits.max_serialized_bytes` must be positive and bound both its count
and canonical serialized form. Overflow or serialization failure stops the
stage as incomplete required analysis. The obsolete `all_summary` spelling is
not accepted.

Coverage records the inspection phase and eligible, assigned, completed, and
excluded candidate counts. An analyzer's inability to inspect an assigned
candidate is incomplete coverage, not an exclusion.

The counters are disjoint: `completed` counts assigned artifacts the analyzer
inspected, while `excluded` counts assigned artifacts made explicitly
inapplicable by policy. `completed + excluded == assigned` is required for a
`complete` analyzer row, but it is not sufficient: protocol, budget, tool, or
other execution failures keep the analyzer and phase `incomplete` even when all
assigned artifacts are arithmetically accounted for. A `complete` phase requires
every analyzer row to be complete. Excluded artifacts never also increment
`completed`.

Pi and external-tool analyzer definitions are accepted by the strict parser so
the end-state configuration has one shape. Pi has a Linux Bubblewrap runner;
external tools do not yet have a runner. A selected unsupported analyzer
produces incomplete coverage and a typed process failure, and authorization
returns exit `30`. Unsupported analyzers are never silently skipped.

## Built-in rules

Existing filename glob and content regex matching becomes the first analyzer.
It operates on immutable artifacts, returns every match in canonical order, and
reports binary, encoding, size, and read applicability explicitly. Existing
rule-embedded `warn`, `remove`, and `recover` behavior is replaced in schema v2
by normalized findings plus policy bindings.

Invalid UTF-8 and content larger than `max_content_bytes` fail closed by
default. A built-in analyzer may explicitly configure either condition as
`exclude`; such an artifact is counted once in that analyzer's `excluded`
coverage while its filename rules still run. This is intentional configured
non-applicability, not a successful content inspection. Object read failures
and manifest length or digest mismatches are always incomplete coverage.

## Internal Pi classifier

Status: implemented on Linux, audit-only.

The Pi analyzer is authorized to send sensitive staged content to the selected
internal model. Its capabilities remain read-only and transaction-scoped.

File Guardian invokes an absolute executable directly, without a shell or
discovered user customizations. Pi 0.83 uses `--thinking` (not
`--reasoning`), and its JSON mode is an event stream rather than a constrained
classifier response. The runner therefore uses an explicit reviewed extension
and a terminating structured-output tool:

```text
pi --print --no-session --no-builtin-tools --no-extensions
   --no-skills --no-prompt-templates --no-themes --no-context-files
   --no-approve --provider <provider> --model <model> --thinking <level>
   --extension <trusted-file-guardian-extension>
   --tools <exact-file-guardian-tool-list> <fixed-start-message>
```

The executable, model, thinking level, administrator-owned instruction,
structured-output schema, vocabulary, tool grant, selectors, and budgets are
fixed by configuration and incorporated into pipeline identity.

### Read-only tools

The preferred runner exposes only host-controlled operations over assigned
artifact IDs:

- `manifest_list`
- `artifact_metadata`
- `artifact_read`
- `artifact_read_range`
- `artifact_search`
- `prior_observations`

Each operation is schema-validated, bounded, audited, and resolves immutable
objects. Pi receives no write, rename, delete, quarantine, shell, subprocess,
arbitrary-path read, credential, or File Guardian control capability. If a
filesystem view is temporarily required, it is a generated read-only tree of
opaque artifact IDs with enforced confinement.

### Instruction and output

The host-owned instruction defines the classification objective, declares all
artifact content untrusted evidence rather than instructions, enumerates tools
and vocabulary, specifies uncertainty behavior, supplies manifest/candidate
identity, and requires exactly one call to the terminal
`submit_classification` tool. Artifact content never alters the tool grant or
host instruction. Free-form model text and Pi's event stream are not parsed as
the authorization result.

Tree scope is the initial priority because publication decisions often depend
on relationships between files. Artifact scope may follow. For tree scope,
complete coverage means the full eligible manifest and working tools were
available, budgets were not unexpectedly exhausted, no relevant tool operation
failed, and a valid terminal classification covers the requested scope. It does
not require reading every byte. The host access transcript is authoritative
about reads but does not prove reasoning quality.

The strict terminal-tool arguments example is
[`examples/pi-classifier/restricted.json`](examples/pi-classifier/restricted.json).
Only configured classification, confidence, and reason codes are accepted.
Unknown fields, extra prose, unknown IDs, wrong manifest identity, oversized
output, invalid counts, inability to complete, timeout, process failure, or
budget exhaustion make a required analyzer incomplete and produce exit `30`.

The Pi process runs in a required OS sandbox. The Linux backend uses Bubblewrap
and mounts neither live staging nor the invocation object store; artifact bytes
are available only through a bounded File Guardian-owned Unix socket proxy in
a private per-run endpoint directory. There is no unsandboxed fallback, and a
selected Pi analyzer is unsupported on non-Linux platforms.

An administrator prepares and protects the Pi runtime bundle, reviewed
extension, instruction, and isolated agent configuration. The bundle manifest
pins the exact Pi version and every runtime file hash. File Guardian executes
the normalized runtime-relative Node launcher with the normalized Pi CLI
entrypoint directly, so it does not depend on a host `/usr/bin/env node`
shebang. The manifest covers a self-contained Node runtime, dynamic loader and
shared libraries, Pi package/dependencies, and CA/resolver material required by
the approved model transport. File Guardian
pins the configured material in pipeline identity, clears ambient
customization, verifies the Pi/runtime handshake and exact tool grant, and
supervises the complete process group. Startup, idle and wall-clock deadlines;
process, memory and descriptor ceilings; concurrent bounded output draining;
and terminate-then-kill cleanup prevent a failed child from outliving the
authorization.

Bubblewrap starts with user, mount, PID, IPC, UTS and cgroup isolation,
explicitly shares only the host network namespace, disables nested user
namespaces, drops all capabilities, and builds a temporary root. It mounts only
the verified bundle at `/runtime`, reviewed extension at
`/policy/file-guardian-extension.js`, isolated Pi configuration at `/config`,
and the private socket directory at `/run/file-guardian`; `/work`, `/home`, and
`/tmp` are temporary. Verified bundle-local resolver, hosts, name-service, and
CA files are mounted at their conventional `/etc` locations. The host
instruction is supplied through the authenticated proxy, not as an argument or
host-file mount.

The sandbox does not mount host `/lib`, `/usr`, or `/etc`. A runtime bundle
that omits its loader, libraries, trust roots, resolver configuration, or any
declared dependency cannot execute and fails authorization closed.

The private proxy authenticates a run and accepts only versioned,
schema-validated requests with monotonic request identities. It maps opaque
candidate and artifact IDs to immutable objects and enforces configured tool
calls, returned bytes, search matches, prior-observation size, and terminal
output limits. It never accepts host paths. A terminal submission closes
content access for that run.

The reviewed extension obtains the trusted host instruction through a private
authenticated bootstrap proxy operation before the agent starts. That
operation is not model-callable. The exact active model grant remains the seven
tools listed above, including the terminal submission tool. `max_tool_calls`
counts those model-callable operations; the runtime-ready and instruction
bootstrap connections are separate mandatory protocol operations.

After an authenticated tool, protocol, object-read, output, or budget error,
the proxy permanently invalidates the run. A later well-formed terminal call
cannot convert partial or failed analysis into complete coverage.

Bubblewrap confines filesystem and process capabilities, but Pi still needs
network access to the configured internal model transport. This is a shared
model-transport network limitation rather than process-level destination
allowlisting. Deployments must constrain the approved provider through their
network or model gateway; File Guardian does not claim that the Pi sandbox
denies every other destination.

Any runtime-bundle mismatch, platform or sandbox failure, handshake/version/
model/thinking/tool disagreement, proxy or tool error, output overflow, timeout,
budget exhaustion, abnormal process exit, missing terminal call, duplicate
terminal call, unknown field/code/ID, manifest mismatch, or incomplete coverage
is a typed required-analyzer failure and yields exit `30`.

Prompt injection remains a classification-quality risk even with capability
confinement. Rollout begins in audit mode: every accepted classification maps
to `audit`. Enforcement requires a frozen prompt/model/vocabulary, a reviewed
labeled evaluation, acceptance thresholds, and explicit operator approval. A
model's `public` classification never removes or suppresses a deterministic
finding.

### Pi acceptance and privacy matrix

| Case | Required behavior |
| --- | --- |
| Artifact prompt injection asks for a tool, path, or policy change | Content remains untrusted evidence; the fixed grant and host policy cannot change. A valid audit classification may complete, otherwise exit `30`. |
| Model returns unknown fields, codes, IDs, counts, manifest identity, or claims coverage it did not receive | Reject the terminal submission, mark Pi coverage incomplete, and exit `30`. Do not echo the rejected payload. |
| Pi stalls, floods output, crashes, forks, or ignores termination | Apply budgets, terminate the complete process group, drain bounded output, reap it, and exit `30`. |
| Runtime, extension, instruction, or isolated configuration disagrees with its compiled identity | Refuse execution before trusting model output and exit `30`. |
| Concurrent runs attempt to reuse a token, socket, request ID, or candidate ID | Per-run authentication and namespace isolation reject the request without exposing either run's content. |
| Pi reads sensitive immutable content successfully | The approved internal model transport may receive it. Reports, stdout, errors, and routine logs retain only normalized safe codes and counts, never the content, prompt, transcript, tool payload, or transport credential. |

Default tests use a fake runtime and synthetic content and run offline. A live
Pi acceptance test is operator opt-in, must name the approved provider/model,
and should use synthetic sensitive fixtures unless the operator intentionally
supplies a protected fixture. Passing a live test validates integration and the
labeled scenario only; it does not make probabilistic classification a security
boundary.

## Deterministic external analyzers

Status: specified and parse-ready; execution is not implemented yet.

Password, credential, and secret scanners are the next analyzer kind. File
Guardian uses reviewed adapters rather than accepting arbitrary native output:

```text
immutable candidates -> native scanner adapter -> validated delegate protocol
                     -> normalized deterministic findings
```

Adapters receive host-assigned candidates and return bounded, versioned NDJSON.
They must explicitly complete every assignment, map validated locations to
artifact IDs, identify the scanner and ruleset, and omit matched values. They
run without a shell in a required sandbox with read-only candidate access,
network denial, resource ceilings, process-group termination, and concurrent
stdout/stderr draining.

Deterministic findings remain present regardless of a later LLM
classification. A later Pi stage may receive their safe normalized summary as
context, but cannot erase them.

## Policy and actions

Policy resolves only after all required stages complete. Directives have this
precedence:

```text
deny > quarantine > delete > audit
```

Any surviving deny suppresses all mutation across the transaction. Evaluate
mode reports the planned result without mutation. Apply mode centralizes target
selection, identity revalidation, journaling, delete, and invocation-scoped
quarantine. An action never targets a logical archive member or analyzer path.

After any mutation, File Guardian captures the remaining staging tree again and
reruns the complete required pipeline. There is no remediation loop in v1: a
new blocking or remediable verification observation produces `30`.

## Archives and job-scoped quarantine

The invocation workspace is also the future authorization work area. ZIP, TAR,
tar+gzip, and single gzip members will become logical immutable artifacts with
nested provenance and global depth, entry, expanded-byte, compression-ratio,
and time limits. File Guardian will not conventionally extract attacker paths.
A finding inside an archive targets the outer physical staged archive.

Job-scoped quarantine lives within the run workspace and is referenced by an
opaque ID, never an absolute path. Retention is explicit (`never`,
`on_modified`, `on_error`, or `always`) with a TTL and storage ceiling. Durable
administrator quarantine remains a later option.

## Fingerprint indexing remains planned

Exact fingerprints remain a separate later analyzer and administration track:

- SHA-256 over exact raw bytes; renamed identical copies still match.
- Configured source roots with root-relative include/exclude globs.
- Manual `build`, `sync`, `add`, and `inspect` commands.
- Optional per-index daemon schedules; static indexes may be on-demand only.
- Metadata-assisted incremental hashing or explicit full-content rehash.
- Atomic SQLite generations, WAL, one writer, and pinned concurrent readers.
- Optional freshness policy and historical/current-snapshot retention.

Directory modification times may be hints but cannot prove descendants are
unchanged. Absence from an exact index never means positive approval. Modified
copies and excerpts require the still-later similarity/chunk track.

## Configuration v2

Schema v2 is a deliberate break, not a dual-shape migration. Unknown fields are
rejected. IDs must be unique, references must resolve, action authority and
resource ceilings must be valid, and all relevant roots must be disjoint before
a workspace is created.

The strict mature example is
[`examples/active-authorization-v2.toml`](examples/active-authorization-v2.toml).
The generic pipeline, selectors, projections, and Linux Pi runner are
implemented. Pi must be configured audit-only. External-tool definitions parse
and validate, but selecting that unsupported runner fails execution closed with
exit `30`; fields are never reinterpreted or aliased.

Pipeline identity covers ordered stages, execution and prior-observation
settings, selected analyzer configurations, selectors, limits, and compiled
rule material. Profile and policy bindings/directives are covered separately by
policy identity.

## Implementation sequence

### Phase 0: Contract and golden examples

Check in this contract, strict configuration, report goldens, and Pi output
golden. Confirm all exit/outcome and incomplete-coverage cases are unambiguous.

### Phase 1: Core workspace and immutable inspection

Add typed artifacts, manifests, observations, coverage, issues, policies,
actions, and reports; deterministic clock/ID seams; private run workspace;
complete descriptor-anchored capture; all-match built-in analysis; typed scan
failures; and strict separation of discovery from mutation.

Gate: fixed input produces one deterministic complete manifest, no coverage
failure exists only in logs, analyzers never reopen staging, and inspection
does not mutate it.

### Phase 2: Read-only one-shot authorization

Add `authorize`, the strict v2 subset, one built-in pipeline, JSON stdout, and
exits `0`, `20`, and `30`. Reserve `10`. Preserve passive monitoring only
through explicit daemon jobs needed at the v2 cutover.

Gate: an external caller can reliably gate a staged tree and operational
uncertainty cannot produce `0` or `20`.

### Phase 3a: Generic analyzer pipeline

Implemented: compiled ordered stages, serial and bounded-parallel execution,
canonical aggregation, byte-safe immutable artifact selectors, bounded
prior-observation projections, explicit coverage, and the same asynchronous
engine for one-shot and daemon policy scans.

Gate: fixed input and configuration produce identical assignments,
observations, coverage, and aggregate report ordering regardless of parallel
task completion order; every required failure yields `30`.

### Phase 3b: Pi classifier

Implemented on Linux: Pi process lifecycle, Bubblewrap confinement, private
read-only artifact tools, instruction/runtime identity, strict structured
output, normalized classifications, and audit-only policy bindings.

Gate: the approved internal model classifies a staged tree through read-only
artifact capabilities; every required Pi failure yields `30`; audit
classifications cannot change the decision.

### Phase 4: Deterministic scanner adapters

Add the delegate protocol, bounded process I/O, required sandbox, fake adapter,
then selected password and secret scanners. Allow later Pi stages to consume
safe prior findings.

### Phase 5: Authorization-safe actions

Harden existing remove/recover concepts into centralized, journaled delete and
invocation quarantine with target identity revalidation and complete pipeline
verification. Introduce exit `10` only here.

### Phase 6: Recursive archives

Materialize bounded logical archive members in the workspace and expose them to
the same analyzer pipeline. Actions remain on outer physical artifacts.

### Phases 7 and 8: Exact fingerprint indexes

First add manual exact index operation and authorization matching. Then add
incremental sync, generation retention, concurrent SQLite readers, freshness,
and optional per-index daemon schedules.

### Phase 9: Narrow redaction

Support deterministic byte ranges in plain regular files, atomic replacement,
recoverable backup, and full verification. LLM classifications alone cannot
produce edit ranges.

### Phase 10: Similarity fingerprints

Add a separately versioned algorithm/index, explicit thresholds and false-
positive model, benchmark corpus, and report-only rollout before enforcement.

## Cross-cutting acceptance gates

- Tests are deterministic and offline; Pi and native scanner behavior uses fake
  processes by default.
- Live internal-model tests are explicit opt-in and use synthetic sensitive
  fixtures unless an operator intentionally supplies a protected fixture.
- Golden JSON and TOML parse in CI and report invariants are tested.
- Property/fuzz testing covers paths, config, JSON/NDJSON, archive metadata,
  and native scanner records as their phases arrive.
- Failure tests cover partial capture, process crashes, pipe floods, timeouts,
  malformed output, budget exhaustion, action interruption, and verification
  disagreement.
- Privacy tests reject absolute paths, matched secrets, prompts, transcripts,
  raw scanner output, credentials, and unsafe environment values in reports.
- Each feature phase updates documentation and changelog and passes formatting,
  lint, test, and release-build gates.
