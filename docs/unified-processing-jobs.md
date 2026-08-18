# Unified Processing Jobs

Status: proposed implementation contract

Base implementation: `feat/pi-tool-execution-sidecar` at `f3872c3`

Configuration schema: `3`

Processing report schema: `2`

## Purpose

File Guardian SHALL process either a caller directory or an HTTPS/SSH Git
repository through one fail-closed job engine. A job owns the exact staged
candidate content, executes a configured pipeline of built-in
rules, first-party open-source scanner adapters, and optional Pi review,
optionally removes or quarantines whole files from the owned copy, verifies the
result from scratch, and emits one durable machine-readable report.

The same engine serves two primary workflows:

- An upload orchestrator submits a path, receives a retained clean stage on
  exit `0` or `10`, promotes that stage, and disposes of its original ingress
  path itself.
- A user submits a local path or authenticated HTTPS/SSH Git locator before
  sharing code with a public coding-agent provider. File Guardian scans a
  private copy and returns a report identifying what must be reviewed or
  removed.

The job engine does not mutate caller-owned paths and does not publish content.
It returns a sealed stage or opaque stage reference only when the configured
policy and all required coverage allow it. A separate caller decides where the
stage is ultimately moved.

### Product and trust model

File Guardian has one acquisition and inspection workflow with exactly two
source forms. `process path` copies a caller directory exactly into the
job-owned stage. `process git` clones an HTTPS/SSH remote directly into that
stage. Both preserve `.git` when it exists. After a path copy, File Guardian
detects whether the owned stage is a valid Git worktree and, if so, applies the
same configured Git-aware analysis as a remote clone. There is no separate
local-repository command, hidden acquisition repository, or stripped
source-tree projection. Optional Git history is analyzed from the staged
repository itself.

Pi is a trusted semantic scanner. Deterministic scanners deliberately trade
context for speed and may report false positives. Pi receives their findings,
the actual matched evidence, surrounding context, and read-only access to the
complete staged files and selected historical artifacts. A configured
authoritative Pi review may confirm or override a deterministic finding. The
original finding and Pi's assessment both remain in the report.

The sandbox is an accidental-mutation boundary, not a confidentiality or
adversarial-agent boundary. Pi may read password-bearing candidate content and
ordinary host files. The host filesystem and candidate stage are mounted
read-only, while a dedicated scratch directory is writable. Pi uses the normal
administrator-installed runtime and shared libraries; File Guardian does not
construct, copy, inspect, or attest a private runtime closure.

Report privacy is a separate boundary. Reports, logs, and durable public state
do not contain matched passwords or raw file contents even though the trusted
Pi invocation may inspect them.

This contract evolves the existing schema-v2 `authorize PATH` foundation. It
preserves immutable capture, canonical artifacts, the generic ordered pipeline,
prior-observation projections, centralized policy, and the existing Pi host
plus persistent Bubblewrap tool sidecar. It replaces the
caller-owned live transaction with a File Guardian-owned processing job and
implements the previously reserved external-analyzer, action, verification,
and `allow_modified` seams.

There is no compatibility parser for the obsolete command, configuration, or
report shapes.

## Non-goals

The first complete release does not:

- rewrite Git history;
- edit or redact byte ranges inside a file;
- hydrate Git LFS objects or recursively acquire submodules;
- let analyzers choose filesystem paths, actions, outcomes, or dispositions;
- run without deterministic scanners when a profile requires them;
- promise secure erasure when a stage is discarded;
- inspect dangling Git objects, reflogs, or refs outside the frozen configured
  ref set;
- automatically download scanners, Git, Pi, or sandbox dependencies;
- treat a model statement as cryptographic proof that a repository is clean.

Archive expansion and exact fingerprint indexes remain separate later
features. Ordinary binary uploads remain valid artifacts and are not rejected
merely because text analyzers mark them not applicable.

## Core security and correctness invariants

1. Every source is acquired into a freshly and exclusively created private job
   stage. The original source is never scanned-and-mutated in place.
2. Deterministic analyzers inspect immutable captured objects or generated
   read-only views. Pi receives the exact stage read-only, including `.git`,
   while the job lease prevents host mutation during analysis.
3. Required execution, findings, and coverage are independent dimensions.
   Missing tools, malformed output, unsupported versions, timeouts, crashes,
   truncation, or unapproved coverage gaps produce `error`, never an implicit
   clean result.
4. File Guardian freezes the source scope, artifact assignments, configured
   tool/version expectations, rules/config identities, and pipeline identity
   before analysis.
5. File Guardian freezes Git scope and assigns deterministic history artifacts.
   Deterministic scanner adapters do not reinterpret refs; trusted Pi may use
   normal Git commands against the exact staged repository.
6. Analyzers return observations and coverage only. The policy engine resolves
   them. The action executor alone mutates the owned stage.
7. Pi is advisory by default. An explicit authoritative profile permits its
   assessment to clear a deterministic finding routed to Pi adjudication. The
   original finding remains in the report.
8. `allow_modified` requires at least one journaled stage mutation followed by
   a new immutable capture and a complete rerun of every required analyzer on
   the final manifest.
9. A retained handoff is bound to the final manifest and report. Post-seal
   mutation invalidates it.
10. Reports contain no matched secret, raw snippet, native scanner output,
    model prompt/transcript, credential, acquisition URL, absolute source path,
    or private analysis path. Pi's private request and read-only content tools
    may contain the evidence required for semantic review.
11. Cancellation kills and reaps every acquisition, scanner, and Pi child;
    prohibits `allow` and `allow_modified`; records a terminal job state; and
    applies the configured cancellation/error disposition.

Long in-process acquisition, hashing, Git graph parsing, object materialization,
report construction, and cleanup loops perform bounded cooperative cancellation
checks. Blocking workers retain their job/workspace lease and the terminal
report is not emitted until every worker has stopped using stage descriptors.
Dropping an async join receiver never detaches live work.

## Command contract

```text
file-guardian [--config FILE] process
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    path DIRECTORY

file-guardian [--config FILE] process
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    git [--ref REF] REMOTE

file-guardian [--config FILE] stage handoff
    RUN_ID --destination PATH --mode move|copy

file-guardian [--config FILE] stage discard RUN_ID
file-guardian [--config FILE] artifact inspect RUN_ID QUARANTINE_ID
file-guardian [--config FILE] artifact recover
    RUN_ID QUARANTINE_ID --destination PATH
file-guardian [--config FILE] artifact discard RUN_ID QUARANTINE_ID
file-guardian [--config FILE] job inspect RUN_ID
file-guardian [--config FILE] job recover
file-guardian [--config FILE] daemon [--job JOB_ID ...]
```

`process path` accepts exactly one literal directory and does not expand globs.
The directory is copied exactly into a job-owned stage,
including `.git`, tracked modifications, tracked deletions, untracked files,
ignored files, and preserved symlink entries. The source is never removed or
modified. After copying, File Guardian detects Git only from the owned stage.
If it is a valid Git worktree, File Guardian freezes its current HEAD and
configured refs and enables the selected history surface. If a profile requires
history but the stage is not a valid Git worktree, acquisition fails with exit
`30`.

`process git` accepts only:

- `https://host/path` without embedded password or query credentials;
- `ssh://[user@]host/path`; or
- SCP-like `[user@]host:path`.

It rejects `http`, `file`, local path, `ext`, helper, option-looking, malformed,
and unknown transports. The configured absolute Git executable is invoked
directly with an argument vector, never through a shell. The optional ref is a
bounded validated value that cannot become an option. The resolved commit, not
the human ref text, becomes the source identity. The clone is created directly
in the job stage, and `.git` remains part of the exact inspection and handoff
candidate.

Configuration selects the Git surfaces and ref set. `--ref` selects the
materialized HEAD but does not reduce configured history coverage. It must
match the profile's `allowed_checkout_ref_patterns` and resolve to exactly one
frozen advertised/local branch or tag ref; raw object IDs and option-looking
values are rejected. Scope itself is profile-only in schema 3 and has no CLI
override.

The CLI action authority is a lattice: `evaluate` may reduce a profile's
`apply` authority; `apply` can never upgrade an evaluate-only profile.

Clap syntax and help failures use exit `2`. Once a syntactically valid process
shape is recognized, File Guardian generates an in-memory run identity before
loading configuration. Configuration parse, root validation, or job-directory
creation failure therefore prints one schema-2 error report and exits `30`.
Such a report has `persistence.status = "unavailable"`, null phase/stage/policy
identities as appropriate, and cannot claim a durable report. After the job
store is available, operational failure attempts a durable report with
`persistence.status = "durable"`. Only CLI shape/help failures return `2`
without a processing report.

`--request-id` is an optional correlation label of 1–128 ASCII characters. It
must start with a letter or digit; subsequent characters may be letters,
digits, `.`, `_`, `:`, or `-`. It is not a path, credential, authorization
token, or idempotency key; repeated request IDs create distinct runs.

`RUN_ID` selects a job under the caller's operating-system access to the
protected jobs root. It is a lookup identifier, not a bearer capability.
`stage handoff` requires an available, sealed, allowed job and an exclusive job
lock. Immediately before both modes, it descriptor-recaptures the complete live
stage and compares publication path/type/mode/link-target/content semantics to
the final manifest. The job directory remains owner-only and no untrusted
writer has access between that revalidation and the rename/copy commit. It
never overwrites an existing destination:

- `move` requires the same filesystem and atomically renames the stage.
- `copy` copies descriptor-relatively into a private sibling destination,
  recomputes the manifest, compares it with the sealed final manifest, and
  atomically renames the verified temporary destination.

There is no silent fallback from `move` to `copy`. Failure leaves the original
sealed stage available. A successful handoff emits a compact receipt binding
the run ID, final manifest identity, report digest, destination identity, and
handoff mode.

Handoff/recovery destinations must be absolute with an existing parent. File
Guardian opens each parent component without following links, requires the
terminal parent be owned by the service EUID, and rejects group/world-writable
parents. The final basename must be absent. It holds the parent descriptor
through temporary creation, verification, and rename. The same contract applies
to artifact recovery; caller-selected destination contents are outside File
Guardian's authority after the atomic commit.

`stage handoff`, `stage discard`, artifact quarantine operations, `job
inspect`, and `job recover` each emit one strict versioned JSON result plus a newline and use
exit `0` for completed operation, `20` for an inapplicable state such as a
non-available handoff, `30` for operational ambiguity/failure, and `2` for CLI
syntax. Mutating commands are idempotent by persisted operation ID. The caller
never supplies that ID. File Guardian derives it from the command
kind, run/quarantine identity, mode, and descriptor-resolved destination
identity. `job inspect` returns mutable job status separately from the immutable
processing report. `job recover` scans all stale jobs and returns a bounded
per-job result array; fresh/non-stale jobs are reported as untouched.
For handoff, the receipt is that single stdout object. The generated operation
ID is durably recorded before copying/moving; repeating the exact command
returns the identical receipt, while a different destination/mode against an
already handed-off stage returns inapplicable/`20`.

## Outcomes and exits

| Exit | Outcome | Required meaning |
| ---: | --- | --- |
| `0` | `allow` | Acquisition and complete required analysis allow the unchanged stage. |
| `10` | `allow_modified` | At least one action committed; complete fresh verification allows the final stage. |
| `20` | `deny` | Complete trustworthy analysis produced a blocking policy result. |
| `30` | `error` | Acquisition, coverage, analysis, policy, action, verification, report, or disposition is incomplete or untrustworthy. |

Rules:

- A known deny plus any required execution or coverage failure is `error`, not
  `deny`.
- Evaluate mode returns `deny` when allowing the stage would require mutation.
- Apply mode performs at most one remediation pass.
- Any non-allow result or operational failure during verification is `error`;
  the engine does not enter a remediation loop, roll the verified mutation
  back, or expose a handoff. It quarantines the modified job stage.
- A required Pi failure is `error`. An advisory Pi failure is a recorded
  degradation and cannot weaken a deterministic blocker.
- The process prints exactly one compact JSON report plus one newline. Logs and
  diagnostics never enter stdout.

## Job ownership and lifecycle

Each run is created beneath an administrator-controlled jobs root:

```text
jobs/<run-id>/
  lock
  state.json
  heartbeat
  resolution-initial.json        # durable resolved evidence before final checks
  resolution-verification.json   # present only after actions
  decision.json                  # private pre-disposition terminal proposal
  stage/                         # exact copied directory or direct Git clone
  private/
    initial/{manifest,objects}/
    verification/{manifest,objects}/
    analyzer-views/
    scanner-output/
    action-journal/
    artifact-quarantine/
    tmp/
reports/<run-id>.json            # durable, outside disposable stage
quarantine/<run-id>/             # whole-job quarantine
```

Directories and files are owner-only, created exclusively without following
links. Configured jobs, reports, quarantine, configuration, rules, logs, Pi
runtime, and scanner-administrator roots are pairwise disjoint after absolute
and canonical resolution.

Durable execution state, policy outcome, and completion disposition are three
orthogonal fields. An `allow` can be retained or discarded; a `deny` can be
retained, discarded, or quarantined without changing the outcome. Only an
allowed retained job becomes handoff-available.

The durable execution state machine is:

```text
created
  -> acquiring
  -> acquired
  -> baseline_captured
  -> analyzing_initial
  -> resolving_initial
  -> [planning_actions -> applying_actions -> capturing_verification
      -> analyzing_verification -> resolving_verification]
  -> revalidating_final
  -> sealing
  -> preparing_decision
  -> disposing
  -> publishing_report
  -> terminal
```

Terminal state stores:

```text
outcome = allow | allow_modified | deny | error | cancelled
disposition = retained | discarded | quarantined | retained_error
handoff = unavailable | available | handed_off
```

`retained_error` is the fixed safe fallback when configured error quarantine or
discard cannot complete. It stays private, cannot be handed off, and requires
operator recovery. `cancelled` is a durable internal/report reason whose public
processing outcome and exit remain `error`/`30`.

After an action transaction has committed a stage mutation, or recovery cannot
prove that a possibly started mutation left or restored the stage unchanged,
an error/cancelled job overrides its effective disposition to whole-job
`quarantined`. The report and private decision retain the profile's configured
`retain`/`discard` value and separately bind effective `quarantined`; recovery
must execute that effective intent. This is the only configured/effective
disposition mismatch. It never applies to allow/allow-modified/deny, never
weakens configured quarantine, and still falls back to `retained_error` if the
quarantine operation itself cannot complete.

Each transition writes a canonical temporary state file, fsyncs it, renames it,
and fsyncs the parent. Every mutating command holds the job lock. The job stores
a process/boot nonce and heartbeat; recovery does not rely on PID reuse-prone
liveness alone.

Every unchanged allow path reaches `revalidating_final`, descriptor-recaptures
the stage, requires equality with the initial composite manifest, and then
reaches `sealing` before any allowed private decision is prepared. Modified
allow reaches the same states against the verification manifest. Sealing is a
durable state and applies write-blocking physical modes without changing the
stored publication-mode semantics. A deny/error disposition may seal a retained
private stage but can never make it handoff-available.

Before leaving `resolving_initial` or `resolving_verification`, File Guardian
atomically writes and fsyncs the corresponding canonical resolution snapshot.
It binds the phase manifest, source/pipeline/policy identities, complete
coverage, normalized resolutions/adjudications, proposed phase result, and
committed action state. `revalidating_final` and `sealing` are reachable only
after that snapshot is durable.

Recovery obtains the lock on stale jobs and handles every execution state:

- `created` or `acquiring`: record acquisition failure, then apply error
  disposition;
- `acquired` through `resolving_initial`: record error and do not silently
  resume analyzer work;
- `planning_actions` through `resolving_verification`: recover the action
  journal; after any applied mutation the effective outcome is error and the
  mandatory disposition is whole-job quarantine;
- `preparing_decision`: validate the private decision record and resume only
  its recorded disposition;
- `disposing`: locate the run by its immutable job identity in both the jobs
  and quarantine roots, finish or safely classify the idempotent disposition,
  and never run a different one;
- `publishing_report`: reconstruct the one final public report from the private
  decision plus actual disposition, publish it once, and mark terminal;
- terminal retained jobs: preserve until explicit handoff/discard or TTL;
- terminal discarded/handed-off tombstones: garbage-collect safely;
- terminal quarantined/retained-error jobs: preserve until operator action or
the applicable retention rule.

A stale `revalidating_final` or `sealing` job first validates the required
resolution snapshot against state and immutable inputs, then recaptures the
stage. Only a valid allow snapshot plus exact equality may resume sealing and
decision; a missing/corrupt/mismatched snapshot or stage mismatch produces
error and the configured safe error disposition. Recovery never reconstructs
an allow from analyzer files and never trusts mode bits alone as a seal.

Recovery never synthesizes an allowed result from ambiguous state.

The ordering protocol avoids publishing a provisional allow:

1. write and fsync a private canonical `decision.json` containing the proposed
   outcome, final manifest, policy evidence, configured disposition, and a
   complete draft report body without actual disposition;
2. perform and fsync the idempotent disposition;
3. construct the terminal report with the actual outcome/disposition and
   atomically create the public report path exactly once;
4. write the terminal state and only then emit the report to stdout.

The public report path never contains a provisional result and is immutable
after creation. A crash before step 3 is recovered from the private decision.
If final report publication fails, no allowed report or handoff is exposed;
recovery retries publication. The current invocation emits a bounded schema-
valid error report to stdout when possible, while durable state remains
`publishing_report` or `retained_error`. A later handoff receipt never rewrites
the processing report and instead binds its immutable digest.

## Source acquisition

### Local paths

Local acquisition descriptor-copies one literal directory into the private
stage. It:

- rejects a root symlink, regular-file operand, or special-file operand;
- preserves every descendant symlink entry and its target bytes exactly without
  resolving or opening the target;
- rejects special files, mount crossings, unreadable entries, source
  instability, and configured limit overflow;
- copies ordinary source hardlinks as independent stage files rather than
  preserving a link to the source;
- validates metadata before and after each read and re-enumerates directories;
- records a stage manifest after the copy;
- never exposes the absolute source path in the report.

Every symlink adds a typed `symbolic_link` artifact and stage entry. Capture and
handoff manifests bind its logical path, entry type, link-target bytes, and
publication mode; analyzers may inspect the target string as data but no File
Guardian component follows it. Absolute and escaping targets remain exact
staged content and MAY independently produce a path-hygiene finding. A
preserved link never counts as completed regular-file content inspection. The
stage remains semantically a tree with a
link, not a regular file containing the target text.

The source can contain arbitrary bytes. Binary files, archives, core files,
images, and executables are captured subject to global size limits. Text
analyzers may account them as `not_applicable`; byte-oriented fingerprint
analyzers may still inspect their digest. A profile may mark selected source or
configuration paths as required text, in which case binary/undecodable content
is an explicit coverage error.

### Git acquisition and authentication

Git acquisition uses the caller's already-configured credential helper, SSH
agent, known-hosts, CA trust, and explicitly allowlisted authentication
configuration only while the trusted configured Git executable is acquiring
objects. File Guardian manages no Git credentials. Authentication, host-key,
transport, clone, or ref failure is a typed acquisition failure.

Acquisition clears process-control and object-location variables including
`GIT_DIR`, `GIT_WORK_TREE`, `GIT_OBJECT_DIRECTORY`, alternate-object paths,
`GIT_CONFIG_*`, askpass overrides, and arbitrary `GIT_SSH_COMMAND`. It disables
URL rewriting, remote helpers, hooks, filters, replace refs, and repository
program execution, and forces Git's protocol allowlist to `https:ssh`. A
separate reviewed configuration path permits only credential-helper, CA,
proxy, SSH executable/config, and known-hosts inputs required for authentication;
their values are not reported. The effective transport is validated after Git
resolution and must remain HTTPS or SSH.

Acquisition is noninteractive and bounded. File Guardian sets
`GIT_TERMINAL_PROMPT=0`, skips LFS smudge, forbids recursive submodules, disables
hooks, and prevents checkout filters or repository-controlled programs from
executing. It captures bounded diagnostic output, kills and reaps the complete
process group on timeout/cancellation, and recursively redacts diagnostics.

The acquisition environment is distinct from analyzer environments. Scanner
and Pi children never inherit `SSH_AUTH_SOCK`, askpass variables, credential
helper secrets, cloud credentials, tokens, acquisition descriptors, or the
remote URL. Pi continues to receive only its explicitly configured model
credential allowlist.

The configured Git executable is hashed/versioned before acquisition and its
identity is revalidated immediately before and after every invocation. A change
is an acquisition error. Protected Git configuration is likewise opened,
hashed, and revalidated. Scanner tool pinning uses the stronger descriptor-
backed rule described below.

The clone target is the job's `stage/`. File Guardian initializes `.git`,
fetches the frozen selected refs, materializes the selected HEAD with Git
plumbing so hooks, filters, submodules, and LFS cannot execute implicitly, and
retains `.git` for Pi, history review, and final handoff. Before analysis it
removes credential-bearing remote URLs, `FETCH_HEAD`, native diagnostics, and
other acquisition-only authentication data from that staged repository.

### Git surfaces

Repository scope has two independent dimensions:

```toml
[processing.profiles.source_scope]
working_tree = true
history = "head"              # none | head | reachable | all_refs
history_ref_patterns = []
```

`working_tree` must be `true`. History is an optional second dimension; schema
3 does not support a history-only job with no stage.

- `working_tree`: the publication files in the exact stage. `.git` is retained
  as staged repository metadata and is available to Pi/Git tools, but ordinary
  working-tree detector assignments exclude Git administrative internals.
- `head`: the exact tree referenced by the frozen resolved HEAD commit.
- `reachable`: every commit reachable from HEAD plus every advertised/local ref
  matching `history_ref_patterns`.
- `all_refs`: every commit reachable from HEAD plus every frozen branch,
  remote-tracking branch, and tag ref in the supported namespaces. Reflogs,
  stash, notes, replace refs, pseudo-refs, and dangling/unreachable objects
  remain out of scope and are reported as such.

`history_ref_patterns` is a required key in the strict profile shape. It MUST
be an empty array for `none`, `head`, and `all_refs`, and nonempty for
`reachable`. Patterns match the original fully
qualified advertised/local ref names before File Guardian maps them to private
namespaces. Each exact pattern must match exactly one ref; each glob must match
at least one ref. Annotated tags are recorded and peeled to commits; a selected
ref that is missing, ambiguous, non-commit, or changes between freeze and
materialization is an acquisition error.

For a remote, File Guardian first freezes `ls-remote --symref` output, then
fetches exact generated refspecs into private `refs/file-guardian/heads/*` and
`refs/file-guardian/tags/*` namespaces, and verifies the resulting OIDs against
the advertised map. For a local repository it freezes the corresponding local
branch, remote-tracking branch, and tag namespaces through bounded plumbing.
The configured/CLI checkout ref must match
`allowed_checkout_ref_patterns`; it chooses resolved HEAD and is always added
to the history root set. It does not implicitly add unrelated refs.

`reachable` and `all_refs` include the exact HEAD object graph in addition to
the mandatory staged working tree. A `purpose = "report_only"` profile still
uses the same stage and analyzers but cannot retain or hand off that stage.

Before analysis, File Guardian freezes:

- Git version and object format;
- sanitized transport kind and an opaque repository identity;
- resolved HEAD commit;
- selected ref-to-object map;
- shallow, partial-clone, replace-ref, alternates, LFS, and submodule state;
- acquisition limits and options.

Unapproved shallow/partial state, alternates, replace refs, LFS pointers,
submodules, or missing objects are coverage errors. Submodules and LFS may be
supported later as separately acquired bounded sources, never silently
followed.

File Guardian owns history enumeration through bounded Git plumbing. It lists
commit/tree/blob provenance, reads blobs through a batch interface, hashes the
bytes into the existing immutable object store, and emits deterministic
artifacts. Deterministic scanner adapters do not receive `.git`, reclone, run
`git log`, or select their own ref scope. Trusted Pi also receives this frozen
scope and may run ordinary Git commands against the same staged `.git`. This
keeps detector coverage deterministic without hiding repository context from
semantic review.

Git artifacts extend, rather than weaken, the existing source-neutral domain:

- a typed SHA-1/SHA-256 Git object ID;
- a `repository_blob` artifact kind;
- logical raw-byte path segments;
- blob mode and byte length;
- commit/ref provenance and occurrence fanout;
- the internal object-store identity used by analyzer views.

Symlink blobs are represented as typed `symbolic_link` entries with their
link-target bytes and are never followed. Git materialization creates the exact
symlink entry and the stage capture records it without traversal. Gitlinks are explicit
unsupported/submodule coverage. Multiple
paths/commits may reference one immutable blob; the object bytes are stored
once while bounded provenance occurrences remain reportable.

Deleting a working-tree file cannot remediate a HEAD or history finding. A
blocking historical finding remains blocking until a future explicit history
rewrite exists. The staged repository retains `.git`; a clean current worktree
must not be described as clean repository history when required history remains
dirty.

## Immutable capture and assignments

Initial and verification captures use the existing descriptor-anchored
Snapshotter and content-addressed ObjectStore. The acquired stage is the live
root; caller source paths are never reopened after acquisition. Each capture
produces a separate immutable manifest and object namespace.

The publication manifest is stronger than a content list. Each entry binds raw
logical path segments, entry type, regular-file bytes and executable bit, or
symbolic-link target bytes. Other permission bits, ownership, timestamps,
xattrs, ACLs, sparse layout, and platform flags are deliberately normalized and
not publication semantics in schema 3. The stage stores the intended executable
bit separately while sealing changes physical mode bits to prevent writes;
handoff applies the normalized publication mode only inside the destination
transaction before the final comparison. Directory path/existence is part of
the manifest. Special files are never valid.

The compiler freezes the ordered stages, required analyzers, selectors,
content applicability, source surfaces, rules/config digests, executable
identities, and prior-observation limits. The same required set and identities
are used for verification. Configuration that selects history without a
required history-capable analyzer is invalid.

Coverage remains explicit:

```text
eligible, assigned, completed, not_applicable
```

`completed + not_applicable == assigned` is required for complete execution.
Ordinary binary content can be `not_applicable` to text scanners. Missing,
unreadable, corrupt, oversized text, malformed required text, unmaterialized
history, omitted ref, scanner-native skip, or unknown exclusion is incomplete,
not clean.

Analyzer `max_file_bytes` is a required-inspection ceiling, not an implicit
exclusion. An assigned applicable text artifact above it makes that analyzer
incomplete and the job error. An administrator who accepts a coverage reduction
must express it as a visible compiled selector exclusion or a distinct
host-owned applicability rule; it enters pipeline/report identity and the
artifact is outside eligibility or explicitly not-applicable as specified. No
scanner silently converts its own size skip into clean coverage.

For repository jobs, each phase manifest is a composite of a fresh physical
stage snapshot plus the same frozen immutable repository-object/ref snapshot.
History objects may reuse verified bytes from the initial object store, but
assignments, external processes, normalized results, coverage, policy, and Pi
results are recreated during verification. A verification run never drops
history merely because only the working tree changed.

## Pipeline execution

The current ordered serial/bounded-parallel executor remains the only analyzer
engine:

```text
immutable assigned artifacts
  -> built-in deterministic rules
  -> open-source deterministic scanners
  -> normalized/correlated findings
  -> optional Pi triage using prior findings and evidence
  -> complete coverage validation
  -> centralized policy
  -> optional actions
  -> fresh full verification pipeline
```

Later deterministic stages receive host-produced bounded projections. Pi
receives normalized findings plus the bounded matched evidence and immutable
content access needed to evaluate them. Raw scanner process output and analyzer
scratch are not forwarded because they are scanner-specific diagnostics, not
because Pi is untrusted.

## External scanner runtime

### Trusted adapter model

The initial release exposes first-party named adapters rather than arbitrary
administrator shell commands:

```toml
[[analyzers]]
id = "gitleaks"
kind = "gitleaks"
executable = "gitleaks"
version_requirement = ">=8.28,<9"
config_file = "/etc/file-guardian/scanners/gitleaks.toml"
ignore_file = "/etc/file-guardian/scanners/gitleaks.ignore"

[analyzers.execution]
initial = "required"       # required | advisory | disabled
verification = "required"  # required | advisory | disabled

[analyzers.selection]
include = ["**"]
exclude = []
artifact_kinds = ["physical_file", "repository_blob"]

[analyzers.limits]
wall_timeout_secs = 90
max_file_bytes = 10485760
max_output_bytes = 10485760
max_findings = 10000

[[analyzers]]
id = "trufflehog"
kind = "trufflehog"
executable = "trufflehog"
version_requirement = ">=3.90,<4"
credential_verification = "disabled" # disabled is the only v1 value

[analyzers.execution]
initial = "required"
verification = "required"

[analyzers.selection]
include = ["**"]
exclude = []
artifact_kinds = ["physical_file", "repository_blob"]

[analyzers.limits]
wall_timeout_secs = 180
max_file_bytes = 10485760
max_output_bytes = 33554432
max_findings = 10000
```

`credential_verification` controls TruffleHog's native online credential
verification, not File Guardian's post-action verification phase. Schema 3
accepts only `disabled`; the field is explicit to prevent conflating the two.

`kind` is a closed tagged enum. Gitleaks accepts only the fields shown plus the
common selection/applicability/limits; TruffleHog accepts its own closed fields.
Generic `adapter`, `args`, `protocol`, shell command, scanner-controlled Git
scope, and configurable sandbox fields do not exist. Required confinement and
native protocol interpretation are implementation invariants. A potentially
blocking scanner cannot be disabled during verification. Configuration rejects
an artifact kind/source surface the selected adapter does not support.

An executable containing no slash is resolved against the File Guardian
startup `PATH`; a path with a slash must be absolute. File Guardian validates
the configured supported version before use. Executables use their normal host
runtime and shared libraries. Protected scanner configuration remains
administrator-owned and enters the pipeline identity. Absence or version
mismatch is a configuration/runtime error; File Guardian never downloads a
tool or changes PATH implicitly.

Adapter code is trusted File Guardian code. It owns exact arguments, native
exit semantics, structured-output schema validation, path normalization,
redaction, and normalization. Repository content cannot supply scanner config,
ignore files, baselines, plugins, templates, or arguments unless the profile
explicitly references a protected administrator-owned file whose digest enters
the analyzer identity.

There is no administrator-supplied delegate executable or generic public
scanner wire protocol in schema 3. Internally, each Rust adapter implements one
typed `ScannerAdapter` trait and returns `execution`, `coverage`, and normalized
occurrences independently. Adapter-specific JSON/NDJSON is parsed directly from
the private output. The fake scanner used in tests exercises process and parser
state machines but is not an extensibility API.

The generic delegate supervisor provides:

- a generated immutable candidate view, read-only at the OS boundary;
- private output/scratch outside the stage;
- the normal administrator-installed runtime on a read-only host filesystem;
- disabled network on Linux;
- bounded wall time, process group, memory/CPU/file descriptors where
  supported, and stdout/stderr/output sizes;
- cancellation-safe termination and reap;
- strict parsing of bounded scanner output;
- mapping only to host-assigned artifact IDs and validated relative locations.

This accidental-write confinement contract is required, not best effort. In
the first release, external scanner execution is Linux-only and requires
Bubblewrap. Selecting Gitleaks or TruffleHog on macOS or a Linux host without
that boundary is a typed required-analyzer error. macOS remains supported for
built-in-only processing.

Native exit is never interpreted generically. Each adapter independently
reports execution status, findings, and coverage. A required process can exit
zero and still fail if its output or completion accounting is missing,
malformed, truncated, inconsistent, or outside its assignment.

Gitleaks and TruffleHog do not emit one positive completion record per clean
file. Their first-party adapters therefore use a reviewed whole-view coverage
contract: the host preclassifies applicability, materializes exactly the
assigned supported text files, removes untrusted ignore/config control files
from scanner semantics, sets every native ignore/archive/decode/size option,
and treats one supported-version successful complete invocation as completion
of that exact assigned view. The adapter is the trusted attester, just as an
in-process analyzer is trusted to report its loop completed. Any documented or
observed native skip, partial-scan diagnostic, input/open error, scan-error
counter, output disagreement, or unsupported file mode makes coverage
incomplete. Scanner versions for which exhaustive view traversal cannot be
established are unsupported rather than assigned fabricated per-file coverage.

### First-party scanners

The initial supported pair is:

1. **Gitleaks** — default fast deterministic secret scanner. The adapter uses
   filesystem/stream mode over File Guardian's immutable candidates, a
   protected rule configuration, JSON report output, full redaction, no
   repository ignore/config, and a dedicated findings exit distinct from
   execution failure. The reviewed command is equivalent to `gitleaks dir`
   with protected `--config` and `--gitleaks-ignore-path`, `--report-format
   json`, private `--report-path`, `--redact=100`, `--exit-code 42`, no banner/
   color, error-only logging, explicit target-size bounds, and the immutable
   `/input` view. Exit `0` requires an empty valid array; exit `42` requires a
   nonempty valid array; every other exit or disagreement is error.
2. **TruffleHog** — independent second scanner. The default profile uses
   filesystem mode with JSON, `--no-update`, `--no-verification`, and no network
   verification. The reviewed command is equivalent to `trufflehog --json
   --no-update --no-verification --results=unverified --fail
   --fail-on-scan-errors --no-color filesystem /input`. Exit `0` requires zero
   valid result records; exit `183` requires at least one; every other exit,
   scan-error indication, or disagreement is error. Secret-bearing `Raw`,
   `RawV2`, `SecretParts`, and `ExtraData` fields are consumed only inside the
   private parser and dropped.

`detect-secrets` is a later optional adapter for an administrator-owned reviewed
baseline workflow. Its ordinary scan creates a baseline-style result and does
not use a findings exit, so the adapter must parse the result rather than infer
cleanliness from exit zero.

Nosey Parker is not added: its official project declares it retired in favor
of Praetorian Titus. Titus may be added after its stable file/stream output and
version contract are reviewed. File Guardian will not ship a new integration
with a retired scanner.

Scanner-native output may contain the secret itself. It is written only to a
private `0600` temporary output, parsed with limits, recursively redacted, and
removed according to private-workspace retention. The normal report stores a
safe category, scanner/rule/version provenance, validated location, verification
state, and job-local opaque evidence token—not the secret or a reversible
low-entropy hash.

## Finding identity and correlation

File Guardian assigns:

- `occurrence_id`: one analyzer observation with native provenance;
- `finding_id`: one normalized logical finding bound to snapshot, artifact,
  category, rule, safe location, and evidence token;
- `correlation_id`: a bounded group of occurrences that may represent the same
  underlying concern.

Native scanner IDs are provenance only. Correlation never discards an
occurrence. Every blocking occurrence in a group must be independently cleared
before the group stops blocking.

Evidence tokens use HMAC-SHA-256 with a random per-job key shared across the
initial and verification phases. The key is not persisted. This prevents
offline guessing of low-entropy test passwords and intentional cross-job
linkage. Public reports omit raw per-file content digests; internal manifests
retain cryptographic digests for integrity.

The HMAC input is host-derived, not taken from redacted scanner JSON. After an
adapter validates a finding location, File Guardian reads the smallest
canonical evidence window it can prove from the immutable object: the exact
byte range when the reviewed native schema defines it, otherwise the complete
bounded source line range plus analyzer/rule/category domain separation. The
input is `schema || phase-independent source identity || logical provenance ||
canonical evidence-window bytes`; the output is never sent back to the native
scanner. Gitleaks may therefore keep `--redact=100`; File Guardian uses its
validated start/end location to read the immutable bytes itself. TruffleHog raw
secret fields are not needed for the public token and are dropped.

When a scanner cannot provide a provable bounded location, the finding has no
evidence token and is correlated only by artifact/provenance, compatible
category, and overlapping validated location supplied by another occurrence;
absence never weakens blocking. Cross-scanner correlation does not require
equal tokens. Initial-to-final correlation prefers equal tokens under the same
job key and compatible provenance/rule, then records any structural-only match
as uncertain rather than treating it as the same cleared finding.

## Pi triage and attestation

### Authority boundary

Pi is the trusted semantic analyzer. It does not directly mutate files or emit
an operating-system action; the host maps its assessment through the selected
profile so job outcomes and durable actions remain deterministic and auditable.
In authoritative mode, that mapping deliberately permits Pi to override an
incorrect deterministic finding.

Pi receives normalized prior findings, their actual bounded evidence, and
read-only access to the complete immutable stage and selected Git-history
artifacts. Its shell runs with the ordinary host filesystem visible read-only
and a dedicated writable scratch directory. The sandbox prevents accidental
host or stage modification; it does not conceal candidate passwords, host
files, the installed runtime, or shared libraries from Pi. The Pi host process
retains model networking and its configured provider credentials.

Pi phase execution is explicit:

```toml
[analyzers.execution]
initial = "advisory"       # required | advisory | disabled
verification = "disabled" # required | advisory | disabled
```

Required Pi participates in phase completeness and fails the job on any
execution/coverage/protocol failure. Advisory Pi runs after the complete
required pipeline; its failure is recorded in a bounded `degradations` array,
does not create a report `issue`, and cannot change required coverage or a
deterministic resolution. A successful advisory assessment annotates existing
findings. Any profile granting authoritative adjudication requires Pi in the
applicable initial phase, and in verification whenever actions run.
The profile's `pi_adjudication.required_initial` and
`required_after_actions` are validation assertions, not overrides: they must
agree with `analyzers.execution.initial = "required"` and
`verification = "required"` respectively. Contradiction is a configuration
error.

### Triage request

The host creates a canonical bounded request containing:

- schema, run/invocation IDs, phase, manifest identity, and request digest;
- pipeline, policy/adjudication, prompt-template, and prior-projection
  identities;
- resolved working-tree/history surfaces and safe Git provenance;
- complete prior analyzer status/coverage;
- `finding_id`, `correlation_id`, occurrence analyzer/version/rule, category,
  severity, validated logical location, verification state, the actual bounded
  matched evidence, and surrounding context;
- explicit omission/truncation flags;
- on verification, safe action codes and initial-to-final finding correlation.

The private request may contain passwords and snippets because Pi needs that
evidence to judge the scanner. It does not contain unrelated scanner stdout or
stderr, host credentials, acquisition URLs, or environment dumps. Those are
operational diagnostics rather than review evidence.

### Terminal schema

Pi submits exactly one strict terminal object through the authenticated control
tool. The conceptual schema is:

```json
{
  "schema_version": "file-guardian-pi-triage/1",
  "invocation_id": "pii_...",
  "phase": "verification",
  "manifest_identity": "sha256:...",
  "request_identity": "sha256:...",
  "prior_observations_identity": "sha256:...",
  "status": "complete",
  "assessments": [
    {
      "finding_id": "fnd_...",
      "classification": "false_positive",
      "confidence": "high",
      "reason_codes": ["documented_test_fixture"],
      "duplicate_of": null,
      "recommended_action": "none"
    }
  ],
  "stage_attestation": "no_blocking_concerns_observed",
  "coverage": {
    "assigned_artifact_count": 12,
    "completed_artifact_count": 12,
    "not_applicable_artifact_count": 0,
    "assigned_finding_count": 1,
    "assessed_finding_count": 1
  }
}
```

Closed classifications are `confirmed`, `likely_true_positive`,
`likely_false_positive`, `false_positive`, `uncertain`, and
`unable_to_assess`. Only exact `false_positive` clears a routed deterministic
finding. Confidence remains `low|medium|high`; it is audit metadata, not a host
threshold.
Reason codes and recommended actions are closed administrator vocabularies.
Recommended actions are advisory only.

Every assigned finding appears exactly once. Duplicate, missing, unknown,
stale, later-stage, wrong-phase, wrong-manifest, wrong-request, invalid-location,
oversized, or trailing submissions fail the required Pi run. Pi's whole-stage
attestation also lets it block a stage when semantic review finds a concern the
deterministic scanners missed.

The stage attestation vocabulary is
`no_blocking_concerns_observed|blocking_concerns_observed|unable_to_assert`.
In advisory mode it is recorded only. In authoritative mode,
`blocking_concerns_observed` denies the unchanged stage and
`unable_to_assert` makes required Pi analysis incomplete. After an action, any
result other than `no_blocking_concerns_observed` is an error because the
modified stage was not accepted by its trusted semantic scanner.

### Trusted Pi adjudication

Default mode is advisory:

```toml
[processing.profiles.pi_adjudication]
analyzer = "pi-triage"
mode = "advisory"
```

An authoritative profile permits Pi to decide whether deterministic findings
are correct:

```toml
[processing.profiles.pi_adjudication]
analyzer = "pi-triage"
mode = "authoritative"
required_initial = true
required_after_actions = true
```

Authoritative adjudication applies when:

1. the profile explicitly selects `mode = "authoritative"`;
2. the finding is routed through an `adjudicate` policy binding;
3. the finding/request/phase/manifest identities match;
4. Pi assessed every assigned finding and completed its assigned artifact
   review;
5. every required deterministic analyzer completed without gaps; and
6. after a mutation, a fresh deterministic and Pi verification run succeeds on
   the final manifest.

For a routed finding, `false_positive` clears the deterministic blocker.
`confirmed`, `likely_true_positive`, `likely_false_positive`, `uncertain`, and
`unable_to_assess` do not clear it. Confidence and reason codes remain useful
audit information but do not override the trusted classification. There are no
fixed non-clearable categories, severity gates, private-key exceptions, or
secondary per-rule clearance allowlists. The ordinary `adjudicate` binding is
the administrator's explicit scope grant.

An unchanged false-positive-only job needs one complete required initial Pi
assessment, then final descriptor revalidation and sealing of the identical
stage; it does not run an artificial verification phase. It may return
`allow`/`0`. `required_after_actions` applies only when an action committed.
Profiles that want a second unmodified
attestation MAY select a separate required final-review stage explicitly; that
is a normal second initial-phase stage, not verification.

The report retains the deterministic finding and adds the Pi assessment plus
an adjudication state `not_requested|advisory|applied|rejected` and a closed
application/rejection reason. Pi never makes a finding disappear.

## Policy and action planning

Detection remains separate from policy. A profile maps every normalized
finding/classification to `audit`, `deny`, `delete`, or `quarantine`; Pi
adjudication is a separately tagged resolution path and not an overloaded
ordinary classification binding.

`default_unbound_observation` is the total-policy fallback with closed values
`audit|deny|error`. Every observation that matches no explicit binding is
resolved through it, so no normalized finding is actually unmapped. `error`
means policy is intentionally incomplete for that observation and yields job
error; `delete` and `quarantine` cannot be defaults because mutation authority
must be granted by an exact binding.

The planner evaluates the complete initial result before mutation:

- any surviving unconditional `deny` suppresses all mutations;
- only physical files in the owned stage are actionable;
- historical and other nonphysical findings are not actionable;
- multiple findings on one file coalesce deterministically;
- `quarantine` dominates `delete`, which dominates `audit`;
- no analyzer-supplied path is used as an operating-system path.

Evaluate mode records the would-be resolution and returns `deny` when mutation
is required. Apply mode proceeds only after complete required initial coverage.

## Action execution and journal

The action executor uses descriptor-relative, no-follow operations beneath the
held stage root. Immediately before acting it revalidates regular-file type,
logical path containment, file identity, length, and digest against the frozen
subject. Replacement, symlink, hardlink, or content mismatch aborts the action
and produces `error` without touching an outside target.

The journal records canonical planned, started, committed, fsynced, rolled-back,
and failed states with precondition/result identities. It is length-framed,
checksum-protected, append-only within the job, flushed before and after each
mutation, and never contains removed bytes.

- Delete renames the file into private transaction trash; physical unlink is
  deferred until the final decision is prepared.
- Artifact quarantine renames it into a collision-safe private quarantine
  location and records an opaque ID.
- A cross-filesystem quarantine fallback copies to an exclusive temporary file,
  fsyncs and verifies the digest, atomically renames the copy, and only then
  removes the source. Failure leaves the source intact.

Before fresh verification begins, an action failure may reverse applied moves
only when it can prove restoration of the exact initial manifest. Once all
actions are fsynced and the fresh verification manifest is durably recorded,
every recapture, analyzer, Pi, policy, verification, cleanup, or final non-allow
result produces `error`/`30` and mandatory effective whole-job quarantine,
regardless of the profile's configured error disposition. From that boundary
File Guardian preserves the modified stage and does not roll it back or retry
remediation. Any earlier rollback failure or ambiguous journal state is also
quarantined. Recovery never replays uncertain actions automatically.

Successful delete transaction trash is descriptor-deleted and fsynced before
the private decision record can propose `allow_modified`; cleanup failure
becomes error and whole-job quarantine. Successful artifact quarantine is moved
to a dedicated protected artifact-quarantine store before stage disposition.
It is retained under an explicit artifact-quarantine TTL/byte reservation and
remains addressable by `(run_id, quarantine_id)` after a stage handoff. The
`artifact inspect`, `recover`, and `discard` commands never reinsert it into a
sealed stage; recovery writes to an absent caller-selected destination and
verifies the recorded identity. Artifact quarantine capacity is reserved before
actions, and an unavailable reservation prevents mutation.

## Verification

After at least one committed mutation, File Guardian:

1. captures a new immutable final stage manifest;
2. recompiles/verifies the same frozen required pipeline identity;
3. reruns every required deterministic analyzer against the final assignments;
4. rebuilds normalized findings and correlations;
5. runs a fresh required Pi invocation when configured;
6. resolves final policy;
7. verifies the live stage still matches the final manifest;
8. seals the stage read-only before reporting it available.

The post-mutation result table is closed:

| Verification result after a committed action | Outcome | Stage handling |
| --- | --- | --- |
| Complete final allow | `allow_modified` / `10` | Commit action transaction; apply configured allow-modified disposition. |
| Deterministic deny, residual/new delete/quarantine, uncleared correlation, failed Pi attestation, incomplete coverage, or operational failure | `error` / `30` | Never hand off; effective whole-job quarantine. |

A mutated job never returns `deny`/`20`, because the one-pass transaction has
already changed the candidate and did not establish an allowed final result.
The report records the initial manifest, any attempted verification manifest,
the current proven manifest when available, action states, and the mandatory
effective disposition.

Initial analyzer results, Pi assessments, and coverage are not reused as final
evidence after a mutation. `allow_modified` is valid only when at least one
action is committed and fsynced, the manifest changed, verification is complete,
final policy allows, required Pi attestation succeeds, and the report and
disposition are durable.

## Disposition and retention

Each profile configures a completion disposition for `allow`,
`allow_modified`, `deny`, `error`, and cancellation:

```toml
[processing.profiles.completion]
allow = "retain"
allow_modified = "retain"
deny = "discard"
error = "quarantine"
cancelled = "quarantine"
```

Closed dispositions are:

- `retain`: keep a sealed stage available for handoff until its explicit TTL;
- `discard`: remove the stage beneath the validated job root during the
  decision protocol; this is not secure erasure;
- `quarantine`: atomically move the whole job/stage under the private quarantine
  root and expose only an opaque ID.

`retain` always uses the profile/jobs retention TTL; there is no overlapping
`retain_until` alias. Jobs and whole-job quarantine roots MUST be on the same
filesystem so quarantine is one journaled atomic rename. Artifact quarantine
has its own root/capacity/TTL.

Reports persist independently. Retention has explicit TTL and aggregate byte
ceilings. Capacity is reserved before acquisition/actions based on configured
worst-case/job quotas and adjusted monotonically as actual use becomes known.
No unexpired available or quarantined job is evicted to admit another. Failed
admission produces an error before source acquisition; failed terminal
quarantine reservation leaves a private `retained_error` job in the jobs root.
Cleanup is descriptor-rooted or proves that the target is one validated run ID
directly beneath the configured root. A disposition failure is visible and
prevents an allowed result; File Guardian applies the fixed safe fallback once
and never loops.

## Processing report schema 2

The strict canonical shape is:

```json
{
  "schema_version": "2",
  "run_id": "run_...",
  "request_id": null,
  "outcome": "allow",
  "exit_code": 0,
  "modified": false,
  "started_at": "...",
  "finished_at": "...",
  "persistence": {"status": "durable", "report_digest": "sha256:..."},
  "source": {},
  "acquisition": {},
  "stage": {},
  "policy": {},
  "phases": {"initial": {}, "verification": null},
  "pi_invocations": [],
  "adjudications": [],
  "actions": [],
  "issues": [],
  "degradations": [],
  "statistics": {},
  "omissions": {"details_omitted": false, "reason": null}
}
```

Every listed key is present; optional values are explicit JSON `null`, not
omitted. Nested structs reject unknown fields and tagged variants reject unknown
kinds.

`persistence.status` is `durable|unavailable`; `report_digest` is null for
unavailable. Allow, allow-modified, and deny require durable persistence. The
digest is computed over the canonical report with `report_digest = null`, then
inserted, avoiding self-reference.

`source` is exactly one variant:

- path: `{kind:"path", repository:null}` for an ordinary directory copy, or
  the same shape with detected
  `{repository_id,resolved_head,history,frozen_refs}`;
- remote Git: `{kind:"git", transport:"https|ssh", repository_id,
  resolved_head, working_tree, history, frozen_refs:[...]}`.

Repository IDs are HMAC-SHA-256 tokens under the random job correlation key,
not raw locator hashes. Frozen ref rows contain a bounded safe ref token,
object ID, and peeled commit ID; unsafe/raw ref bytes use the same segment-safe
encoding as paths. They never contain the locator or username.

`acquisition` contains `status: complete|failed`, implementation/version
identity, start/end/duration, frozen source identity when known, and safe issue
codes. No-manifest acquisition failure has `phases.initial = null`, an
unavailable stage, outcome error, and one acquisition issue.

`stage` contains `reference` (the run ID only for a retained stage, otherwise
null), `configured_disposition`, `effective_disposition`, `handoff_status`,
`sealed`, `initial_manifest_identity`, `final_manifest_identity`,
`current_manifest_identity`, and expiry/quarantine opaque IDs where applicable.
These identities bind only the publication-stage tree and its publication-mode
semantics. They do not include Git history. Every successfully acquired job has
a stage; report-only purpose changes handoff authority, not acquisition shape.
Outcome and disposition remain independent.

Each non-null phase contains exactly:

```text
phase, manifest_identity, source_scope_identity, pipeline_identity,
artifacts[], analyzer_runs[], coverage[], occurrences[], findings[],
correlations[], resolutions[], statistics
```

`phase.manifest_identity` binds the complete immutable analysis snapshot: the
working-tree catalog when selected plus every selected frozen Git history
surface. It is deliberately independent of the publication-stage identities.
For `working_tree + history` it therefore differs from the stage identity.

Artifact rows contain opaque IDs, kind, raw-byte segment-encoded logical path,
byte length, publication type/mode, and safe Git provenance; no raw content
digest. Analyzer rows contain adapter/analyzer ID, basename, supported version,
rules/config identity, execution status, and coverage, but never the canonical
absolute executable path. Occurrences retain exact
analyzer/rule provenance. Findings and correlations retain every contributing
occurrence and job-local evidence token. Resolutions cite the exact policy or
adjudication binding and closed directive/reason.

`pi_invocations` contains safe phase, configured/resolved model identity,
prompt/tool/protocol identities, execution status, coverage, attestation,
normalized output digest, and timestamps. `adjudications` contains finding ID,
assessment, `not_requested|advisory|applied|rejected`, and a closed
application/rejection reason. The corresponding resolution row cites the exact
authorizing `adjudicate` policy binding. Neither contains model prose or
provider request IDs.

`actions` contains action ID, kind, initial subject/finding/binding IDs, planned
and terminal journal state, and opaque artifact-quarantine ID. It never contains
an operating-system path. `issues` is reserved for outcome-affecting typed
failures. `degradations` records bounded optional/advisory failures and may be
nonempty on allow/deny without changing required completeness.

Required invariant table:

| Outcome | Initial phase | Verification | Actions | Issues | Stage |
| --- | --- | --- | --- | --- | --- |
| `allow` | present and required-complete | null | empty | empty | unchanged final identity; actual disposition succeeded |
| `allow_modified` | present and required-complete | present and required-complete/final allow | at least one committed | empty | changed, sealed final identity; actual disposition succeeded |
| `deny` | present and required-complete | null | none committed | empty | unchanged; no handoff |
| `error` | null or safely known partial/complete | null or safely known partial | any safe journal state | at least one unless report-publication recovery is the sole failure | no handoff |

No post-mutation job can report `deny`; it reports `error`. Only
allow/allow-modified plus effective retained disposition produce
`handoff_status = available`. Discarded/quarantined outcomes never expose a
stage reference. The process report is immutable; later handoff/discard status
and receipts are returned by `job inspect` and auxiliary command schemas.

The report records:

- source kind without absolute local path or raw Git locator;
- safe transport kind, opaque repository identity, resolved HEAD, selected
  scope, and frozen ref/OID set;
- acquisition status, bounded duration, Git identity, and typed issues;
- opaque stage reference, state/disposition, initial/final manifest identities,
  seal state, and availability;
- scanner name, supported version, rules/config identity, execution status,
  and coverage;
- original occurrences/findings and correlations;
- Pi invocation identity, safe assessments, attestation, and adjudication gates;
- planned/applied action codes and opaque quarantine IDs;
- terminal disposition and handoff eligibility.

Only an available retained stage may expose a trusted-caller handoff reference.
The normal report does not expose internal object, analyzer-view, scanner-output,
Pi scratch, proxy, socket, token, acquisition repository, or quarantine paths.

Public artifact records use opaque IDs, logical segment paths, kind, byte
length, and provenance. They do not expose raw per-file content SHA-256 values,
which can enable cross-run correlation or guessing of low-entropy files.
Protected internal manifests retain those digests.

Reports never contain matched values, snippets, scanner stdout/stderr, Git
diagnostics, remote URL, URL userinfo/query, source absolute path, environment,
credential, model prompt/transcript/prose, chain of thought, or raw tool output.
Report construction and serialization are recursively checked with privacy
canaries. `processing.jobs.max_report_bytes`, per-array count ceilings, maximum
path/ref bytes, and maximum normalized finding/action counts are validated
against the acquisition/analyzer maxima before admission. Successful and deny
reports never truncate required evidence. If actual safe evidence cannot fit,
the job becomes error and emits a bounded error report with aggregate counts
and `omissions.details_omitted = true`; an omission can never coexist with an
allowed or deny outcome. Report publication follows the private-decision/
disposition/final-publication protocol above. A report-write failure prevents
`allow` and `allow_modified`.

## Configuration schema 3

Schema `3` is strict and rejects every schema-2 processing shape rather than
parsing both. Illustrative configuration:

```toml
schema_version = "3"

[processing]
default_profile = "upload"

[processing.jobs]
root = "/var/lib/file-guardian/jobs"
reports_root = "/var/lib/file-guardian/reports"
quarantine_root = "/var/lib/file-guardian/quarantine"
artifact_quarantine_root = "/var/lib/file-guardian/artifact-quarantine"
stale_after_secs = 900
max_report_bytes = 67108864

[processing.jobs.capture]
max_entries = 200000
max_files = 100000
max_file_bytes = 1073741824
max_total_bytes = 10737418240
max_depth = 64

[processing.jobs.retention]
available_ttl_secs = 86400
available_max_bytes = 107374182400
quarantine_ttl_secs = 2592000
quarantine_max_bytes = 536870912000
artifact_quarantine_ttl_secs = 2592000
artifact_quarantine_max_bytes = 53687091200

[processing.acquisition]
git_executable = "/usr/bin/git"
git_timeout_secs = 600
max_stdout_bytes = 1048576
max_stderr_bytes = 1048576
max_refs = 10000
max_commits = 1000000
max_unique_blobs = 1000000
max_provenance_occurrences = 5000000
max_git_bytes = 10737418240

[[processing.profiles]]
id = "upload"
pipeline = "publication-review"
action_mode = "apply"
purpose = "handoff" # handoff | report_only
default_unbound_observation = "deny"

[processing.profiles.source_scope]
working_tree = true
history = "none"
history_ref_patterns = []

[processing.profiles.git]
allowed_checkout_ref_patterns = ["refs/heads/*", "refs/tags/*"]
submodules = "reject"
lfs = "reject_pointer"

[processing.profiles.completion]
allow = "retain"
allow_modified = "retain"
deny = "discard"
error = "quarantine"
cancelled = "quarantine"
```

`git.delivery` does not exist in schema 3: every handoff candidate is the exact
stage. A copied repository and a remote clone both retain sanitized `.git`;
history scope controls required analysis rather than changing the delivered
tree.

Analyzer and pipeline definitions retain the current ordered stage model,
selectors, prior projection, content applicability, and Pi sandbox contract.
External analyzers switch from generic parse-ready executables to
closed first-party adapter kinds. Policy bindings become a strict tagged shape
for ordinary directive resolution versus Pi adjudication.

All analyzer/version expectations, Git scope, ref set, Git acquisition options,
protected configs, Pi model/prompt/vocabulary, policy bindings, and
action/disposition authority enter the appropriate source, pipeline, or policy
identity.

Strict validation covers the complete matrix of source kind, purpose, history
mode, ref patterns, checkout ref, adapter scope, Pi phase execution, action
authority, and completion disposition. Every profile requires a staged working
tree; report-only profiles prohibit available/retain handoff; reachable
requires matching history patterns; other modes forbid them; and every selected
history surface has at least one required capable analyzer. Applying a
history-requiring profile to a path source succeeds only when the exact copied
stage is a valid Git worktree; otherwise acquisition fails with exit `30`.

## Daemon behavior

An explicit daemon job submits a `ProcessingRequest` to the same service. It
does not retain the old live-path authorization semantics. Scheduled local-path
jobs copy their target into an owned stage; scheduled Git jobs acquire the
remote. Daemon startup validates every selected job/profile/analyzer and fails
closed rather than silently disabling a missing required scanner.

Daemon schema is a strict tagged source request:

```toml
[[daemon.jobs]]
id = "incoming-upload"
profile = "upload"
schedule = "0 */5 * * * *"
run_on_start = false
overlap = "reject" # reject | queue_one

[daemon.jobs.source]
kind = "path" # path | git
path = "/srv/incoming/batch"
```

The `path` variant may auto-detect Git after exact staging; the `git` variant
permits `remote` plus optional `reference`. Fields belonging to another variant
are rejected.
Startup compiles every job/profile and preflights every required tool. Runs of
the same job follow `overlap`: `reject` records a bounded daemon scheduling
event and starts no processing run; `queue_one` retains at most one pending run
and coalesces further ticks. Each started run acquires a fresh owned stage.

Without `--job`, daemon starts every enabled configured job. One or more
`--job` values select exactly those unique enabled IDs; unknown, disabled, or
duplicate IDs are CLI/configuration errors and no daemon loop starts.
`run_on_start` schedules one immediate run before the first cron tick using the
same overlap rule. Acceptance covers startup preflight failure, exact selection,
run-on-start, scheduled ticks under a fake clock, both overlap modes,
cancellation, and per-run report/disposition behavior.

Each completed daemon run writes exactly one newline-terminated schema-2
processing report to stdout in completion order. A report whose
`persistence.status` is `durable` is also persisted byte-for-byte under
`reports_root` by run ID; a run that fails before the job store is available
emits only an `unavailable` stdout report. Logs use stderr. If the daemon cannot
write a completed run's report, it exits `30` rather than silently losing the
result stream.

## Implementation phases and commit gates

### Phase 0 — reviewed contract

Deliver this specification, update its correspondence after independent
subagent review, and run the Claude Fable 5 Keel specification loop until it
reports clean.

Commit: `Specify unified processing jobs and repository review`

### Phase 1 — processing domain, strict config, and report

- Add source, source-scope, Git provenance, job/state, disposition, finding,
  correlation, Pi-assessment, adjudication, and action domain types.
- Replace the public CLI/config/report contract without aliases.
- Add report schema-2 invariants and golden allow/allow-modified/deny/error
  documents.
- Keep existing authorization behavior internally reachable through the new
  job service while subsequent phases land; do not expose a dual public parser.

Commit: `Add processing job contracts and source provenance`

### Phase 2 — durable job store and local/Git acquisition

- Implement job layout, locks, atomic state, heartbeat, recovery, and private
  analysis workspaces.
- Implement descriptor-safe local copy and source immutability tests.
- Implement supervised ambient-auth HTTPS/SSH Git acquisition and Git plumbing
  materialization/history enumeration.
- Extend immutable artifacts and analyzer views for Git blob provenance.

Commit: `Acquire local and Git sources into owned stages`

### Phase 3 — common external scanner runtime

- Replace `Unsupported(External)` with the common first-party scanner
  supervisor and closed adapter trait.
- Add read-only/networkless execution, strict structured completion, process
  bounds, cancellation, bounded scanner-output parsing, and report redaction.
- Add a reusable Rust fake-scanner test support binary covering process and
  protocol failure matrices.

Commit: `Run confined deterministic scanner delegates`

### Phase 4 — Gitleaks and TruffleHog adapters

- Implement PATH discovery, supported-version validation, protected configuration,
  exact commands, native exit semantics, parsers, normalization, and coverage.
- Add checked-in File Guardian and scanner templates.
- Add offline native-output fixtures and opt-in live scripts.

Commit: `Add Gitleaks and TruffleHog scanner adapters`

### Phase 5 — Pi finding triage

- Add stable occurrence/finding/correlation IDs and the private prior-finding
  DTO with bounded evidence.
- Replace the Pi classifier terminal role with strict triage/attestation.
- Implement advisory and explicit authoritative adjudication.
- Preserve the existing Pi host and persistent Bubblewrap tool-sidecar
  architecture while using the normal read-only host runtime.

Commit: `Let Pi assess deterministic findings safely`

### Phase 6 — centralized actions and verification

- Implement deterministic action planning, identity preconditions, durable
  journal, delete-to-trash, artifact quarantine, rollback, and recovery.
- Recapture the final stage and rerun the complete frozen required pipeline.
- Enable `allow_modified` only with all specified invariants.

Commit: `Apply journaled remediation and verify final stages`

### Phase 7 — disposition, handoff, and recovery

- Implement retain/discard/whole-job quarantine/TTL and storage ceilings.
- Atomically seal reports and stages.
- Implement explicit verified move/copy handoff, discard, inspect, and recover
  commands.

Commit: `Finalize stage disposition and verified handoff`

### Phase 8 — operator templates and live acceptance

- Update README, requirements, implementation contract, examples, and release
  packaging.
- Add upload, local repository, HTTPS, SSH, working-tree, HEAD, reachable/all
  refs, scanner, Pi advisory/authoritative, action, and disposition templates.
- Create deterministic local Git repositories and exercise the release binary.
- Run opt-in live Gitleaks/TruffleHog and Pi acceptance with synthetic values.

Commit: `Document and exercise complete processing workflows`

### Phase 9 — iterative code review and release gates

After each major implementation milestone, commit and run the relevant local
gates. At the end, run the Claude Fable 5 Keel iterative code review over the
complete branch, incorporate every actionable correctness/security/test/docs
finding, commit each review repair, signal the same review run, and continue
until clean.

Final gates:

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --doc --all-features
cargo build --release --all-features
git diff --check
```

Linux runs all Bubblewrap and child-supervision tests. macOS ARM64 compiles and
runs all non-Linux job, acquisition, parsing, policy, report, and action tests;
selecting Linux-only Pi/sandbox behavior fails closed with a typed issue.

## Acceptance test matrix

### Source and Git

- Local directory, non-UTF-8 names, empty tree, binary/core file, every
  size/depth/count bound, source mutation during copy, unreadable directory,
  symlink, hardlink, FIFO/device, mount crossing, and source/jobs overlap.
- HTTPS, `ssh://`, and SCP-like acquisition using a fake Git command fixture;
  exact argv/env, no shell, noninteractive auth failure, timeout, descendant
  kill/reap, output flood, URL redaction, malicious ref, and prohibited
  transport.
- Real offline local Git fixture with fixed author, committer, timestamps, and
  commits: clean HEAD; dirty tracked/untracked secret; secret deleted from HEAD
  but present in parent; secret only on another branch/tag; duplicate blob;
  merge; detached HEAD; non-UTF-8 path; symlink; gitlink; LFS pointer; malicious
  attributes/filter; shallow/partial state.
- `working_tree`, `head`, `reachable`, and `all_refs` produce distinct expected
  artifact/provenance sets. A history finding cannot be cleared by deleting the
  current file.
- Local `process path` over a Git worktree proves `.git`, dirty tracked,
  deleted, untracked, and ignored content are copied exactly while HEAD and
  configured history surfaces remain distinguishable.
- Validation matrix covers every history mode with empty/nonempty exact/glob
  patterns, zero/multiple matches, checkout ref allowed/forbidden, annotated
  tags, symbolic HEAD, advertised-ref movement, and remote-to-private namespace
  mapping.
- Every profile without working-tree coverage is rejected at compile time;
  report-only purpose cannot produce a handoff reference.

### External scanners

- Required tool absent, wrong version/digest, clean result, findings result,
  malformed/truncated JSON, exit/output disagreement, unknown/duplicate
  artifact, invalid path/range, native skip, timeout, crash, signal, child leak,
  stage mutation attempt, stdout/stderr flood, secret-bearing diagnostic, and
  cancellation.
- Gitleaks and TruffleHog normalize the same synthetic credential into separate
  occurrences and one safe correlation without exposing its value.
- Binary not-applicable coverage remains complete; an unapproved scanner skip
  does not.
- Assigned valid text one byte over each adapter's `max_file_bytes` produces
  incomplete required coverage/error; a separately configured explicit glob
  exclusion is visible in identity/report and is never mislabeled completed.

### Pi

- Strict parser rejects duplicate/foreign/stale/later-stage IDs, wrong digests,
  missing findings, invalid confidence/reasons, duplicate cycle, oversized
  output, and trailing submission.
- Advisory Pi cannot clear a fake password. An explicit authoritative profile
  clears a routed deterministic finding when trusted Pi classifies it
  `false_positive`; the original finding remains visible.
- The authoritative matrix covers ordinary passwords, private keys, verified
  credentials, and high-severity findings without fixed host-side exceptions.
  Incomplete deterministic scanning, an incomplete Pi run, and any assessment
  other than exact `false_positive` do not clear a finding.
- After action, stale initial Pi output is rejected and a fresh final manifest
  assessment/attestation is required.
- Advisory Pi timeout/malformed output can coexist with allow only through one
  valid degradation row, complete required coverage, and no Pi-dependent
  override; the same failure is error when Pi is required.
- Initial attestation is advisory in advisory mode. In authoritative mode,
  no-blocking permits policy evaluation, blocking denies the unchanged stage,
  and unable-to-assert is incomplete required analysis. Post-action
  nonaccepted codes follow the mandatory error/quarantine table.
- Configuration requires the authoritative Pi analyzer in the initial phase
  and again after actions; advisory mode does not gain override authority.

### Actions, disposition, and handoff

- Multiple findings coalesce; deny suppresses mutation; quarantine dominates
  delete; history artifacts are non-actionable.
- Replace a target with content, symlink, or hardlink between plan/action;
  action aborts and no outside path changes.
- Fault injection before/after every journal/fsync/mutation/rollback/capture/
  verification/report/disposition boundary.
- Verification catches residual and newly introduced findings. Exit `10` is
  impossible without a changed final manifest and complete fresh coverage.
- Every outcome/disposition combination, TTL boundary, storage pressure,
  concurrent handoff/discard, same-FS move, verified copy, existing destination,
  interrupted copy, post-seal mutation, cancellation, and crash recovery.
- Crash at private decision creation, disposition rename/removal, final public
  report creation, terminal state, and receipt publication; no public
  provisional allow and recovery publishes at most one immutable report.
- Recovery from stale final revalidation/sealing resumes only with the exact
  fsynced valid allow resolution snapshot and equal recapture; missing,
  truncated, corrupt, wrong-manifest/pipeline/policy/action, or non-allow
  snapshots produce error and never synthesize an allowed decision.
- Artifact quarantine across retain, handoff, stage discard, TTL, capacity
  pressure, recovery-to-new-destination, explicit discard, and crash.
- Golden/round-trip tests for handoff, stage discard, artifact inspect/recover/
  discard, job inspect, and job recover receipts/errors and idempotence.

### Privacy

- Canary credentials in remote userinfo/query, environment, Git stderr,
  scanner JSON/stderr, source path, Pi prompt, sidecar tool output, and action
  target never appear in the public report/stdout/logs.
- A low-entropy fake password cannot be recovered by comparing a plain digest
  in the report; job-local evidence tokens do not correlate across jobs.
- Retained stages expose none of the private immutable objects, analyzer views,
  raw scanner outputs, Pi scratch, proxy state, acquisition credentials, or
  artifact quarantine. A staged repository intentionally retains its own
  sanitized `.git` metadata.

### Live acceptance

The default Rust suite is deterministic and offline. Separate operator-gated
scripts MAY use explicitly installed PATH tools and configured Pi credentials;
they never download or update tools themselves.

The live fixture creates a disposable local Git repository containing only
synthetic non-credentials:

- a clean source file;
- a documented example password expected to be a false positive;
- a realistic synthetic credential expected to remain blocking;
- a credential in an older commit removed at HEAD;
- a credential reachable only from another selected branch/tag.

The release binary is exercised against local path and local test Git plumbing,
then optional authenticated disposable HTTPS and SSH remotes. The acceptance
asserts:

- built-ins plus real Gitleaks and TruffleHog produce normalized findings;
- default advisory Pi leaves the documented example blocked;
- an explicit authoritative profile lets Pi adjudicate both fixtures, preserving
  each original finding and applying Pi's assessment to the outcome;
- HEAD and reachable/all-ref scopes differ as specified;
- authenticated smart-HTTPS and SSH-agent acquisition both retain the exact
  staged clone, including a usable `.git`, through verified handoff;
- delete/quarantine followed by a full rescan can yield `allow_modified`;
- reports contain no synthetic values, credentials, URLs, or private paths;
- every child, sidecar, workspace, and stage follows its configured terminal
  lifecycle.

Live model output is evidence about integration, not a deterministic policy
test. Fake Pi protocol fixtures remain the CI authority for all safety gates.

## Completion criteria

The work is complete when:

1. Local paths and authenticated HTTPS/SSH Git repositories enter the same
   ProcessingJob engine without mutating their source.
2. Working-tree, HEAD, reachable, and all-ref scope choices are source-owned,
   frozen, reported, and demonstrated by deterministic repositories.
3. Built-ins, Gitleaks, TruffleHog, and optional Pi run through immutable
   assignments with complete explicit coverage and actual review evidence.
4. Authoritative Pi false-positive adjudication preserves original evidence
   and cannot override incomplete deterministic or Pi analysis.
5. Authorized whole-file delete/quarantine is journaled, identity-checked, and
   followed by a complete fresh pipeline.
6. All four exits and every configured disposition satisfy schema-2 report and
   handoff invariants.
7. Offline, live scanner, live Pi, cancellation, recovery, privacy, Linux
   release, and macOS non-Pi gates pass.
8. Major milestones are committed and the final Claude Fable 5 Keel iterative
   code review reports clean after all accepted findings are incorporated.
