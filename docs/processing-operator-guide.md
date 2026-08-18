# Processing jobs operator guide

This guide turns File Guardian's schema-3 processing contract into a safe
deployment and caller workflow. The
[unified processing specification](unified-processing-jobs.md) remains
normative when this overview omits a detail.

## Deployment checklist

Run File Guardian as the account that owns its private state. The following
must be absolute, normalized, administrator-controlled paths:

- jobs, reports, whole-job quarantine, and artifact-quarantine roots;
- built-in rule files and Gitleaks configuration/ignore files;
- the Git executable;
- the Bubblewrap executable, Pi runtime, trusted extension, instruction,
  sidecar runner, and isolated agent directory when Pi is enabled.

Jobs and whole-job quarantine must share a filesystem so terminal quarantine
is an atomic rename. Keep all state roots mode `0700`. Keep scanner policy and
Pi runtime material outside source trees and job roots. Validate retention and
capacity reservations against the configured maximum job size before service
startup.

File Guardian resolves a configured scanner basename from the startup `PATH`,
opens and identity-pins it, checks the supported version, and uses that opened
identity for the job. A staged executable cannot replace it. The service never
downloads, installs, updates, or authenticates a scanner.

Before enabling a profile, verify:

```bash
command -v bwrap
command -v gitleaks
command -v trufflehog
git --version
gitleaks version
trufflehog --version
```

Use the exact version ranges supported by the first-party adapters and pin
your image/package versions more narrowly when possible. A missing or changed
required executable fails processing closed.

## Choose a source and scope

Use `process path` for an upload directory, ordinary filesystem tree, or local
Git worktree. File Guardian copies the exact directory—including `.git`,
untracked files, and ignored files—into the job-owned stage. It then detects
whether that owned copy is a valid Git worktree. If it is, the configured
HEAD/history review runs against that same staged repository; if the profile
requires history and no repository is detected, acquisition fails.

Use `process git` for an HTTPS or SSH remote. File Guardian clones directly
into the owned stage and retains `.git`; there is no hidden second repository
or stripped source-tree projection. Authentication is entirely ambient to the
configured Git process. For unattended use, arrange an existing credential
helper, SSH agent/key policy, and known-hosts policy before launch. File
Guardian deliberately has no credential configuration. Git is invoked
noninteractively, so an unavailable credential produces a bounded acquisition
error instead of a prompt.

Every profile scans the staged working tree. History is an optional additional
dimension:

| Setting | Reviewed material |
| --- | --- |
| `working_tree = true`, `history = "none"` | Only the acquired publication tree. |
| `history = "head"` | Blobs reachable from the exact resolved HEAD tree. |
| `history = "reachable"` | Commits/blobs reachable from the configured matching frozen refs. |
| `history = "all_refs"` | Commits/blobs reachable from every accepted frozen ref. |

`history_ref_patterns` is valid only with `reachable`. `--ref` chooses the
materialized checkout; it never reduces history. A secret removed at HEAD can
still block reachable history, and a history finding cannot be remediated by
deleting a current working-tree file.

Suggested profile split:

- `upload`: handoff purpose, working tree only, apply authority, retain
  allow/allow-modified, discard deny, quarantine error/cancellation;
- `repository-head`: report only, working tree plus HEAD, evaluate;
- `repository-reachable`: report only, selected branches/tags, evaluate;
- `repository-all-refs`: report only, all accepted refs, evaluate.

The checked-in [schema-3 example](examples/processing-v3.toml) demonstrates the
core upload and repository-review forms. Create separate profiles instead of
adding a CLI scope override, so policy identity always covers scope.

## Scanners and built-in rules

Put deterministic analyzers before Pi. A typical pipeline is:

1. built-in filename/content policy;
2. Gitleaks and TruffleHog in a bounded-parallel stage;
3. Pi triage with `prior_observations = "findings_summary"`.

Gitleaks and TruffleHog run against host-materialized immutable assignments
derived from the staged working tree and configured history. Their network
namespace is empty. Credential verification and updates are disabled. Native
JSON remains private adapter input and never enters reports. File Guardian does
pass each normalized finding's actual bounded evidence to Pi, because semantic
triage cannot judge a match it is forbidden to see.

Use the reviewed [scanner templates](examples/scanners/README.md). Treat native
scanner exit/output disagreement, malformed or truncated JSON, an unknown
path, an unsupported native skip, timeout, or incomplete candidate coverage as
an analyzer error. Do not turn required scanner failure into a clean result.

Built-in rules should detect reusable facts. Policy bindings decide whether a
fact means audit, deny, delete, or quarantine for a profile. Paths listed under
`required_text_include` must be valid bounded text; binary/NUL files can be
ordinary not-applicable inputs only when policy does not require text there.
Large core files and other binaries remain bounded acquisition artifacts and
are never implicitly fed to a model.

## Pi triage

Pi is optional and Linux-only. Its parent process performs the approved model
request with normal host networking. The configured Pi executable runs with
the exact stage mounted read-only at `/input`, normal installed runtime/tool
directories mounted read-only, and isolated writable agent state and scratch.
Every model-visible shell command uses the same read-only stage and a
networkless persistent sidecar. Pi is trusted to inspect candidate content,
including `.git` and the actual matched evidence. Git acquisition credentials,
unrelated environment values, and File Guardian control capabilities are not
passed to command tools.

The checked-in [schema-3 example](examples/processing-v3.toml) includes the
complete strict `pi_classifier` analyzer shape: installed Pi and Bubblewrap
versions, trusted instruction/extension/sidecar paths, isolated agent state,
one explicitly mapped provider credential, closed triage vocabulary, phase
execution, artifact selection, and every enforced resource limit. Replace its
illustrative runtime paths, version, provider/model, and credential mapping with
the administrator-installed values; do not add generic analyzer arguments. If
the deployment does not use Pi, remove the `semantic-triage` pipeline stage,
both profile `pi_adjudication` blocks, and the `pi-triage` analyzer as one
closed configuration change.

Start with advisory mode:

```toml
[processing.profiles.pi_adjudication]
analyzer = "pi-triage"
mode = "advisory"
```

Advisory assessments annotate deterministic findings but cannot clear them or
make a denied tree allowable. Treat this as the default operational mode.

If Pi should decide whether routed deterministic findings are correct, create a
separate profile with `mode = "authoritative"` and route the intended findings
through ordinary `adjudicate` policy bindings. An exact `false_positive`
assessment clears that blocker; confidence and reason codes remain audit
metadata. There are no host-defined non-clearable secret classes. Apply
profiles require a fresh authoritative Pi review after actions. Keep the
original finding visible even when the adjudication is applied.

Provider secrets enter only through explicit
`FILE_GUARDIAN_PI_CREDENTIAL_*` mappings. Never put them in TOML, command
arguments, the test fixture, or the live-acceptance environment file. The
acceptance harness inherits credentials from the operator's already prepared
environment only when Pi cases are explicitly enabled.

## Remediation and verification

`evaluate` never changes the owned stage. It returns deny when allowing would
require remediation. `apply` permits only the actions granted by both the
profile and policy binding.

Remediation is whole-file only:

- `delete` moves the file to private job trash before final cleanup;
- `quarantine` moves it to durable artifact quarantine under an opaque ID;
- multiple findings on one file coalesce;
- quarantine dominates delete;
- any deny on the subject suppresses mutation;
- symlinks, shared hardlinks, special files, and nonphysical Git-history blobs
  are not valid targets.

Immediately before mutation, File Guardian verifies the file identity frozen
by the action plan. It journals and fsyncs each transition. After actions, it
recaptures the complete final stage and reruns the frozen required pipeline.
Only a changed manifest with complete clean verification can produce exit `10`.
A residual/new finding or any verification uncertainty produces `error`, never
an optimistic deny or allow. Once the fresh verification pass has begun, File
Guardian does not roll the successful stage actions back: it keeps the modified
stage private, applies effective whole-job quarantine, exposes no handoff, and
returns exit `30`. A caller-owned path source is still untouched.

Artifact quarantine outlives stage handoff or discard until its own retention
policy expires. Use `artifact inspect` for safe metadata, `artifact recover` to
an absent trusted destination, and `artifact discard` for explicit removal.

Capacity is reserved before acquisition using `capture.max_total_bytes` for
each terminal pool the selected profile can reach. Make each applicable pool
at least that large; larger ceilings allow multiple outstanding stages. A
capacity rejection happens before File Guardian copies or clones the source and
returns an unavailable error report. It never evicts an unexpired result to
make room.

Every `process` admission and `job recover` invocation performs retention
maintenance. It discards expired retained stages, whole-job quarantines, and
artifact quarantines, but leaves the corresponding immutable report in
`reports_root`. A reservation belonging to interrupted work remains charged
until that work is recovered or its absent job is proven stale.

## Parse reports fail closed

For every process invocation:

1. capture stdout separately from stderr;
2. require exactly one newline-terminated JSON value;
3. reject unknown/missing fields through a strict schema-2 decoder;
4. require `exit_code` to equal the actual process status;
5. require durable persistence for allow, allow-modified, and deny;
6. require complete initial coverage, and complete verification after actions;
7. accept a stage only when outcome is allow/allow-modified and its handoff
   status is `available`;
8. reject an allowed report containing `issues`, omitted details, or an
   inconsistent stage identity.

Do not authorize using `request_id`; it is only a bounded correlation label.
Do not find stages by filesystem search. Use the report's `run_id` and the
administrative command contract.

Reports intentionally preserve findings without values. Investigate using the
logical path, analyzer/rule identity, safe location, occurrence/correlation ID,
and job-local evidence token. Use the original private source or retained stage
under your existing access controls when human inspection is required.

## Disposition and handoff

Outcome and disposition are separate. A profile chooses `retain`, `discard`,
or whole-job `quarantine` for each outcome. Only retained, sealed allowed stages
are available for handoff. Report-only profiles cannot retain a stage.

For a retained result:

```bash
file-guardian --config /etc/file-guardian/config.toml \
  stage handoff RUN_ID --destination /srv/approved/JOB --mode move
```

Choose `move` when the destination shares the filesystem; choose `copy` when it
does not. Copy is verified before atomic publication. Neither overwrites.
Exact command retries are idempotent; changing destination or mode after a
completed handoff is inapplicable.

The destination parent must already exist, be trusted, and not be group/world
writable. The final destination must be absent. After successful handoff the
destination is caller-owned state and outside File Guardian's authority.

## Daemon use

Daemon jobs submit the same processing request as the CLI. They do not inspect
live trees in place. Every tick creates a new owned stage. Startup validates
selected profiles and preflights required tools before any loop begins.

```bash
file-guardian --config /etc/file-guardian/config.toml daemon
file-guardian --config /etc/file-guardian/config.toml daemon --job incoming-upload
```

Use `overlap = "reject"` to skip an overlapping tick or `queue_one` to retain
at most one pending run. The application that owns an upload inbox should still
coordinate completed writes and decide when to remove its source; File Guardian
does not infer that application lifecycle.

For each completed run, daemon writes one newline-terminated schema-2
processing report to stdout in completion order. Durable reports are persisted
byte-for-byte under `reports_root` by run ID; a run that fails before the job
store is available emits only an `unavailable` stdout report. Logs use stderr.
Failure to write a completed report terminates daemon with exit `30`.

## Live acceptance

The default Rust suite is deterministic, offline, and authoritative for safety
invariants. The live harness validates the release binary against installed
tool versions and, optionally, a configured Pi provider. It creates a disposable
fixture containing only documented/test-only values, uses no production repo,
and never downloads anything.

Prerequisites:

- release binary built from the commit under review;
- `git` and `jq`;
- a schema-3 acceptance configuration whose roots point to a disposable private
  directory and whose profile names match the selected cases;
- installed Gitleaks/TruffleHog on `PATH` for scanner cases;
- an already configured isolated Pi runtime/credential environment for Pi
  cases. This is the normal installed Pi runtime, not a copied runtime bundle.

The block profile must require both scanner adapters and bind their documented
synthetic AWS finding to deny. The clean profile uses the same required
pipeline and retains allowed stages. The HEAD, reachable, and all-refs profiles
must differ only where their declared source scopes require it; reachable must
select `refs/heads/main`. Optional Pi profiles must bind the fixture-only
`FILE_GUARDIAN_TEST_PASSWORD` rule: advisory leaves it active, while the
authoritative profile may clear the exact routed finding after inspecting its
actual evidence and staged context.

Fixture generation itself can be checked without a File Guardian configuration
or any scanner/model invocation:

```bash
scripts/processing-live-acceptance.sh --fixtures-only
```

This mode retains the generated root and prints its location for inspection.
Remove it when review is complete. Set an absent absolute
`FG_ACCEPTANCE_ROOT` to choose that location explicitly.

Run the default local path and Git-scope cases:

```bash
FG_ACCEPTANCE_BINARY=target/release/file-guardian \
FG_ACCEPTANCE_CONFIG=/absolute/path/acceptance.toml \
FG_ACCEPTANCE_CLEAN_PROFILE=accept-clean \
FG_ACCEPTANCE_BLOCK_PROFILE=accept-block \
FG_ACCEPTANCE_HEAD_PROFILE=accept-head \
FG_ACCEPTANCE_REACHABLE_PROFILE=accept-reachable \
FG_ACCEPTANCE_ALL_REFS_PROFILE=accept-all-refs \
scripts/processing-live-acceptance.sh
```

The same variable set is available as a comment-only, credential-free
[environment template](examples/processing-live-acceptance.env). Export or
source reviewed local values; do not add provider or Git credentials to it.

Optional cases are enabled only when their profile variable is set:

```bash
FG_ACCEPTANCE_REMEDIATE_PROFILE=accept-remediate \
FG_ACCEPTANCE_PI_ADVISORY_PROFILE=accept-pi-advisory \
FG_ACCEPTANCE_PI_AUTHORITATIVE_PROFILE=accept-pi-authoritative \
FG_ACCEPTANCE_HTTPS_REMOTE=https://example.invalid/disposable/repo.git \
FG_ACCEPTANCE_SSH_REMOTE=git@example.invalid:disposable/repo.git \
scripts/processing-live-acceptance.sh
```

The remote values must name disposable repositories containing the fixture
history; the harness never pushes, creates, or deletes a remote. Omit them to
remain fully local. Review the script header for exact profile expectations.

The harness verifies process/report exit parity, expected scope outcomes,
privacy canaries, original-source immutability, optional remediation and
handoff, and optional Pi advisory versus authoritative behavior. Live model
output is integration evidence, not a deterministic policy oracle.

To exercise real ambient authentication without using an external service,
run the separate transport harness. It requires Docker and a suitable image
already present locally; it never pulls an image or reaches the external
network. The image needs Git, Python 3, and OpenSSH server. Put the configured
Gitleaks and TruffleHog executables on the harness process's `PATH`.

```bash
PATH=/absolute/scanner/bin:"$PATH" \
FG_TRANSPORT_ACCEPTANCE_BINARY=target/release/file-guardian \
FG_TRANSPORT_ACCEPTANCE_CONFIG=/absolute/path/acceptance.toml \
FG_TRANSPORT_ACCEPTANCE_PROFILE=accept-reachable \
FG_TRANSPORT_ACCEPTANCE_RETAIN_PROFILE=accept-clean \
FG_TRANSPORT_ACCEPTANCE_IMAGE=locally-installed-git-test-image \
scripts/processing-git-transport-acceptance.sh
```

The harness creates a disposable two-commit repository, private CA, HTTP Basic
credential helper, OpenSSH server, strict known-hosts file, and one-use key in
a disposable `ssh-agent`. For both HTTPS and SSH it proves that reachable
history blocks the deleted synthetic credential, then processes the clean HEAD
under a retained profile and hands off a usable two-commit clone whose `.git`
directory is intact. Reports and stderr are checked for the remote locator,
synthetic credential, and transport password. Set
`FG_TRANSPORT_ACCEPTANCE_KEEP=1` only when retaining synthetic diagnostics for
review.

## Troubleshooting

- Exit `2`: command shape failed before a job existed; inspect stderr.
- Exit `30` with `configuration_failure`: validate schema version, absolute
  protected paths, unique IDs, profile/source matrix, and tool requirements.
- Acquisition error: check source readability, limits, Git transport, frozen
  ref policy, noninteractive ambient auth, submodule/LFS policy, and repository
  shallow/partial/alternates/replace-ref restrictions.
- Analyzer error: check installed version, startup `PATH`, Bubblewrap support,
  protected policy files, timeout/output ceilings, and native parse/exit
  agreement. Do not suppress a required analyzer.
- Pi error: check exact runtime manifest, Bubblewrap/Pi versions, isolated agent
  permissions, credential mapping, proxy/sidecar lifecycle, and terminal schema.
- Handoff inapplicable: confirm the immutable report allowed a retained stage,
  the stage is still available, the destination is absent, and the selected
  mode matches filesystem topology.
- Stale work: run `job inspect RUN_ID`, then `job recover`. Recovery is
  fail-closed and may quarantine or retain an error rather than guess.
