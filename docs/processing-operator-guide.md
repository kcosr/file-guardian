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

Use `process path` for an upload directory or ordinary filesystem tree. Its
profile must select the working tree and history `none`. A `.git` directory in
this mode is ordinary payload.

Use `process repo` for a local Git repository. File Guardian freezes Git
metadata separately, materializes the selected working tree into the stage,
and never copies `.git` into the handoff tree. A bare repository is usable only
with a history-only report profile.

Use `process git` for an HTTPS or SSH remote. Authentication is entirely
ambient to the configured Git process. For unattended use, arrange an existing
credential helper, SSH agent/key policy, and known-hosts policy before launch.
File Guardian deliberately has no credential configuration. Git is invoked
noninteractively, so an unavailable credential produces a bounded acquisition
error instead of a prompt.

Profile scope has two independent dimensions:

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

Gitleaks and TruffleHog run against host-materialized immutable views, never a
repository's `.git` database or authentication context. Their network namespace
is empty. Credential verification and updates are disabled. Native JSON is
private adapter input; matched secrets and raw diagnostics never reach reports
or Pi.

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
request with normal host networking. Every model-visible OS tool call executes
in one persistent Bubblewrap sidecar with no network, read-only input/runtime,
and ephemeral writable `/work` and `/tmp`. The model does not receive the host
home, job root, source repository, scanner output, Git credential, or File
Guardian control socket.

Start with advisory mode:

```toml
[processing.profiles.pi_adjudication]
analyzer = "pi-triage"
mode = "advisory"
```

Advisory assessments annotate deterministic findings but cannot clear them or
make a denied tree allowable. Treat this as the default operational mode.

If a well-understood recurring false positive justifies authority, create a
separate profile with `mode = "clear_false_positives"`. Its clearance rule must
name exact analyzer, rule, category, maximum severity, verification state, and
allowed reason code, and it must require at least the configured confidence.
Configure protected categories, verified/error verification states, critical
severity, and hard-block rules as non-clearable. Apply profiles must require a
fresh Pi assertion after actions. Keep the original finding visible even when
the adjudication is applied.

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
an optimistic deny or allow.

Artifact quarantine outlives stage handoff or discard until its own retention
policy expires. Use `artifact inspect` for safe metadata, `artifact recover` to
an absent trusted destination, and `artifact discard` for explicit removal.

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
  cases.

The block profile must require both scanner adapters and bind their documented
synthetic AWS finding to deny. The clean profile uses the same required
pipeline and retains allowed stages. The HEAD, reachable, and all-refs profiles
must differ only where their declared source scopes require it; reachable must
select `refs/heads/main`. Optional Pi profiles must bind the fixture-only
`FILE_GUARDIAN_TEST_PASSWORD` rule: advisory leaves it active, while clearance
may clear only that exact unverified rule at the configured confidence/reason.

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
FG_ACCEPTANCE_PI_CLEARANCE_PROFILE=accept-pi-clearance \
FG_ACCEPTANCE_HTTPS_REMOTE=https://example.invalid/disposable/repo.git \
FG_ACCEPTANCE_SSH_REMOTE=git@example.invalid:disposable/repo.git \
scripts/processing-live-acceptance.sh
```

The remote values must name disposable repositories containing the fixture
history; the harness never pushes, creates, or deletes a remote. Omit them to
remain fully local. Review the script header for exact profile expectations.

The harness verifies process/report exit parity, expected scope outcomes,
privacy canaries, original-source immutability, optional remediation and
handoff, and optional Pi advisory versus narrow-clearance behavior. Live model
output is integration evidence, not a deterministic policy oracle.

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
