# File Guardian Requirements

## Product purpose

File Guardian evaluates one exact, job-owned filesystem stage before that stage
is handed to another system. Its narrow purpose is to find passwords,
credentials, and other configured disclosure-policy violations, combine
deterministic scanners with trusted Pi semantic review, apply explicitly
authorized whole-file remediation, and publish one fail-closed result.

The normative detailed contract is
[`docs/unified-processing-jobs.md`](docs/unified-processing-jobs.md). The
operator workflow is
[`docs/processing-operator-guide.md`](docs/processing-operator-guide.md).

## One workflow and two source forms

The public processing interface has exactly two source forms:

```text
file-guardian [--config FILE] process [COMMON OPTIONS] path DIRECTORY
file-guardian [--config FILE] process [COMMON OPTIONS]
    git [--ref REF] REMOTE
```

- `path` descriptor-copies one literal directory into a newly created,
  job-owned stage. It never edits or removes the caller's directory.
- `git` clones one HTTPS, `ssh://`, or SCP-like SSH remote directly into the
  job-owned stage using ambient noninteractive Git authentication.
- There is no separate local-repository source form and no hidden source-tree
  projection. A copied directory containing a valid Git worktree is detected
  after acquisition and reviewed as Git.
- `.git`, dirty tracked files, tracked deletions, untracked files, ignored
  files, executable modes, and symlink entries remain part of the exact staged
  content. Symlinks are preserved as entries and never followed during capture.
- A clone's `.git` directory stays in the same stage Pi inspects and the caller
  may later receive. File Guardian does not keep a second clone as the
  authoritative inspection source.

Inputs using local/file/helper Git transports, credential-bearing or
query-bearing HTTPS URLs, malformed or option-looking operands, unsupported
submodules, hydrated LFS content, shallow/partial repositories, or ref movement
fail closed. Git is invoked directly, never through a shell. Acquisition
credentials and agent sockets are not passed to analyzers.

## Source and history scope

A profile selects independently:

- whether the staged working tree is scanned; and
- Git history `none`, `head`, `reachable`, or `all_refs`.

Handoff-capable profiles always scan the working tree. A history-requiring path
profile errors if the copied stage is not a valid repository. File Guardian
freezes selected refs and object IDs before analysis. Deterministic history
scanners receive host-selected immutable blob assignments rather than choosing
their own clone or ref coverage. Pi receives the actual read-only stage and may
use normal Git commands against its `.git` metadata.

## Analyzer pipeline

Profiles compile an ordered pipeline containing:

- built-in filename and content rules;
- configured, `PATH`-discovered Gitleaks and TruffleHog adapters; and
- optional Pi triage.

Every required analyzer reports complete assigned coverage. A missing binary,
unsupported version, timeout, crash, malformed native result, truncated result,
or incomplete required assignment is an error, never a clean scan. Native
scanner output and matched values remain private pipeline input and do not
enter public reports.

External scanners run against immutable host-materialized assignments with
their configured scanner policy. File Guardian owns Git enumeration and
provenance. Scanners cannot reclone, reinterpret ref scope, update themselves,
or contact verification services.

## Trusted Pi triage

Pi is a trusted semantic scanner, not an adversary. It receives:

- normalized deterministic findings and correlation identities;
- the actual bounded matched evidence and surrounding canonical window;
- the exact read-only job stage, including `.git` when present;
- selected artifact and Git-history provenance; and
- the closed policy vocabulary needed to assess each finding.

Pi may read passwords and other sensitive staged content. Keeping evidence or
ordinary staged files secret from Pi is not a product goal. Pi never directly
edits the stage or chooses an operating-system mutation.

The default Pi mode is advisory. An explicitly authoritative profile may clear
a deterministic finding when Pi returns `false_positive` for that exact
snapshot-bound finding and all required coverage is complete. The original
finding, Pi assessment, matched adjudication rule, and effective policy result
all remain in the report. A confirmed, uncertain, missing, stale, or malformed
assessment does not clear the finding.

Pi runs through the configured administrator-installed CLI and normal host
runtime. File Guardian does not construct, hash, inspect, or attest a private
runtime closure and does not perform ELF dependency analysis or require static
binaries. Bubblewrap exists to prevent mistaken host/stage edits and contain
runaway commands:

- the exact stage and ordinary runtime/tool directories are read-only;
- a dedicated scratch directory is writable;
- Pi retains provider networking and only its configured provider credential;
- model-requested shell tools run in a nested networkless view of the same
  stage and scratch directory; and
- timeout, cancellation, and normal completion terminate descendants.

## Policy and remediation

Policy bindings may audit, deny, request Pi adjudication, delete a whole regular
file, or move a whole regular file to artifact quarantine. Only File Guardian's
central action executor mutates the owned stage. Analyzer paths and commands
are never executed as actions.

`evaluate` never mutates. `apply` may not exceed profile authority. A surviving
deny suppresses mutation. Duplicate actions coalesce deterministically and
quarantine dominates delete for the same file.

The action transaction is journaled and revalidates the exact planned file
identity immediately before each rename. After at least one action:

1. File Guardian captures a fresh final stage;
2. it reruns the complete required pipeline, including required Pi;
3. it resolves policy again against only the fresh results; and
4. it produces `allow_modified` only if that final result allows the stage.

If the second pipeline run fails technically or its final policy does not
allow, the job returns `error`/exit `30`. It exposes no handoff, does not run a
third automatic pass, does not roll back after fresh verification has begun,
and forces whole-job quarantine of the modified stage and action evidence. A
caller-owned path source remains unchanged.

## Outcomes and reports

One valid processing command emits exactly one compact report plus a newline on
stdout. The report's exit code equals the process status:

| Exit | Outcome | Required meaning |
| ---: | --- | --- |
| `0` | `allow` | Complete required analysis allows an unchanged stage. |
| `10` | `allow_modified` | At least one action committed and a complete fresh pipeline allows the final stage. |
| `20` | `deny` | Complete trustworthy analysis produced a blocking policy result before mutation. |
| `30` | `error` | Acquisition, required analysis, policy, action, verification, report publication, or disposition is incomplete or failed after mutation. |

Reports retain safe source/Git provenance, analyzer versions and coverage,
findings, correlations, Pi assessments, adjudications, actions, stage manifest
identities, disposition, and handoff eligibility. They never contain matched
bytes, evidence windows, content snippets, raw scanner/model output, prompts,
credentials, source paths, Git locators, or private workspace paths.

## Stage lifecycle

Jobs durably separate policy outcome from disposition. A profile configures
retain, discard, or whole-job quarantine per outcome. Any ambiguous or failed
post-mutation transaction overrides retain/discard to whole-job quarantine.

Only a retained, sealed `allow` or `allow_modified` stage is available for
handoff. Handoff revalidates the sealed manifest and either performs an atomic
same-filesystem move or a verified copy to an absent destination; it never
overwrites or silently changes mode. Reports survive stage discard and
quarantine. Stale-job recovery reconciles durable state, action journals,
reports, dispositions, and handoff receipts without manufacturing an allow.

## Acceptance requirements

Deterministic offline tests must prove:

- path and remote Git sources enter the same engine;
- local Git auto-detection preserves `.git`, dirty, untracked, and ignored
  content;
- working-tree, HEAD, reachable, and all-ref scopes differ as configured;
- built-in, Gitleaks, and TruffleHog findings normalize with complete coverage;
- Pi receives actual evidence and the exact staged/Git context;
- authoritative Pi can clear an incorrect deterministic finding while both are
  reported;
- shell tools cannot edit the stage or host, can write scratch, and have no
  network or acquisition credentials;
- delete/quarantine changes only the owned stage;
- successful remediation runs the full pipeline twice;
- failed second-pass verification returns exit `30`, forces whole-job
  quarantine, preserves the modified stage, and leaves the source unchanged;
- every outcome/disposition/handoff invariant round-trips through the strict
  report schema; and
- reports and logs pass privacy canaries containing fake secrets, credentials,
  paths, URLs, and raw native output.

Opt-in live acceptance uses preinstalled Git, Bubblewrap, Gitleaks,
TruffleHog, and the configured Pi model. It never downloads tools or relies on
real credentials or production repositories.

Before a milestone is committed, run `cargo fmt`, strict `cargo clippy`, the
full deterministic `cargo test` suite, Node/Pi harnesses, and
`cargo build --release`. Review feedback is a proposal: incorporate findings
that support these requirements, explain conflicts to the reviewer, and do not
silently redesign the product around adversarial-Pi assumptions.
