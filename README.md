# File Guardian

File Guardian copies a file tree or Git repository into a private, owned stage,
runs a policy pipeline over that copy, and emits one machine-readable decision.
It is intended to answer a narrow operational question before source is handed
to a public coding-agent provider or promoted from an upload staging area:
does this exact acquired tree satisfy the configured disclosure policy?

The source is never edited. When a profile permits remediation, File Guardian
may delete or quarantine whole files only inside its owned stage, then reruns
the complete required pipeline before it can return `allow_modified`.

## Capabilities

- A caller directory copied with `process path` and an authenticated HTTPS/SSH
  clone created with `process git` enter the same durable processing-job
  engine. A copied directory containing `.git` is detected after acquisition
  and receives the configured Git-aware review.
- Git review scope is policy-controlled: working tree plus no history, `head`,
  `reachable`, or `all_refs`. Selected refs and object IDs are frozen before
  analysis.
- Built-in filename/content rules, Gitleaks, and TruffleHog produce normalized,
  correlated findings with explicit coverage.
- Optional Pi triage receives normalized findings, their actual bounded
  evidence, and read-only access to the complete staged/history review surface.
  It is advisory by default; an authoritative profile may override an incorrect
  deterministic finding routed to Pi adjudication.
- Tools use the administrator-installed host runtime and `PATH` inside a
  read-only Bubblewrap filesystem with writable scratch. File Guardian never
  builds a private runtime closure or downloads or updates scanners.
- Durable jobs support retained-stage handoff, whole-job quarantine, artifact
  quarantine, discard, inspection, and stale-job recovery.
- Reports contain normalized evidence and opaque identities, never matched
  bytes, snippets, scanner output, model transcripts, credentials, source
  absolute paths, or raw Git locators.

File Guardian is a policy gate, not a filesystem access-control boundary. Its
jobs, reports, quarantine roots, scanner policy, and Pi runtime must remain
private and administrator-controlled.

## Install

Download the archive for your platform from
[GitHub Releases](https://github.com/kcosr/file-guardian/releases). Supported
release platforms are `linux-x86_64` and `macos-arm64`; Linux is required for
Bubblewrap-backed external scanners and Pi.

```bash
RELEASE_ROOT=/path/to/file-guardian-VERSION-PLATFORM

sudo install -m 0755 "$RELEASE_ROOT/bin/file-guardian" /usr/local/bin/file-guardian
sudo install -d -m 0700 /var/lib/file-guardian/jobs
sudo install -d -m 0700 /var/lib/file-guardian/reports
sudo install -d -m 0700 /var/lib/file-guardian/quarantine
sudo install -d -m 0700 /var/lib/file-guardian/artifact-quarantine
sudo install -d -m 0755 /etc/file-guardian/scanners
```

Install version-pinned Gitleaks and TruffleHog binaries through the host's
package or image-management process. Put them on the service's startup `PATH`.
Do not allow a repository to supply either executable or scanner policy.

Start with the checked-in
[schema-3 example](docs/examples/processing-v3.toml) and
[scanner policy templates](docs/examples/scanners/README.md). Replace every
illustrative absolute path and version requirement with reviewed deployment
values. Configuration precedence is `--config`, then
`FILE_GUARDIAN_CONFIG`, then `/etc/file-guardian/config.toml`.

## Process a source

```text
file-guardian [--config FILE] process
    [--profile PROFILE_ID]
    [--request-id ID]
    [--action-mode evaluate|apply]
    path DIRECTORY

file-guardian [--config FILE] process [COMMON OPTIONS]
    git [--ref REF] REMOTE
```

Examples:

```bash
# Upload/tree review. The caller-owned source remains untouched.
file-guardian --config /etc/file-guardian/config.toml \
  process --profile upload --request-id upload-4821 path \
  /srv/uploader/private-stage/upload-4821

# Local repository: copy the exact directory, then detect and review `.git`.
file-guardian --config /etc/file-guardian/config.toml \
  process --profile repository-review path /srv/repos/application

# Ambient Git authentication is used; File Guardian stores no Git credential.
file-guardian --config /etc/file-guardian/config.toml \
  process --profile repository-review git --ref refs/heads/main \
  git@example.com:organization/application.git
```

`process path` copies the exact directory, including `.git` and untracked or
ignored files. File Guardian then detects Git from that owned copy; a profile
requiring history fails acquisition if the copied stage is not a valid Git
worktree. `process git` accepts HTTPS, `ssh://`, and SCP-like SSH locators only
and clones directly into the job stage, retaining `.git` as part of the exact
inspection and handoff candidate. It invokes the configured absolute Git
executable without a shell and relies on ambient noninteractive authentication.
It rejects password-bearing/query-bearing HTTPS URLs, `http`, `file`, local
paths, helper transports, and option-looking inputs.

Git scope belongs to the profile, not the command line. `--ref` selects the
materialized working tree but does not narrow configured history coverage.
`--action-mode evaluate` can reduce an apply profile's authority; `apply` can
never upgrade an evaluate-only profile.

## Decisions and reports

A syntactically valid processing command writes exactly one compact JSON
report plus one newline to stdout. Logs remain on stderr. Callers must parse the
strict report, require `schema_version == "2"`, and verify that `exit_code`
equals the process status.

| Exit | Outcome | Meaning |
| ---: | --- | --- |
| `0` | `allow` | Complete required analysis allows the unchanged stage. |
| `10` | `allow_modified` | A stage-only action committed and a complete fresh scan allows the result. |
| `20` | `deny` | Complete trustworthy analysis found a blocking policy result. |
| `30` | `error` | Acquisition, coverage, analysis, policy, action, verification, reporting, or disposition is incomplete or untrustworthy. |

CLI syntax and help failures exit `2` before a job report exists. A caller must
fail closed on missing, malformed, truncated, omitted, or exit-inconsistent
JSON. A known finding plus an incomplete required analyzer is `error`, not
`deny`.

The report preserves safe source provenance, selected Git scope and frozen
refs, analyzer identity and coverage, original findings and correlations, Pi
assessments and adjudication decisions, actions, disposition, and handoff
status. It intentionally excludes source paths, Git locators, matched values,
content digests, snippets, raw scanner diagnostics, prompts, transcripts, and
internal workspace paths.

## Upload and handoff workflow

For an upload service:

1. Finish writing a caller-owned private source directory and stop other
   writers.
2. Run `process path`; File Guardian acquires its own copy.
3. Parse and validate the report/status pair.
4. Accept only `allow` or `allow_modified` whose report says the sealed stage
   is available.
5. Explicitly hand off that retained stage to a new, absent destination.
6. Remove the caller-owned upload source according to the application's own
   policy.

```bash
file-guardian --config /etc/file-guardian/config.toml \
  stage handoff RUN_ID --destination /srv/approved/upload-4821 --mode move
```

`move` requires the same filesystem and never falls back to copying. `copy`
uses a private sibling destination, verifies it against the sealed final
manifest, and atomically publishes it. Neither mode overwrites an existing
destination. File Guardian revalidates the retained stage immediately before
handoff.

Other administrative commands are:

```text
file-guardian stage discard RUN_ID
file-guardian artifact inspect RUN_ID QUARANTINE_ID
file-guardian artifact recover RUN_ID QUARANTINE_ID --destination PATH
file-guardian artifact discard RUN_ID QUARANTINE_ID
file-guardian job inspect RUN_ID
file-guardian job recover
file-guardian daemon [--job JOB_ID ...]
```

Each emits one versioned JSON result. Administrative commands use exit `0` for
success, `20` when the requested state transition is inapplicable, `30` when
the result is operationally untrustworthy, and `2` for syntax errors.

## Policy pipeline

The schema-3 configuration compiles named profiles, ordered pipelines, analyzer
selection and limits, policy bindings, Pi authority, remediation authority, and
terminal disposition. Unknown fields, duplicate IDs, unresolved references,
unsafe path overlaps, invalid source/scope combinations, and inconsistent Pi
authority fail before acquisition.

Built-in rules detect; profile policy decides. External scanner findings are
normalized by first-party adapters. Repository-provided `.gitleaks.toml`,
`.gitleaksignore`, or tool binaries are untrusted scan inputs and never policy.
Required analyzer assignment has explicit eligible, assigned, completed, and
not-applicable coverage. Administrator-approved selector exclusions are bound
into the compiled pipeline/report identity rather than counted as a coverage
bucket.

Pi receives normalized finding records, the real matched evidence and context,
and complete read-only staged/history content access. Advisory Pi can annotate
but cannot clear. `authoritative` Pi may clear a routed finding by classifying
it `false_positive`; confidence and reason codes remain audit metadata rather
than a second host veto. The original deterministic finding remains in the
report even when cleared.

Whole-file `delete` and `quarantine` actions operate only on regular files in
the owned stage. They are identity-checked and durably journaled. Deny suppresses
mutation, quarantine dominates delete for the same file, and Git-history
artifacts are never actionable. After any action, File Guardian recaptures the
stage and reruns every required analyzer (and required Pi assertion) against
the final manifest. If that fresh verification does not allow the result, the
job exits `30`, the modified stage is quarantined, and no handoff is available;
File Guardian does not automatically retry or roll the stage back.

## Retention and recovery

Every job has a private durable state machine. A profile independently chooses
`retain`, `discard`, or whole-job `quarantine` for each terminal outcome.
Only a sealed retained `allow`/`allow_modified` stage is handoff-eligible.
Report-only profiles cannot retain a handoff stage.

Retention TTLs and capacity ceilings are admission controls, not opportunistic
eviction. Unexpired available or quarantined jobs are never deleted to admit a
new run. Each job reserves its configured maximum publication payload before
acquisition; a capacity failure therefore occurs before the source is copied or
cloned. New admissions and `job recover` remove only expired terminal payloads
while preserving their immutable reports. Recovery resumes or fails stale work
from durable identities and journals; it never manufactures an allowed decision
from incomplete state.

## Operator documentation and testing

- [Operator guide](docs/processing-operator-guide.md) covers deployment,
  profiles, Git authentication, scanners, Pi, remediation, privacy checks,
  lifecycle operations, and troubleshooting.
- [Unified processing specification](docs/unified-processing-jobs.md) is the
  normative architecture, security, schema, and acceptance contract.
- [Live acceptance harness](scripts/processing-live-acceptance.sh) creates only
  disposable synthetic fixtures and uses only explicitly installed tools. It
  never downloads scanners or uses production credentials/repos.
- [Git transport acceptance](scripts/processing-git-transport-acceptance.sh)
  starts disposable authenticated smart-HTTPS and OpenSSH servers from an
  already-installed local container image. It proves credential-helper and
  SSH-agent acquisition, history coverage, and retained handoff of the exact
  clone including `.git`, without contacting an external network.

The normal Rust suite is deterministic and offline:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --doc --all-features
cargo build --release --all-features
```

Live acceptance is separately operator-gated. See the operator guide before
providing scanner or Pi profiles.

## Release

Maintainers release from clean, up-to-date `main` with the release script:

```bash
node scripts/release.mjs current
node scripts/release.mjs patch
node scripts/release.mjs minor
node scripts/release.mjs major
node scripts/release.mjs 1.0.0
```

Release archives are named `file-guardian-VERSION-PLATFORM.tar.gz` and contain
`bin/file-guardian`, configuration/rule examples, `README.md`, `CHANGELOG.md`,
`LICENSE`, and `docs/`. Verify archive contents and checksums before
distribution.

## License

See [LICENSE](LICENSE).
