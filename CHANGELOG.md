# Changelog

## [Unreleased]

### Breaking Changes

- Replaced the `authorize` command and schema-2 authorization configuration
  with strict schema-3 `process path|git` jobs and processing report schema 2.
  ([#5](https://github.com/kcosr/file-guardian/pull/5))

### Added

- Added durable owned stages, exact local-directory copy and authenticated
  HTTPS/SSH cloning, Git history scopes, PATH-discovered Gitleaks and
  TruffleHog pipelines, trusted Pi evidence triage and false-positive
  adjudication, stage-only remediation with full verification, lifecycle
  disposition/handoff/recovery, artifact quarantine, and daemon processing.
  ([#5](https://github.com/kcosr/file-guardian/pull/5))

### Changed

- Pi now receives actual matched evidence and the complete staged repository or
  directory read-only; its Bubblewrap boundary prevents mistaken mutation and
  contains descendants rather than treating Pi as an adversary.
  ([#5](https://github.com/kcosr/file-guardian/pull/5))

### Fixed

- Fixed release script cleanup handling after successful GitHub release creation.
- Improved release-script diagnostics and changelog validation edge cases.

## [0.0.4] - 2026-06-03

### Changed

- Release automation now creates normal GitHub releases. ([#4](https://github.com/kcosr/file-guardian/pull/4))
- Release version bumping is now handled inside the single release script, matching sibling Rust release tooling. ([#4](https://github.com/kcosr/file-guardian/pull/4))
- Release script now supports `current` and explicit stable version arguments, with clean-main, origin/main sync, authenticated GitHub CLI, and free-tag preconditions. ([#4](https://github.com/kcosr/file-guardian/pull/4))
- Hardened release version validation, local and remote tag checks, release recovery instructions, and release-script cleanup paths. ([#4](https://github.com/kcosr/file-guardian/pull/4))
- Documented release download/install guidance and Linux x86_64 plus macOS ARM64 archive
  packaging, with source builds moved to the development workflow. ([#4](https://github.com/kcosr/file-guardian/pull/4))

## [0.0.3] - 2026-01-17

### Breaking Changes
- Remove `replace` as a primary action; use `policy.replacement` with `remove`/`recover` instead. ([#3](https://github.com/kcosr/file-guardian/pull/3))

### Added
- Optional replacement stubs via `policy.replacement` with marker-based suppression. ([#3](https://github.com/kcosr/file-guardian/pull/3))

## [0.0.2] - 2026-01-16

### Breaking Changes
- Summary outputs now write `<run_id>.json` under the selected layout and default to `flat` (no per-run `summary.json` directory). ([#2](https://github.com/kcosr/file-guardian/pull/2))

### Added
- Configurable scan summary layout (`scan.summary_layout`) with flat/daily/hourly buckets. ([#2](https://github.com/kcosr/file-guardian/pull/2))

## [0.0.1] - 2026-01-14

### Added
- Rule-based file scanning with per-rule actions (log/remove/recover/replace).
- Streaming violation logging with JSON summary output.
- Deterministic rule loading from `rules.d`.
- Symlink loop detection during directory traversal.
- Cross-device recover fallback (copy+remove).

### Changed
- Use `Cargo.toml` as single source of truth for versioning, remove `VERSION` file.

### Documentation
- Add security warning to README about best-effort detection limitations.
