# Changelog

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
