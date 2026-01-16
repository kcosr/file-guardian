# Changelog

## [Unreleased]

### Added
- Configurable scan summary layout (`scan.summary_layout`) with flat/daily/hourly buckets.

### Changed
- Summary files now use the run timestamp as the filename and default to flat layout.

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
