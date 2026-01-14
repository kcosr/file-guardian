# File Guardian

A policy enforcement service that periodically scans directories for disallowed files based on configurable rules, taking automatic remediation actions when violations are found.

## Reference Implementation

For Rust conventions (config, logging, error handling), reference the build-service project:

```
/home/kevin/worktrees/build-service
```

Key patterns to follow:

- **Config** (`src/config/mod.rs`):
  - TOML with `serde::Deserialize` structs
  - `schema_version` field for forward compatibility
  - Default values via `#[serde(default = "default_fn")]` and standalone `fn default_*()` functions
  - Separate `validate()` method called after parsing
  - `ConfigError` enum with `thiserror` for typed errors

- **Logging** (`src/logging/mod.rs`):
  - `tracing` + `tracing-subscriber` for structured logging
  - `RotatingFileWriter` for size-based log rotation
  - Optional console + file output via `TeeWriter`
  - Non-blocking writes via channel + worker thread
  - Plain text format (not JSON)

- **Error handling**:
  - Custom error enums with `#[derive(Debug, thiserror::Error)]`
  - `#[error("message with {field}")]` for Display impl
  - `#[source]` attribute for error chaining

## Purpose

- Enforce file policies across user directories (e.g., no executables, no hardcoded secrets)
- Detect sensitive content that shouldn't be stored in plaintext
- Provide configurable remediation: warn, remove, replace content, or recover files
- Run as a system service with periodic scanning

## Environment

- Host OS: Linux (Rocky Linux, Ubuntu, etc.)
- Runs as: root (to read/modify files across all user directories)
- Target directories: User home directories, shared storage, etc.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  file-guardian                                              │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │ Config      │───►│ Rules       │───►│ Scanner         │  │
│  │ Loader      │    │ Compiler    │    │                 │  │
│  └─────────────┘    └─────────────┘    │  - Glob expand  │  │
│        │                   │           │  - Walk dirs    │  │
│        ▼                   ▼           │  - Match rules  │  │
│  ┌─────────────┐    ┌─────────────┐    │  - Execute act  │  │
│  │ TOML Config │    │ .rules      │    └─────────────────┘  │
│  │             │    │ files       │             │           │
│  └─────────────┘    └─────────────┘             ▼           │
│                                        ┌─────────────────┐  │
│                                        │ Actions         │  │
│                                        │  - warn         │  │
│                                        │  - remove       │  │
│                                        │  - replace      │  │
│                                        │  - recover      │  │
│                                        └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. file-guardian (Daemon)

Rust binary running as root under systemd.

**Responsibilities:**
- Load configuration from TOML file
- Compile rules from inline config and `.rules` files
- Periodically scan directories matching configured glob patterns
- Match files against rules (filename globs, content regexes)
- Execute configured actions on violations
- Log all violations with detailed metadata

### 2. Rule Sources

Rules are loaded from two sources:

1. **Inline rules** in the main config file
2. **External `.rules` files** in a configurable `rules.d` directory

This allows base rules in config with drop-in additions via separate files.

## Configuration

**Location:** `/etc/file-guardian/config.toml`

**Environment variable override:** `FILE_GUARDIAN_CONFIG`

```toml
schema_version = "1"

[scan]
# Glob patterns for directories to scan
directories = ["/home/*"]

# Scan interval in seconds (default: 1 hour)
interval_secs = 3600

# Maximum file size to scan in bytes (skip larger files)
max_file_size = 10485760  # 10 MiB

# Write summary files after each scan
write_summaries = true

# Directory to store scan summaries
summary_dir = "/var/log/file-guardian/summaries"

# Patterns to exclude from scanning (glob syntax)
exclude_patterns = [
    "*.git*",
    "node_modules",
    ".cache",
]

[policy]
# Default action when a rule doesn't specify one: warn, remove, replace, recover
default_action = "warn"

# Directory for recovered files (used with 'recover' action)
recovery_dir = "/var/lib/file-guardian/recovered"

# Message to write when using 'replace' action
replace_message = """
This file has been removed by file-guardian due to policy violation.
Contact your system administrator for more information.
"""

[rules]
# Directory containing .rules files (one rule per line)
rules_d = "/etc/file-guardian/rules.d"

# Inline rules defined in this config file
[[rules.inline]]
name = "no-exe"
filename_glob = "*.exe"
action = "remove"

[[rules.inline]]
name = "detect-passwords"
content_regex = "(?i)password\\s*=\\s*[\"'][^\"']+[\"']"
action = "warn"

[logging]
level = "info"
directory = "/var/log/file-guardian"
max_bytes = 104857600   # 100MB
max_files = 5
console = false
```

## Rules Format

### Inline Rules (TOML)

```toml
[[rules.inline]]
name = "rule-name"           # Required: unique identifier
filename_glob = "*.exe"      # Optional: glob pattern for filename matching
content_regex = "pattern"    # Optional: regex pattern for content matching
action = "warn"              # Optional: override default_action
```

At least one of `filename_glob` or `content_regex` must be specified.

### External Rules Files

**Location:** `/etc/file-guardian/rules.d/*.rules`

**Format:** One rule per line

```
name:type:pattern[:action]
```

- `name` - Unique identifier for the rule
- `type` - `glob` (filename matching) or `regex` (content matching)
- `pattern` - The glob or regex pattern
- `action` - Optional, one of: `warn`, `remove`, `replace`, `recover`

**Example file:** `/etc/file-guardian/rules.d/security.rules`

```
# Block Windows executables
no-exe:glob:*.exe:remove
no-dll:glob:*.dll:remove
no-msi:glob:*.msi:remove

# Detect secrets in files
passwords:regex:(?i)password\s*[:=]\s*["'][^"']{4,}["']:warn
aws-access-key:regex:AKIA[0-9A-Z]{16}:recover
private-ssh-key:regex:-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----:recover
```

Lines starting with `#` are comments. Empty lines are ignored.

## Rule Matching

### Filename Matching (Glob)

Uses standard glob syntax:
- `*` matches any sequence of characters
- `?` matches any single character
- `[abc]` matches any character in the set
- `[!abc]` matches any character not in the set

Matching is performed against the filename only (not the full path).

### Content Matching (Regex)

Uses Rust regex syntax (similar to PCRE). Content scanning:
- Only performed on text files (binary files are skipped)
- Binary detection: files containing null bytes in the first 8KB are considered binary
- Files larger than `max_file_size` are skipped

## Actions

| Action | Description |
|--------|-------------|
| `warn` | Log the violation, take no other action |
| `remove` | Delete the file |
| `replace` | Replace file content with `policy.replace_message` |
| `recover` | Move file to recovery directory with timestamped path |

### Recovery Directory Structure

When using the `recover` action, files are moved to a timestamped subdirectory with the original path encoded in the filename:

```
/var/lib/file-guardian/recovered/
└── 2026-01-14T10-36-40/
    ├── --home--kevin--sensitive.txt
    └── --home--alice--secrets.conf
```

Path encoding: `/` characters are replaced with `--`

Example: `/home/kevin/sensitive.txt` → `--home--kevin--sensitive.txt`

This preserves the original location information while creating a flat, safe filename.

The recovery directory is created on-demand when a `recover` action executes.

## Violation Logging

Each violation is logged with detailed metadata:

```
WARN file_guardian::scanner: violation: path=/home/kevin/secrets.txt rule=passwords match=content action=warn owner=1000:1000 size=1234 mtime=2026-01-14 10:30:00 snippet="password = \"secret123\"..."
```

Fields logged:
- `path` - Full path to the violating file
- `rule` - Name of the matched rule
- `match` - Match type: `filename` or `content`
- `action` - Action taken (or would be taken in dry-run)
- `owner` - File owner as `uid:gid`
- `size` - File size in bytes
- `mtime` - File modification time
- `snippet` - For content matches, truncated matched text (max 100 chars)
- `dry_run` - Present and `true` if running in dry-run mode

## Scan Summaries

When `scan.write_summaries = true`, each scan writes a summary file to
`scan.summary_dir` using a timestamped
subdirectory:

```
/var/log/file-guardian/summaries/
└── 2026-01-14T10-36-40/
    └── summary.json
```

The summary contains counts, timestamps, and a list of violations (with action errors, if any).

Set `scan.write_summaries = false` to disable summary file creation.

## CLI Interface

```
file-guardian [OPTIONS]

Options:
    --config <PATH>    Path to configuration file
    --once             Run a single scan and exit (don't loop)
    --dry-run          Log violations but don't modify any files
    -h, --help         Print help
    -V, --version      Print version
```

### Usage Examples

```bash
# Run as daemon (periodic scanning)
sudo file-guardian

# Run with custom config
sudo file-guardian --config /path/to/config.toml

# Single scan, no modifications (testing)
sudo file-guardian --once --dry-run

# Single scan with enforcement
sudo file-guardian --once
```

## Deployment

### Systemd Service

**File:** `/etc/systemd/system/file-guardian.service`

```ini
[Unit]
Description=File Guardian - Policy enforcement scanner
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/file-guardian
Restart=on-failure
RestartSec=10

# Hardening (optional)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Installation

```bash
# Build
cargo build --release

# Install binary
sudo cp target/release/file-guardian /usr/local/bin/
sudo chmod 755 /usr/local/bin/file-guardian

# Install config
sudo mkdir -p /etc/file-guardian/rules.d
sudo cp config/config.toml /etc/file-guardian/
sudo cp config/rules.d/*.rules /etc/file-guardian/rules.d/

# Create directories
sudo mkdir -p /var/log/file-guardian
# Optional if scan.write_summaries = true
sudo mkdir -p /var/log/file-guardian/summaries
# Optional if recover action is used
sudo mkdir -p /var/lib/file-guardian/recovered

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable file-guardian
sudo systemctl start file-guardian
```

## Error Handling

| Error | Behavior |
|-------|----------|
| Config file not found | Exit with error |
| Invalid config syntax | Exit with error |
| Invalid rule pattern | Exit with error (fail fast) |
| Cannot read directory | Log warning, continue scanning |
| Cannot read file | Log debug, skip file |
| Cannot execute action | Log error, continue scanning |
| Recovery dir creation fails | Log error, skip recovery |

The scanner continues on per-file errors to ensure one problematic file doesn't halt the entire scan.

## Security Considerations

- **Runs as root**: Required to read/modify files across user directories
- **No shell execution**: All file operations use direct syscalls
- **Path validation**: Recovery paths are encoded to prevent directory traversal
- **Atomic operations**: File moves use `rename()` for atomicity where possible
- **Audit trail**: All actions are logged with full context

## Testing

### Dry-Run Mode

Always test new rules with `--dry-run` first:

```bash
sudo file-guardian --once --dry-run 2>&1 | grep violation
```

This logs what would happen without modifying any files.

### Rule Validation

Rules are validated at startup. Invalid glob or regex patterns cause immediate exit with a descriptive error message.

## Future Considerations

- **Checksums**: Option to log file checksums for forensic purposes
- **Notifications**: Webhook or email alerts on violations
- **Rate limiting**: Limit actions per scan to prevent mass deletions
- **Allowlists**: Per-directory or per-user rule overrides
- **Metrics**: Prometheus endpoint for monitoring scan stats
- **Inotify mode**: Real-time scanning via filesystem events instead of periodic
