# file-guardian

A Rust service that scans directories for disallowed files based on configurable rules. Designed to run as root to monitor and enforce file policies across user directories.

## Features

- **Periodic scanning** of directories matching glob patterns (e.g., `/home/*`)
- **Filename matching** via glob patterns (e.g., `*.exe`, `*.dll`)
- **Content matching** via regex patterns (e.g., detect hardcoded passwords, API keys)
- **Binary file detection** - automatically skips binary files for content scanning
- **Configurable actions**:
  - `warn` - log the violation only
  - `remove` - delete the file
  - `replace` - replace file content with a policy message
  - `recover` - move file to a timestamped recovery directory
- **Dry-run mode** - test rules without modifying files
- **Scan summaries** - optional JSON report per scan
- **Rules from multiple sources** - inline in TOML config or from `.rules` files

## Installation

```bash
cargo build --release
sudo cp target/release/file-guardian /usr/local/bin/
sudo mkdir -p /etc/file-guardian/rules.d
sudo cp config/config.toml /etc/file-guardian/
sudo cp config/rules.d/*.rules /etc/file-guardian/rules.d/
sudo mkdir -p /var/log/file-guardian
# Optional if scan.write_summaries = true
sudo mkdir -p /var/log/file-guardian/summaries
# Optional if recover action is used
sudo mkdir -p /var/lib/file-guardian/recovered
```

## Usage

```bash
# Run with default config (/etc/file-guardian/config.toml)
sudo file-guardian

# Run with custom config
sudo file-guardian --config /path/to/config.toml

# Run once and exit (don't loop)
sudo file-guardian --once

# Dry-run mode (log violations without modifying files)
sudo file-guardian --dry-run

# Combine flags
sudo file-guardian --once --dry-run
```

## Configuration

Configuration is loaded from (in order of precedence):
1. `--config` command-line argument
2. `FILE_GUARDIAN_CONFIG` environment variable
3. `/etc/file-guardian/config.toml` (default)

### Example config.toml

```toml
schema_version = "1"

[scan]
# Glob patterns for directories to scan
directories = ["/home/*"]

# Scan interval in seconds
interval_secs = 3600

# Skip files larger than this (bytes)
max_file_size = 10485760

# Write summary files after each scan
write_summaries = true

# Directory to store scan summaries
summary_dir = "/var/log/file-guardian/summaries"

# Patterns to exclude
exclude_patterns = ["*.git*", "node_modules"]

[policy]
# Default action: warn, remove, replace, recover
default_action = "warn"

# Recovery directory for 'recover' action
recovery_dir = "/var/lib/file-guardian/recovered"

# Message for 'replace' action
replace_message = "This file was removed due to policy violation.\n"

[rules]
# Directory containing .rules files
rules_d = "/etc/file-guardian/rules.d"

# Inline rules
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
max_bytes = 104857600
max_files = 5
console = false
```

## Rules Files

Rules can be defined in `.rules` files in the `rules.d` directory. Format:

```
# Comments start with #
name:type:pattern[:action]
```

- `name` - unique identifier for the rule
- `type` - `glob` (filename) or `regex` (content)
- `pattern` - the glob or regex pattern
- `action` - optional, one of: `warn`, `remove`, `replace`, `recover`

### Example rules file

```
# Block executables
no-exe:glob:*.exe:remove
no-dll:glob:*.dll:remove

# Detect secrets
passwords:regex:(?i)password\s*=\s*["'][^"']+["']:warn
aws-keys:regex:AKIA[0-9A-Z]{16}:recover
private-keys:regex:-----BEGIN PRIVATE KEY-----:recover
```

## Recovery Directory Structure

When using the `recover` action, files are moved to:
```
/var/lib/file-guardian/recovered/
└── 2026-01-14T10-36-40/
    ├── --home--kevin--sensitive.txt
    └── --home--alice--secrets.conf
```

The original path is encoded in the filename by replacing `/` with `--`.

The recovery directory is created on-demand when a `recover` action executes.

## Logging

Logs are written to:
- Console (if `logging.console = true`)
- File (if `logging.directory` is set)

Log rotation is automatic based on `max_bytes` and `max_files` settings.

Override log level via environment:
```bash
FILE_GUARDIAN_LOG_LEVEL=debug file-guardian
```

## Scan Summaries

When `scan.write_summaries = true`, each scan writes a summary file to
`scan.summary_dir` using a timestamped subdirectory, for example:

```
/var/log/file-guardian/summaries/
└── 2026-01-14T10-36-40/
    └── summary.json
```

Set `scan.write_summaries = false` to disable summary file creation.

## Running as a Service

Create a systemd unit file at `/etc/systemd/system/file-guardian.service`:

```ini
[Unit]
Description=File Guardian - Policy enforcement scanner
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/file-guardian
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable file-guardian
sudo systemctl start file-guardian
```

## License

MIT
