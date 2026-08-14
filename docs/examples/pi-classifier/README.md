# Pi classifier fixtures

[`restricted.json`](restricted.json) is a canonical terminal submission for
`file-guardian-pi-classifier/1`. It is the argument to the terminating
`submit_classification` tool, not Pi stdout and not an authorization report.
The host accepts it only when all of these values agree with the current run:

- the immutable manifest identity;
- the exact assigned-artifact count and every referenced artifact ID;
- tree scope and canonical ordering/uniqueness;
- the configured classification, confidence, and reason-code vocabulary;
- configured list and serialized-output limits.

Unknown fields or values are rejected. A rejection is reported through a safe
typed analyzer issue; the submitted JSON, prompt, model prose, artifact content,
tool requests and responses, transport credentials, proxy token/socket, and
Pi stdout/stderr are not copied into the authorization report.

Automated tests use fake processes and synthetic artifacts and do not contact a
model. The offline extension checks can also be run directly from the repository
root when Node is installed:

```bash
node --check src/analyzers/pi/assets/file_guardian_extension.js
node --check src/analyzers/pi/assets/tool_sidecar_runner.js
node --check tests/pi_extension_harness.mjs
node --check tests/pi_tool_sidecar_harness.mjs
node --check tests/pi_tool_sidecar_bwrap_harness.mjs
node tests/pi_extension_harness.mjs
node tests/pi_tool_sidecar_harness.mjs
node tests/pi_tool_sidecar_bwrap_harness.mjs
```

The Rust `pi_extension_contract` test invokes the same harness when `node` is
available; otherwise it retains the deterministic source-contract checks. The
harness uses a mocked Pi/TypeBox environment and synthetic proxy pages, never a
provider or artifact content.

Live acceptance is deliberately operator opt-in. Build the release
binary, prepare the pinned runtime bundle and approved provider configuration,
and use synthetic sensitive content unless a protected fixture is intentional:

```bash
export FILE_GUARDIAN_PI_LIVE_CONFIG=/absolute/path/to/config.toml
export FILE_GUARDIAN_PI_LIVE_INPUT=/absolute/path/to/private-synthetic-staging
export FILE_GUARDIAN_BIN=target/release/file-guardian
tests/pi_live_acceptance.sh
```

The executable script contacts the configured model, requires one schema-valid
allow report with matching exit status, checks that stdout omits the staging
path, and verifies the input remains unchanged. It is not part of `cargo test`.
A live pass tests that configured integration and scenario; it does not promote
Pi from audit-only or establish the model as a filesystem security boundary.

[`runtime-manifest.example.json`](runtime-manifest.example.json) illustrates
the strict runtime-manifest shape. Its hashes are placeholders, and a real
manifest lists every regular file in the bundle exactly once except the
manifest itself. The `executable` flag must match file mode. In addition to the
shown categories, include every Pi/Node dependency needed by the selected
platform. The sidecar receives no host library mounts, so its Node, Bash, and
toolbox executables must be self-contained/static; the example is not a
ready-to-run bundle. The manifest-pinned toolbox must include the Node launcher,
noninteractive `bash`, `rg`, `fd`, and the command-line programs documented by
the active configuration. Pi uses the host network, while every model-directed
operating-system tool executes through the persistent networkless sidecar with
an empty inherited environment. Search tools run with ignore processing
disabled.
