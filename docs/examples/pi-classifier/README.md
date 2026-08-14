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
model. Live acceptance is deliberately operator opt-in. Build the release
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
shown categories, include every Pi/Node dependency and shared library actually
needed by the selected platform. The Node ELF interpreter and runtime search
path must resolve below sandbox `/runtime`; the example is not a ready-to-run
bundle. `bin/rg` and `bin/fd` are mandatory manifest-pinned helpers used by the
custom `grep` and `find` tools; they run without a shell, without an inherited
environment, and with ignore processing disabled.
