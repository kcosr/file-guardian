# Trusted Pi triage extension

`file_guardian_extension.js` is the reviewed extension for the configured Pi
triage runtime. File Guardian loads it into a normally networked Pi process with
an explicit `--extension` argument while extension discovery and Pi built-ins
remain disabled. Pi uses the administrator-installed executable and ordinary
host runtime; there is no copied runtime closure.

The extension registers exactly eight sequential tools:

```text
bash,find,grep,ls,manifest_list,read,submit_triage,triage_request
```

The extension starts one persistent Bubblewrap sidecar at session startup and
exchanges bounded newline-delimited JSON requests with it over private pipes.
The sidecar has no network, receives no provider credentials or proxy token,
sees the immutable analyzer view and normal host filesystem read-only, and has
a writable scratch directory that persists across tool calls. This is an
accidental-write boundary, not a confidentiality boundary against Pi.

`bash`, `read`, `grep`, `find`, and `ls` all execute inside that one sidecar.
`bash` supplies a normal noninteractive shell over administrator-installed host
tools, with scratch as its working directory. The path tools accept only
relative paths beneath the immutable input view. Absolute paths, `..`, NUL,
`~`, leading `@`, links, special files, and normalization escapes are rejected.
`grep` and `find` invoke `rg` and `fd` from the validated host `PATH`, using
`--hidden --no-ignore`. All parameters, output, result counts, helper
diagnostics, and execution time are bounded.
Search and listing output is truncated only at complete line boundaries with a
deterministic notice; ripgrep also caps and previews overlong columns. Invalid
model-supplied search expressions close their audit record as a recoverable
`invalid_arguments` outcome and return a sanitized retry instruction. Path,
proxy, accounting, helper lifecycle, and other integrity failures remain fatal.

The launcher supplies the validated non-secret
`FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS` value. The extension requires a canonical
decimal integer from 1 through 10,000 at module load, uses it as the schema
maximum for `grep`, `find`, and `ls`, and clamps each omitted tool default to
that cap. The host proxy independently enforces the same configured budget.

Every accepted sidecar operation is bracketed by authenticated
`native_tool_begin` and `native_tool_end` proxy records. Any validation,
execution, accounting, or proxy failure permanently invalidates the run and
prevents terminal submission. The helpers run sequentially, preserving the
proxy protocol's monotonically increasing request order.

`manifest_list` supplies the authoritative presentation-path to immutable
artifact-ID mapping in bounded cursor pages. Callers begin at cursor `0` and
follow `next_cursor` until it is `null`. `triage_request` returns bounded,
identity-bound normalized findings with their actual matched evidence and
context. Working-tree findings carry their exact staged paths. History
findings carry their frozen commit, blob, path, and ref provenance; Pi uses
ordinary Git commands against the exact staged `.git` directory to inspect
that context. The content tools expose the staged tree, while the Git CLI
exposes the configured history surface.
`submit_triage` is
candidate-free and finding-ID based, and terminates the agent only after the
host validates and accepts the structured payload.

The extension itself imports only Pi/TypeBox APIs and the Node path,
Unix-socket, readline, crypto, and child-process modules needed for the closed
control plane. It performs no model-directed filesystem operation in the Pi
parent. There is no HTTP, session, configuration-discovery, write/edit, command,
shortcut, or messaging tool. The authenticated internal `instruction`
operation supplies the host-owned system instruction and is never exposed as
an LLM tool.
