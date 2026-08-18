# Trusted Pi triage extension

`file_guardian_extension.js` is the reviewed extension for the pinned Pi 0.83.0
triage runtime. File Guardian hashes this exact file into pipeline identity
and loads it into a normally networked Pi process with an explicit `--extension`
argument while extension discovery and Pi built-ins remain disabled.

The extension registers exactly eight sequential tools:

```text
bash,find,grep,ls,manifest_list,read,submit_triage,triage_request
```

The extension starts one persistent Bubblewrap sidecar at session startup and
exchanges bounded newline-delimited JSON requests with it over private pipes.
The sidecar has no network namespace, receives no provider credentials or proxy
token, mounts the immutable analyzer view read-only at `/input`, and provides an
ephemeral writable `/work` that persists across tool calls in the invocation.
It mounts only the manifest-pinned runtime toolbox and the reviewed
`tool_sidecar_runner.js`; it does not mount Pi configuration, the File Guardian
workspace, the host root, or the host proxy socket.

`bash`, `read`, `grep`, `find`, and `ls` all execute inside that one sidecar.
`bash` supplies a normal noninteractive shell over the pinned toolbox, with
`/work` as its working directory. The path tools accept only relative paths
beneath `/input`. Absolute paths, `..`, NUL, `~`, leading `@`, links, special
files, and normalization escapes are rejected. `grep` and `find` invoke only
the manifest-pinned `/runtime/bin/rg` and `/runtime/bin/fd`, always using
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
follow `next_cursor` until it is `null`. `triage_request` returns only bounded,
identity-bound normalized prior findings; it never supplies file contents,
matched values, snippets, or raw scanner output. `submit_triage` is
candidate-free and finding-ID based, and terminates the agent only after the
host validates and accepts the structured payload.

The extension itself imports only pinned Pi/TypeBox APIs and the Node path,
Unix-socket, readline, crypto, and child-process modules needed for the closed
control plane. It performs no model-directed filesystem operation in the Pi
parent. There is no HTTP, session, configuration-discovery, write/edit, command,
shortcut, or messaging tool. The authenticated internal `instruction`
operation supplies the host-owned system instruction and is never exposed as
an LLM tool.
