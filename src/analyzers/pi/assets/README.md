# Trusted Pi classifier extension

`file_guardian_extension.js` is the reviewed extension for the pinned Pi 0.83.0
classifier runtime. File Guardian hashes this exact file into pipeline identity
and mounts it read-only in the sandbox. It is loaded only with an explicit
`--extension` argument while extension discovery and Pi built-ins remain
disabled.

The extension registers exactly seven sequential tools:

```text
find,grep,ls,manifest_list,prior_observations,read,submit_classification
```

`read`, `grep`, `find`, and `ls` preserve the familiar Pi read-only workflow,
but are File Guardian implementations rather than ambient built-ins. They accept
only relative paths beneath the immutable analyzer view mounted at `/input`.
Absolute paths, `..`, NUL, `~`, leading `@`, links, special files, and
normalization escapes are rejected. `read` and `ls` use bounded Node filesystem
operations. `grep` and `find` invoke only the manifest-pinned
`/runtime/bin/rg` and `/runtime/bin/fd` executables, without a shell or inherited
credentials, and always use `--hidden --no-ignore`. All parameters, output,
result counts, helper diagnostics, and execution time are bounded.

The launcher supplies the validated non-secret
`FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS` value. The extension requires a canonical
decimal integer from 1 through 10,000 at module load, uses it as the schema
maximum for `grep`, `find`, and `ls`, and clamps each omitted tool default to
that cap. The host proxy independently enforces the same configured budget.

Every accepted native operation is bracketed by authenticated
`native_tool_begin` and `native_tool_end` proxy records. Any validation,
execution, accounting, or proxy failure permanently invalidates the run and
prevents terminal submission. The helpers run sequentially, preserving the
proxy protocol's monotonically increasing request order.

`manifest_list` supplies the authoritative presentation-path to immutable
artifact-ID mapping. `prior_observations` returns only bounded normalized
observations; it never supplies file contents, matched values, snippets, or raw
scanner output. `submit_classification` remains artifact-ID based and terminates
the agent only after the host validates and accepts the structured payload.

The extension imports only pinned Pi/TypeBox APIs and the Node filesystem, path,
Unix-socket, and child-process modules needed for this closed implementation.
There is no model-callable shell, general subprocess, HTTP, session,
configuration-discovery, mutation, command, shortcut, or messaging capability.
The authenticated internal `instruction` operation supplies the host-owned
system instruction and is never exposed as an LLM tool.
