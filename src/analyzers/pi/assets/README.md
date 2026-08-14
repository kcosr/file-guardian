# Trusted Pi classifier extension

`file_guardian_extension.js` is the reviewed extension for the pinned Pi
0.83.0 classifier runtime. File Guardian hashes this exact file into pipeline
identity and mounts it read-only in the sandbox. It must be loaded only with an
explicit `--extension` argument while extension discovery is disabled.

The launcher uses print mode without sessions, built-in tools, skills, prompt
templates, themes, context files, or project approval. Its exact tool allowlist
is:

```text
artifact_metadata,artifact_read,artifact_read_range,artifact_search,manifest_list,prior_observations,submit_classification
```

The extension has only three imports: Pi's pinned version constant, TypeBox for
closed parameter schemas, and Node's Unix-socket transport. It does not import
filesystem, subprocess, or HTTP APIs. All artifact access and the terminal
classification travel through File Guardian's authenticated, invocation-scoped
proxy. Pi runs every registered tool sequentially, preserving monotonically
increasing request arrival and ensuring terminal submission cannot race an
artifact read. An authenticated extension-internal `instruction` proxy operation
supplies the exact host-owned system instruction; `instruction` is not an LLM
tool, is not passed on the command line, and is never read from an ambient path.

`submit_classification` terminates the agent only after the host has validated
and accepted the structured payload. Free-form stdout is never accepted as a
classification result.
