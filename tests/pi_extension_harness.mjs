import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const extensionUrl = new URL("../src/analyzers/pi/assets/file_guardian_extension.js", import.meta.url);
let source = await readFile(extensionUrl, "utf8");
source = source
	.replace(/^import .*;$/gm, "")
	.replace("export default function fileGuardianClassifierExtension", "function fileGuardianClassifierExtension");
source += `
globalThis.__fileGuardianTestHooks = {
  boundedLineOutput,
  consumeManifestPage,
  manifestPageResult,
  normalizedToolCallId,
  readLineWindow,
  requiredBoundedIntegerEnvironment,
  getNextManifestCursor: () => nextManifestCursor,
};
`;

const environment = {
	FILE_GUARDIAN_PI_PROXY_SOCKET: "/run/file-guardian/proxy.sock",
	FILE_GUARDIAN_PI_RUN_TOKEN: "token",
	FILE_GUARDIAN_PI_RUN_ID: "run_01",
	FILE_GUARDIAN_PI_MANIFEST_IDENTITY: `sha256:${"4".repeat(64)}`,
	FILE_GUARDIAN_PI_ANALYZER_ID: "pi-review",
	FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS: "37",
};
const Type = new Proxy(
	{},
	{
		get: () => (...args) => ({ args }),
	},
);
const context = {
	Buffer,
	createHash,
	TextDecoder,
	Type,
	clearTimeout,
	console,
	process: { env: environment },
	setTimeout,
};
vm.runInNewContext(source, context, { filename: extensionUrl.pathname });
const hooks = context.__fileGuardianTestHooks;

const providerToolCallId = "call_7G2ERUu9RTsYpne1UqqGmeeJ|fc_044c3f1c9703cdb5016a7ea72a094481";
assert.equal(
	hooks.normalizedToolCallId(providerToolCallId),
	`tc_${createHash("sha256").update(providerToolCallId, "utf8").digest("hex")}`,
);
assert.match(hooks.normalizedToolCallId(providerToolCallId), /^tc_[0-9a-f]{64}$/);
assert.throws(() => hooks.normalizedToolCallId("bad\nidentity"), /invalid tool call identity/);

assert.equal(hooks.requiredBoundedIntegerEnvironment("FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS", 10_000), 37);
for (const invalid of ["0", "01", "+1", " 1", "10001"]) {
	environment.FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS = invalid;
	assert.throws(
		() => hooks.requiredBoundedIntegerEnvironment("FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS", 10_000),
		/invalid File Guardian integer runtime setting/,
	);
}
environment.FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS = "37";

const firstPage = {
	schema: "file-guardian-pi-manifest-page/1",
	manifest_identity: environment.FILE_GUARDIAN_PI_MANIFEST_IDENTITY,
	cursor: 0,
	total_count: 3,
	entries: [{ artifact_id: "a_01" }, { artifact_id: "a_02" }],
	next_cursor: 2,
};
assert.equal(hooks.consumeManifestPage(firstPage), firstPage);
assert.equal(hooks.getNextManifestCursor(), 2);
assert.throws(
	() => hooks.manifestPageResult({ ...firstPage, cursor: 2, next_cursor: 1 }, 2),
	/discontinuous manifest page/,
);
assert.equal(
	hooks.consumeManifestPage(
		{
			...firstPage,
			cursor: 2,
			entries: [{ artifact_id: "a_03" }],
			next_cursor: null,
		},
		2,
	).next_cursor,
	null,
);
assert.equal(hooks.getNextManifestCursor(), 3);
const terminalPage = {
	...firstPage,
	cursor: 3,
	entries: [],
	next_cursor: null,
};
assert.equal(hooks.consumeManifestPage(terminalPage), terminalPage);
assert.equal(hooks.getNextManifestCursor(), 3);

assert.equal(hooks.readLineWindow("one\ntwo\nthree", 2, 1), "two");
assert.throws(
	() => hooks.readLineWindow("one\ntwo", 3, 1),
	(error) =>
		error?.name === "RecoverableNativeToolError" &&
		/Read offset is beyond end of file/.test(error.message),
);

const oversizedLine = "sensitive-partial-line".repeat(5000);
const bounded = hooks.boundedLineOutput(["complete", oversizedLine], "(empty)", false, 10, "entry");
assert.equal(bounded.resultCount, 1);
assert.match(bounded.text, /^complete\n\n\[Truncated: 65536 output byte limit\]$/);
assert.ok(!bounded.text.includes("sensitive-partial-line"));
assert.ok(Buffer.byteLength(bounded.text, "utf8") <= 64 * 1024);

console.log("Pi extension harness passed");
