import assert from "node:assert/strict";
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
  manifestPageResult,
  requiredBoundedIntegerEnvironment,
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
	TextDecoder,
	Type,
	clearTimeout,
	console,
	process: { env: environment },
	setTimeout,
};
vm.runInNewContext(source, context, { filename: extensionUrl.pathname });
const hooks = context.__fileGuardianTestHooks;

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
assert.equal(hooks.manifestPageResult(firstPage, 0), firstPage);
assert.throws(
	() => hooks.manifestPageResult({ ...firstPage, next_cursor: 1 }, 0),
	/discontinuous manifest page/,
);
assert.equal(
	hooks.manifestPageResult(
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

const oversizedLine = "sensitive-partial-line".repeat(5000);
const bounded = hooks.boundedLineOutput(["complete", oversizedLine], "(empty)", false, 10, "entry");
assert.equal(bounded.resultCount, 1);
assert.match(bounded.text, /^complete\n\n\[Truncated: 65536 output byte limit\]$/);
assert.ok(!bounded.text.includes("sensitive-partial-line"));
assert.ok(Buffer.byteLength(bounded.text, "utf8") <= 64 * 1024);

console.log("Pi extension harness passed");
