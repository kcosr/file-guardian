import assert from "node:assert/strict";
import { mkdtemp, mkdir, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { spawn } from "node:child_process";

const protocol = "file-guardian-tool-sidecar/1";
const temporary = await mkdtemp(join(tmpdir(), "file-guardian-sidecar-"));
const input = join(temporary, "input");
const work = join(temporary, "work");
const sentinelPath = join(temporary, "parent-only-fd");
await mkdir(input, { mode: 0o700 });
await mkdir(work, { mode: 0o700 });
await writeFile(join(input, "artifact.txt"), "one\ntwo\nthree\n", { mode: 0o400 });
const inheritedSentinel = await open(sentinelPath, "w+");

const runner = new URL("../src/analyzers/pi/assets/tool_sidecar_runner.js", import.meta.url);
const child = spawn(process.execPath, [runner.pathname, "--test-roots", input, work, "/usr"], {
	env: {},
	stdio: ["pipe", "pipe", "pipe"],
});
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false });
const iterator = lines[Symbol.asyncIterator]();
let requestId = 0;

async function response() {
	const next = await iterator.next();
	assert.equal(next.done, false);
	return JSON.parse(next.value);
}

async function request(tool, params) {
	requestId += 1;
	child.stdin.write(`${JSON.stringify({ protocol, request_id: requestId, tool, params })}\n`);
	const value = await response();
	assert.equal(value.protocol, protocol);
	assert.equal(value.request_id, requestId);
	return value;
}

try {
	assert.deepEqual(await response(), { protocol, type: "ready" });

	const read = await request("read", { path: "artifact.txt", offset: 2, limit: 1 });
	assert.equal(read.status, "ok");
	assert.equal(read.result.text, "two");
	assert.equal(read.result.path, "artifact.txt");

	const write = await request("bash", { command: "printf persistent > state.txt" });
	assert.equal(write.status, "ok");
	assert.match(write.result.text, /\[exit 0\]$/);
	const reuse = await request("bash", { command: "cat state.txt" });
	assert.equal(reuse.status, "ok");
	assert.match(reuse.result.text, /^persistent\n\[exit 0\]$/);
	const descriptor = await request("bash", {
		command: `test \"$(readlink /proc/self/fd/${inheritedSentinel.fd} 2>/dev/null || true)\" != \"${sentinelPath}\"`,
	});
	assert.equal(descriptor.status, "ok");
	assert.match(descriptor.result.text, /\[exit 0\]$/);

	const invalid = await request("read", { path: "../outside", offset: 1, limit: 1 });
	assert.equal(invalid.status, "recoverable_error");
	assert.equal(invalid.error_code, "invalid_arguments");

	const stopped = await request("shutdown", {});
	assert.equal(stopped.status, "ok");
	assert.deepEqual(stopped.result, { stopped: true });
	console.log("Pi tool sidecar harness passed");
} finally {
	child.kill("SIGKILL");
	await inheritedSentinel.close();
	await rm(temporary, { recursive: true, force: true });
}
