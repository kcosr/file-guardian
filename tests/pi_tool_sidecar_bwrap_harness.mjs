import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";

const BWRAP = "/usr/bin/bwrap";
const PROTOCOL = "file-guardian-tool-sidecar/1";
const runnerSource = new URL("../src/analyzers/pi/assets/tool_sidecar_runner.js", import.meta.url);

function unavailable(result) {
	return (
		result.error !== undefined ||
		/operation not permitted|permission denied|no permissions to create new namespace|user namespaces? (?:are )?not (?:available|supported)/i.test(
			result.stderr ?? "",
		)
	);
}

assert.equal(unavailable({ error: { code: "ETIMEDOUT" }, stderr: "" }), true);
assert.equal(unavailable({ stderr: "bwrap: setting up uid map: Permission denied" }), true);
assert.equal(unavailable({ status: 1, stderr: "unexpected Bubblewrap failure" }), false);

const probe = spawnSync(
	BWRAP,
	[
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		"--assert-userns-disabled",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/",
		"/",
		"--",
		"/bin/true",
	],
	{ encoding: "utf8", timeout: 3_000 },
);
if (unavailable(probe)) {
	console.log("Pi Bubblewrap sidecar harness skipped: namespaces are unavailable");
	process.exit(0);
}
assert.equal(probe.status, 0, probe.stderr || "Bubblewrap probe failed");

function dynamicDependencies(executable) {
	const result = spawnSync("ldd", [executable], { encoding: "utf8", timeout: 3_000 });
	assert.equal(result.status, 0, result.stderr || `ldd failed for ${executable}`);
	const dependencies = new Set();
	for (const line of result.stdout.split("\n")) {
		const arrow = line.match(/=>\s+(\/\S+)\s+\(0x[0-9a-f]+\)/i);
		const direct = line.match(/^\s*(\/\S+)\s+\(0x[0-9a-f]+\)/i);
		const path = arrow?.[1] ?? direct?.[1];
		if (path) dependencies.add(path);
	}
	return dependencies;
}

const temporary = await mkdtemp(join(tmpdir(), "file-guardian-bwrap-sidecar-"));
const runtime = join(temporary, "runtime");
const runtimeBin = join(runtime, "bin");
const dependencyCopies = join(temporary, "dependencies");
const input = join(temporary, "input");
const outside = join(temporary, "outside-sentinel");
await Promise.all([
	mkdir(runtimeBin, { recursive: true, mode: 0o700 }),
	mkdir(dependencyCopies, { mode: 0o700 }),
	mkdir(input, { mode: 0o700 }),
]);
await Promise.all([
	copyFile(process.execPath, join(runtimeBin, "node")),
	copyFile("/bin/bash", join(runtimeBin, "bash")),
	writeFile(join(input, "artifact.txt"), "immutable\n", { mode: 0o400 }),
	writeFile(outside, "host-only\n", { mode: 0o600 }),
]);
await Promise.all([chmod(join(runtimeBin, "node"), 0o500), chmod(join(runtimeBin, "bash"), 0o500)]);

const dependencies = new Set([
	...dynamicDependencies(process.execPath),
	...dynamicDependencies("/bin/bash"),
]);
const libraryMounts = [];
let dependencyIndex = 0;
for (const target of [...dependencies].sort()) {
	const source = join(dependencyCopies, String(dependencyIndex++));
	await copyFile(target, source);
	// The ELF interpreter is one of these manifest-like dependency mounts and
	// must retain execute permission; using the same read/execute mode for the
	// shared libraries keeps the fixture simple and read-only in the sandbox.
	await chmod(source, 0o500);
	libraryMounts.push({ source, target });
}

const directoryTargets = new Set();
for (const { target } of libraryMounts) {
	let current = dirname(target);
	while (current !== "/") {
		directoryTargets.add(current);
		current = dirname(current);
	}
}
const libraryArguments = [];
for (const directory of [...directoryTargets].sort(
	(left, right) => left.split("/").length - right.split("/").length || left.localeCompare(right),
)) {
	libraryArguments.push("--dir", directory);
}
for (const { source, target } of libraryMounts) {
	libraryArguments.push("--ro-bind", source, target);
}

const server = createServer();
let hostConnectionObserved = false;
server.on("connection", (socket) => {
	hostConnectionObserved = true;
	socket.destroy();
});
await new Promise((resolvePromise, reject) => {
	server.once("error", reject);
	server.listen(0, "127.0.0.1", resolvePromise);
});
const address = server.address();
assert.ok(address && typeof address === "object");

const argumentsList = [
	"--unshare-all",
	"--unshare-user",
	"--disable-userns",
	"--assert-userns-disabled",
	"--die-with-parent",
	"--new-session",
	"--hostname",
	"file-guardian-tools",
	"--cap-drop",
	"ALL",
	"--tmpfs",
	"/",
	"--dir",
	"/runtime",
	"--dir",
	"/policy",
	"--dir",
	"/input",
	"--dir",
	"/work",
	"--dir",
	"/tmp",
	"--dev",
	"/dev",
	...libraryArguments,
	"--ro-bind",
	runtime,
	"/runtime",
	"--ro-bind",
	runnerSource.pathname,
	"/policy/tool-sidecar-runner.mjs",
	"--ro-bind",
	input,
	"/input",
	"--tmpfs",
	"/work",
	"--tmpfs",
	"/tmp",
	"--chdir",
	"/work",
	"--",
	"/runtime/bin/node",
	"/policy/tool-sidecar-runner.mjs",
];

const child = spawn(BWRAP, argumentsList, { env: {}, stdio: ["pipe", "pipe", "pipe"] });
const stderr = [];
child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
const lines = createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false });
const iterator = lines[Symbol.asyncIterator]();
let requestId = 0;

async function response() {
	const next = await iterator.next();
	assert.equal(next.done, false, Buffer.concat(stderr).toString("utf8"));
	return JSON.parse(next.value);
}

async function request(tool, params) {
	requestId += 1;
	child.stdin.write(`${JSON.stringify({ protocol: PROTOCOL, request_id: requestId, tool, params })}\n`);
	const value = await response();
	assert.equal(value.protocol, PROTOCOL);
	assert.equal(value.request_id, requestId);
	return value;
}

try {
	assert.deepEqual(await response(), { protocol: PROTOCOL, type: "ready" });

	const read = await request("read", { path: "artifact.txt", offset: 1, limit: 1 });
	assert.equal(read.status, "ok");
	assert.equal(read.result.text, "immutable");

	const isolatedRoot = await request("bash", {
		command:
			"test ! -e /proc/self/environ && test ! -e /etc/passwd && test ! -e /usr/bin/env && test ! -e /outside-sentinel",
	});
	assert.equal(isolatedRoot.status, "ok");
	assert.match(isolatedRoot.result.text, /\[exit 0\]$/);

	const immutableInput = await request("bash", { command: "printf changed > /input/artifact.txt" });
	assert.equal(immutableInput.status, "ok");
	assert.doesNotMatch(immutableInput.result.text, /\[exit 0\]$/);
	assert.equal(await readFile(join(input, "artifact.txt"), "utf8"), "immutable\n");

	const persistentWork = await request("bash", { command: "printf scratch > /work/state.txt" });
	assert.match(persistentWork.result.text, /\[exit 0\]$/);
	const reusedWork = await request("bash", {
		command: "IFS= read -r value < /work/state.txt; printf '%s\\n' \"$value\"",
	});
	assert.match(reusedWork.result.text, /^scratch\n+\[exit 0\]$/);

	const network = await request("bash", {
		command: `printf probe > /dev/tcp/127.0.0.1/${address.port}`,
	});
	assert.equal(network.status, "ok");
	assert.doesNotMatch(network.result.text, /\[exit 0\]$/);
	await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
	assert.equal(hostConnectionObserved, false);

	const stopped = await request("shutdown", {});
	assert.equal(stopped.status, "ok");
	child.stdin.end();
	await new Promise((resolvePromise, reject) => {
		child.once("close", resolvePromise);
		child.once("error", reject);
	});
	console.log("Pi Bubblewrap sidecar confinement harness passed");
} finally {
	child.kill("SIGKILL");
	server.close();
	await rm(temporary, { recursive: true, force: true });
}
