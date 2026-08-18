import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

const probe = spawnSync(
	BWRAP,
	[
		"--unshare-net",
		"--unshare-pid",
		"--die-with-parent",
		"--ro-bind",
		"/usr",
		"/usr",
		"--ro-bind",
		"/lib",
		"/lib",
		"--ro-bind",
		"/lib64",
		"/lib64",
		"--",
		"/usr/bin/true",
	],
	{ encoding: "utf8", timeout: 3_000 },
);
if (unavailable(probe)) {
	console.log("Pi Bubblewrap sidecar harness skipped: namespaces are unavailable");
	process.exit(0);
}
assert.equal(probe.status, 0, probe.stderr || "Bubblewrap probe failed");

const temporary = await mkdtemp(join(tmpdir(), "file-guardian-bwrap-sidecar-"));
const input = join(temporary, "input");
const outside = join(temporary, "outside-sentinel");
const agent = join(temporary, "agent");
const proxy = join(temporary, "proxy");
await Promise.all([
	mkdir(input, { mode: 0o700 }),
	mkdir(agent, { mode: 0o700 }),
	mkdir(proxy, { mode: 0o700 }),
]);
await Promise.all([
	writeFile(join(input, "artifact.txt"), "immutable\n", { mode: 0o400 }),
	writeFile(outside, "outside sparse runtime\n", { mode: 0o600 }),
	writeFile(join(agent, "provider-auth.json"), "synthetic provider state\n", { mode: 0o600 }),
	writeFile(join(proxy, "control-token"), "synthetic control state\n", { mode: 0o600 }),
]);
const gitInit = spawnSync("git", ["init", "-q", "-b", "main", input], { encoding: "utf8" });
assert.equal(gitInit.status, 0, gitInit.stderr);
const gitAdd = spawnSync("git", ["-C", input, "add", "artifact.txt"], { encoding: "utf8" });
assert.equal(gitAdd.status, 0, gitAdd.stderr);
const gitCommit = spawnSync("git", ["-C", input, "commit", "-q", "-m", "fixture"], {
	encoding: "utf8",
	env: {
		...process.env,
		GIT_AUTHOR_NAME: "File Guardian Fixture",
		GIT_AUTHOR_EMAIL: "fixture@example.invalid",
		GIT_COMMITTER_NAME: "File Guardian Fixture",
		GIT_COMMITTER_EMAIL: "fixture@example.invalid",
	},
});
assert.equal(gitCommit.status, 0, gitCommit.stderr);

const nodeRoot = dirname(dirname(process.execPath));
const nodeParents = [];
let parent = dirname(nodeRoot);
while (parent !== "/") {
	nodeParents.unshift(parent);
	parent = dirname(parent);
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
	"--unshare-net",
	"--unshare-pid",
	"--die-with-parent",
	"--new-session",
	"--tmpfs",
	"/",
	"--ro-bind",
	"/usr",
	"/usr",
	"--ro-bind",
	"/bin",
	"/bin",
	"--ro-bind",
	"/lib",
	"/lib",
	"--ro-bind",
	"/lib64",
	"/lib64",
	"--ro-bind",
	"/etc",
	"/etc",
	...nodeParents.flatMap((directory) => ["--dir", directory]),
	"--ro-bind",
	nodeRoot,
	nodeRoot,
	"--dir",
	"/policy",
	"--ro-bind",
	runnerSource.pathname,
	"/policy/tool-sidecar-runner.mjs",
	"--ro-bind",
	input,
	"/input",
	"--ro-bind",
	agent,
	"/agent",
	"--ro-bind",
	proxy,
	"/proxy",
	"--tmpfs",
	"/agent",
	"--tmpfs",
	"/proxy",
	"--tmpfs",
	"/work",
	"--tmpfs",
	"/tmp",
	"--proc",
	"/proc",
	"--dev",
	"/dev",
	"--chdir",
	"/work",
	"--setenv",
	"FILE_GUARDIAN_INPUT_ROOT",
	"/input",
	"--setenv",
	"FILE_GUARDIAN_WORK_ROOT",
	"/work",
	"--setenv",
	"FILE_GUARDIAN_TOOL_PATH",
	"/usr/local/bin:/usr/bin:/bin",
	"--",
	process.execPath,
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

	const normalRuntime = await request("bash", {
		command:
			"test -r /etc/passwd && test -x /usr/bin/env && test ! -e /outside-sentinel && test ! -e /agent/provider-auth.json && test ! -e /proxy/control-token",
	});
	assert.match(normalRuntime.result.text, /\[exit 0\]$/);

	const gitHistory = await request("bash", {
		command: "git -C /input rev-parse --verify HEAD && git -C /input log -1 --format=%s",
	});
	assert.match(gitHistory.result.text, /fixture/);
	assert.match(gitHistory.result.text, /\[exit 0\]$/);

	const immutableInput = await request("bash", { command: "printf changed > /input/artifact.txt" });
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
