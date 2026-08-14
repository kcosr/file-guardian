// Persistent, networkless File Guardian tool runner.
//
// The trusted Pi extension starts this program as the sole command inside a
// Bubblewrap sandbox. stdin/stdout carry one JSON request/response per line;
// command output is captured and never shares the protocol stream.

import { spawn } from "node:child_process";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { createInterface } from "node:readline";
import { isAbsolute, relative, resolve, sep } from "node:path";

const PROTOCOL = "file-guardian-tool-sidecar/1";
const testRoots = process.argv[2] === "--test-roots" ? process.argv.slice(3, 6) : null;
if (testRoots && (testRoots.length !== 3 || testRoots.some((root) => !isAbsolute(root)))) {
	throw new Error("invalid sidecar test roots");
}
const INPUT_ROOT = testRoots?.[0] ?? "/input";
const WORK_ROOT = testRoots?.[1] ?? "/work";
const RUNTIME_ROOT = testRoots?.[2] ?? "/runtime";
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_COMMAND_CHARACTERS = 16 * 1024;
const MAX_PATH_CHARACTERS = 4096;
const MAX_READ_FILE_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const COMMAND_TIMEOUT_MILLIS = 10_000;
const MAX_READ_LINES = 2000;
const MAX_SEARCH_RESULTS = 10_000;

const COMMAND_ENVIRONMENT = Object.freeze({
	HOME: WORK_ROOT,
	LANG: "C",
	LC_ALL: "C",
	MAGIC: `${RUNTIME_ROOT}/share/misc/magic.mgc`,
	PATH: `${RUNTIME_ROOT}/bin`,
	TMPDIR: "/tmp",
});

class RecoverableError extends Error {
	constructor(message) {
		super(message);
		this.name = "RecoverableError";
	}
}

function exactObject(value, keys) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function integer(value, minimum, maximum) {
	return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function boundedString(value, minimum, maximum) {
	return typeof value === "string" && value.length >= minimum && value.length <= maximum && !value.includes("\0");
}

function runtimeExecutable(name) {
	return resolve(RUNTIME_ROOT, "bin", name);
}

function isContained(root, candidate) {
	const rel = relative(root, candidate);
	return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

async function resolveInputPath(rawPath, expectedKind) {
	if (
		!boundedString(rawPath, 1, MAX_PATH_CHARACTERS) ||
		isAbsolute(rawPath) ||
		rawPath.startsWith("~") ||
		rawPath.startsWith("@") ||
		rawPath.split("/").includes("..")
	) {
		throw new RecoverableError("Path must be relative to the immutable input.");
	}
	const root = await realpath(INPUT_ROOT);
	const lexical = resolve(INPUT_ROOT, rawPath);
	if (!isContained(INPUT_ROOT, lexical)) throw new RecoverableError("Path is outside the immutable input.");
	let current = INPUT_ROOT;
	for (const part of relative(INPUT_ROOT, lexical).split(sep).filter(Boolean)) {
		current = resolve(current, part);
		const metadata = await lstat(current);
		if (metadata.isSymbolicLink()) throw new RecoverableError("Symbolic links are not accepted.");
	}
	const canonical = await realpath(lexical);
	if (!isContained(root, canonical)) throw new RecoverableError("Path is outside the immutable input.");
	const metadata = await lstat(canonical);
	if (expectedKind === "file" && !metadata.isFile()) throw new RecoverableError("Path is not a file.");
	if (expectedKind === "directory" && !metadata.isDirectory()) throw new RecoverableError("Path is not a directory.");
	if (expectedKind === "file_or_directory" && !metadata.isFile() && !metadata.isDirectory()) {
		throw new RecoverableError("Path is not a file or directory.");
	}
	return {
		absolute: canonical,
		relative: relative(root, canonical).split(sep).join("/") || ".",
		metadata,
	};
}

function truncateUtf8(buffer, maximumBytes) {
	if (buffer.length <= maximumBytes) return { text: buffer.toString("utf8"), truncated: false };
	let end = maximumBytes;
	while (end > 0 && (buffer[end] & 0xc0) === 0x80) end--;
	return { text: buffer.subarray(0, end).toString("utf8"), truncated: true };
}

function runCommand(program, argumentsList, { cwd = WORK_ROOT, acceptedExitCodes = null } = {}) {
	return new Promise((resolvePromise, reject) => {
		let stdout = Buffer.alloc(0);
		let stderr = Buffer.alloc(0);
		let truncated = false;
		let timedOut = false;
		let settled = false;
		const child = spawn(program, argumentsList, {
			cwd,
			detached: true,
			env: COMMAND_ENVIRONMENT,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const killGroup = () => {
			if (child.pid) {
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch {
					// The group may already be gone.
				}
			}
		};
		const timer = setTimeout(() => {
			timedOut = true;
			killGroup();
		}, COMMAND_TIMEOUT_MILLIS);
		const collect = (current, chunk) => {
			if (current.length >= MAX_OUTPUT_BYTES) {
				truncated = true;
				killGroup();
				return current;
			}
			const remaining = MAX_OUTPUT_BYTES - current.length;
			if (chunk.length > remaining) {
				truncated = true;
				killGroup();
			}
			return Buffer.concat([current, chunk.subarray(0, remaining)]);
		};
		child.stdout.on("data", (chunk) => {
			stdout = collect(stdout, Buffer.from(chunk));
		});
		child.stderr.on("data", (chunk) => {
			stderr = collect(stderr, Buffer.from(chunk));
		});
		child.once("error", () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			killGroup();
			reject(new Error("sandbox command could not be started"));
		});
		child.once("exit", killGroup);
		child.once("close", (code, signal) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			killGroup();
			const stdoutResult = truncateUtf8(stdout, MAX_OUTPUT_BYTES);
			const stderrResult = truncateUtf8(stderr, MAX_OUTPUT_BYTES);
			const result = {
				exit_code: code,
				signal: signal ?? null,
				stdout: stdoutResult.text,
				stderr: stderrResult.text,
				timed_out: timedOut,
				truncated: truncated || stdoutResult.truncated || stderrResult.truncated,
			};
			if (acceptedExitCodes && !acceptedExitCodes.has(code)) {
				reject(new RecoverableError("Command arguments were rejected. Revise them and retry."));
				return;
			}
			resolvePromise(result);
		});
	});
}

function formatCommandResult(result) {
	const sections = [];
	if (result.stdout) sections.push(result.stdout);
	if (result.stderr) sections.push(`[stderr]\n${result.stderr}`);
	sections.push(`[exit ${result.exit_code ?? result.signal ?? "unknown"}${result.timed_out ? "; timed out" : ""}${result.truncated ? "; output truncated" : ""}]`);
	return truncateUtf8(Buffer.from(sections.join("\n"), "utf8"), MAX_OUTPUT_BYTES).text;
}

function commandDetails(result) {
	return {
		exit_code: result.exit_code,
		signal: result.signal,
		timed_out: result.timed_out,
		truncated: result.truncated,
	};
}

async function execute(request) {
	if (!exactObject(request, ["protocol", "request_id", "tool", "params"]) || request.protocol !== PROTOCOL || !integer(request.request_id, 1, Number.MAX_SAFE_INTEGER)) {
		throw new Error("invalid sidecar request envelope");
	}
	const params = request.params;
	switch (request.tool) {
		case "bash": {
			if (!exactObject(params, ["command"]) || !boundedString(params.command, 1, MAX_COMMAND_CHARACTERS)) throw new RecoverableError("Bash requires a bounded command.");
			const command = await runCommand(runtimeExecutable("bash"), ["--noprofile", "--norc", "-c", params.command]);
			return { path: ".", text: formatCommandResult(command), result_count: 1, details: commandDetails(command) };
		}
		case "read": {
			if (!exactObject(params, ["path", "offset", "limit"]) || !integer(params.offset, 1, Number.MAX_SAFE_INTEGER) || !integer(params.limit, 1, MAX_READ_LINES)) throw new RecoverableError("Read arguments are invalid.");
			const path = await resolveInputPath(params.path, "file");
			if (path.metadata.size > MAX_READ_FILE_BYTES) throw new RecoverableError("File exceeds the read limit; use grep or bash streaming tools.");
			const content = new TextDecoder("utf-8", { fatal: true }).decode(await readFile(path.absolute));
			const lines = content.split("\n");
			const start = params.offset - 1;
			if (start >= lines.length) throw new RecoverableError("Read offset is beyond end of file.");
			const selected = lines.slice(start, Math.min(start + params.limit, lines.length)).join("\n");
			const bounded = truncateUtf8(Buffer.from(selected, "utf8"), MAX_OUTPUT_BYTES);
			return { path: path.relative, text: bounded.text, result_count: 1, details: { truncated: bounded.truncated } };
		}
		case "grep": {
			if (!exactObject(params, ["pattern", "path", "glob", "ignore_case", "literal", "context", "limit"]) || !boundedString(params.pattern, 1, 4096) || !integer(params.context, 0, 20) || !integer(params.limit, 1, MAX_SEARCH_RESULTS)) throw new RecoverableError("Grep arguments are invalid.");
			const path = await resolveInputPath(params.path, "file_or_directory");
			const args = ["--line-number", "--with-filename", "--color=never", "--hidden", "--no-ignore", "--max-count", String(params.limit)];
			if (params.ignore_case) args.push("--ignore-case");
			if (params.literal) args.push("--fixed-strings");
			if (params.glob !== null) args.push("--glob", params.glob);
			if (params.context > 0) args.push("--context", String(params.context));
			args.push("--", params.pattern, path.relative);
			const result = await runCommand(runtimeExecutable("rg"), args, { cwd: INPUT_ROOT, acceptedExitCodes: new Set([0, 1]) });
			const resultLines = result.stdout === "" ? [] : result.stdout.replace(/\n$/, "").split("\n");
			if (resultLines.length > params.limit) {
				result.stdout = resultLines.slice(0, params.limit).join("\n");
				result.truncated = true;
			}
			const text = formatCommandResult(result);
			return { path: path.relative, text, result_count: Math.min(resultLines.length, params.limit), details: commandDetails(result) };
		}
		case "find": {
			if (!exactObject(params, ["pattern", "path", "limit"]) || !boundedString(params.pattern, 1, 1024) || !integer(params.limit, 1, MAX_SEARCH_RESULTS)) throw new RecoverableError("Find arguments are invalid.");
			const path = await resolveInputPath(params.path, "directory");
			const result = await runCommand(runtimeExecutable("fd"), ["--glob", "--color=never", "--hidden", "--no-ignore", "--max-results", String(params.limit), "--", params.pattern, path.relative], { cwd: INPUT_ROOT, acceptedExitCodes: new Set([0]) });
			const text = formatCommandResult(result);
			return { path: path.relative, text, result_count: result.stdout ? result.stdout.replace(/\n$/, "").split("\n").length : 0, details: commandDetails(result) };
		}
		case "ls": {
			if (!exactObject(params, ["path", "limit"]) || !integer(params.limit, 1, MAX_SEARCH_RESULTS)) throw new RecoverableError("List arguments are invalid.");
			const path = await resolveInputPath(params.path, "directory");
			const entries = await readdir(path.absolute, { withFileTypes: true });
			entries.sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
			const selected = entries.slice(0, params.limit).map((entry) => `${entry.name}${entry.isDirectory() ? "/" : ""}`);
			const bounded = truncateUtf8(Buffer.from(selected.join("\n") || "(empty directory)", "utf8"), MAX_OUTPUT_BYTES);
			return { path: path.relative, text: bounded.text, result_count: selected.length, details: { truncated: bounded.truncated || entries.length > params.limit } };
		}
		default:
			throw new Error("unsupported sidecar tool");
	}
}

function writeResponse(value) {
	process.stdout.write(`${JSON.stringify(value)}\n`);
}

writeResponse({ protocol: PROTOCOL, type: "ready" });
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
for await (const line of lines) {
	if (Buffer.byteLength(line, "utf8") > MAX_REQUEST_BYTES) {
		writeResponse({ protocol: PROTOCOL, request_id: null, status: "fatal_error", error_code: "invalid_request" });
		process.exitCode = 1;
		break;
	}
	let request;
	try {
		request = JSON.parse(line);
	} catch {
		writeResponse({ protocol: PROTOCOL, request_id: null, status: "fatal_error", error_code: "invalid_request" });
		process.exitCode = 1;
		break;
	}
	if (exactObject(request, ["protocol", "request_id", "tool", "params"]) && request.protocol === PROTOCOL && request.tool === "shutdown" && exactObject(request.params, [])) {
		writeResponse({ protocol: PROTOCOL, request_id: request.request_id, status: "ok", result: { stopped: true } });
		break;
	}
	try {
		const result = await execute(request);
		writeResponse({ protocol: PROTOCOL, request_id: request.request_id, status: "ok", result });
	} catch (error) {
		if (error instanceof RecoverableError) {
			writeResponse({ protocol: PROTOCOL, request_id: request?.request_id ?? null, status: "recoverable_error", error_code: "invalid_arguments", message: error.message });
			continue;
		}
		writeResponse({ protocol: PROTOCOL, request_id: request?.request_id ?? null, status: "fatal_error", error_code: "execution_failed" });
		process.exitCode = 1;
		break;
	}
}
