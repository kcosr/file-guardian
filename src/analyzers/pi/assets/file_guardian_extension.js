// Trusted File Guardian classifier extension for Pi 0.83.0.
//
// Pi's built-ins remain disabled. This extension exposes a familiar read-only
// coding-agent surface over the immutable analyzer view mounted at /input.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { createConnection } from "node:net";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { VERSION } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PROTOCOL = "file-guardian-pi-proxy/2";
const INPUT_ROOT = "/input";
const RG = "/runtime/bin/rg";
const FD = "/runtime/bin/fd";
const MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PATH_CHARACTERS = 4096;
const MAX_NATIVE_READ_FILE_BYTES = 1024 * 1024;
const MAX_NATIVE_TOOL_OUTPUT_BYTES = 64 * 1024;
const MAX_NATIVE_NOTICE_BYTES = 256;
const MAX_READ_LINES = 2000;
const MAX_CONFIGURED_SEARCH_RESULTS = 10000;
const DEFAULT_GREP_MATCHES = 100;
const DEFAULT_FIND_RESULTS = 1000;
const DEFAULT_LS_ENTRIES = 500;
const MAX_HELPER_STDERR_BYTES = 4096;
const HELPER_TIMEOUT_MILLIS = 10000;
const MAX_GREP_COLUMNS = 4096;
const REQUIRED_TOOLS = Object.freeze([
	"find",
	"grep",
	"ls",
	"manifest_list",
	"prior_observations",
	"read",
	"submit_classification",
]);
const NATIVE_TOOLS = new Set(["read", "grep", "find", "ls"]);

const socketPath = requiredEnvironment("FILE_GUARDIAN_PI_PROXY_SOCKET");
const runToken = requiredEnvironment("FILE_GUARDIAN_PI_RUN_TOKEN");
const runId = requiredEnvironment("FILE_GUARDIAN_PI_RUN_ID");
const manifestIdentity = requiredEnvironment("FILE_GUARDIAN_PI_MANIFEST_IDENTITY");
const analyzerId = requiredEnvironment("FILE_GUARDIAN_PI_ANALYZER_ID");
const maxSearchResults = requiredBoundedIntegerEnvironment(
	"FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
	MAX_CONFIGURED_SEARCH_RESULTS,
);

let nextRequestId = 1;
let terminalState = "open";
let runtimeInstruction;
let integrityFailure;
let nextManifestCursor = 0;

function requiredEnvironment(name) {
	const value = process.env[name];
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`missing required File Guardian runtime setting: ${name}`);
	}
	return value;
}

function requiredBoundedIntegerEnvironment(name, maximum) {
	const value = requiredEnvironment(name);
	if (!/^[1-9][0-9]*$/.test(value)) {
		throw new Error(`invalid File Guardian integer runtime setting: ${name}`);
	}
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed > maximum) {
		throw new Error(`invalid File Guardian integer runtime setting: ${name}`);
	}
	return parsed;
}

function strictObject(properties, options = {}) {
	return Type.Object(properties, { ...options, additionalProperties: false });
}

function safeErrorCode(value) {
	return typeof value === "string" && /^[a-z0-9_]{1,128}$/.test(value)
		? value
		: "invalid_proxy_response";
}

function hasExactKeys(value, keys) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function requireAccepted(result) {
	if (!hasExactKeys(result, ["accepted"]) || result.accepted !== true) {
		throw new Error("File Guardian proxy omitted operation acceptance");
	}
}

function proxyRequest(type, fields = {}, signal) {
	if (integrityFailure) return Promise.reject(integrityFailure);
	if (terminalState !== "open" && type !== "submit_classification") {
		return Promise.reject(new Error("classification has already been submitted"));
	}

	const requestId = nextRequestId++;
	const request = {
		...fields,
		protocol: PROTOCOL,
		run_token: runToken,
		run_id: runId,
		manifest_identity: manifestIdentity,
		request_id: requestId,
		analyzer_id: analyzerId,
		type,
	};

	return new Promise((resolvePromise, reject) => {
		let settled = false;
		let receivedBytes = 0;
		let responseText = "";
		const socket = createConnection({ path: socketPath });

		const finish = (callback, value) => {
			if (settled) return;
			settled = true;
			signal?.removeEventListener("abort", abort);
			socket.destroy();
			callback(value);
		};
		const fail = (message) => finish(reject, new Error(message));
		const abort = () => fail("File Guardian proxy request aborted");

		if (signal?.aborted) {
			abort();
			return;
		}
		signal?.addEventListener("abort", abort, { once: true });

		socket.setEncoding("utf8");
		socket.once("connect", () => socket.end(`${JSON.stringify(request)}\n`));
		socket.on("data", (chunk) => {
			receivedBytes += Buffer.byteLength(chunk, "utf8");
			if (receivedBytes > MAX_PROXY_RESPONSE_BYTES) {
				fail("File Guardian proxy response exceeded its extension limit");
				return;
			}
			responseText += chunk;
		});
		socket.once("error", () => fail("File Guardian proxy transport failed"));
		socket.once("end", () => {
			if (settled) return;
			let response;
			try {
				response = JSON.parse(responseText);
			} catch {
				fail("File Guardian proxy returned invalid JSON");
				return;
			}

			if (response?.protocol !== PROTOCOL || response.request_id !== requestId) {
				fail("File Guardian proxy returned a mismatched response");
				return;
			}
			if (
				response.status === "error" &&
				hasExactKeys(response, ["protocol", "request_id", "status", "error"]) &&
				hasExactKeys(response.error, ["code"])
			) {
				fail(`File Guardian proxy rejected request: ${safeErrorCode(response.error?.code)}`);
				return;
			}
			if (
				response.status !== "ok" ||
				!hasExactKeys(response, ["protocol", "request_id", "status", "result"])
			) {
				fail("File Guardian proxy returned an invalid response shape");
				return;
			}
			finish(resolvePromise, response.result);
		});
	});
}

function toolResult(text, details = {}) {
	return { content: [{ type: "text", text }], details };
}

function proxyToolResult(result) {
	return toolResult(JSON.stringify(result));
}

function manifestPageResult(result, cursor) {
	if (
		!hasExactKeys(result, ["schema", "manifest_identity", "cursor", "total_count", "entries", "next_cursor"]) ||
		result.schema !== "file-guardian-pi-manifest-page/1" ||
		result.manifest_identity !== manifestIdentity ||
		result.cursor !== cursor ||
		!Number.isSafeInteger(result.total_count) ||
		result.total_count < 0 ||
		!Array.isArray(result.entries) ||
		!(result.next_cursor === null || Number.isSafeInteger(result.next_cursor))
	) {
		throw new Error("File Guardian proxy returned an invalid manifest page");
	}
	const pageEnd = cursor + result.entries.length;
	if (
		!Number.isSafeInteger(pageEnd) ||
		pageEnd > result.total_count ||
		(result.next_cursor === null
			? pageEnd !== result.total_count
			: result.entries.length === 0 || result.next_cursor !== pageEnd)
	) {
		throw new Error("File Guardian proxy returned a discontinuous manifest page");
	}
	return result;
}

function consumeManifestPage(result) {
	const page = manifestPageResult(result, nextManifestCursor);
	nextManifestCursor = page.next_cursor ?? page.total_count;
	return page;
}

function latchIntegrityFailure() {
	integrityFailure ??= new Error("Pi read-only tool integrity check failed");
}

class RecoverableNativeToolError extends Error {
	constructor(message) {
		super(message);
		this.name = "RecoverableNativeToolError";
	}
}

function readLineWindow(content, offset, limit) {
	const lines = content.split("\n");
	const start = offset - 1;
	if (start >= lines.length) {
		throw new RecoverableNativeToolError("Read offset is beyond end of file. Revise it and retry.");
	}
	return lines.slice(start, Math.min(start + limit, lines.length)).join("\n");
}

function normalizedToolCallId(value) {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_PATH_CHARACTERS ||
		Buffer.byteLength(value, "utf8") > MAX_PATH_CHARACTERS ||
		/[\u0000-\u001f\u007f-\u009f]/.test(value)
	) {
		throw new Error("invalid tool call identity");
	}
	return `tc_${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function isContained(root, candidate) {
	const rel = relative(root, candidate);
	return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

async function resolveInputPath(rawPath, expectedKind) {
	if (
		typeof rawPath !== "string" ||
		rawPath.length === 0 ||
		rawPath.length > MAX_PATH_CHARACTERS ||
		Buffer.byteLength(rawPath, "utf8") > MAX_PATH_CHARACTERS ||
		rawPath.includes("\0") ||
		isAbsolute(rawPath) ||
		rawPath.startsWith("~") ||
		rawPath.startsWith("@") ||
		rawPath.split("/").includes("..")
	) {
		throw new Error("path is outside the analyzer input");
	}

	const root = await realpath(INPUT_ROOT);
	const lexical = resolve(INPUT_ROOT, rawPath);
	if (!isContained(INPUT_ROOT, lexical)) {
		throw new Error("path is outside the analyzer input");
	}

	let current = INPUT_ROOT;
	const relativeParts = relative(INPUT_ROOT, lexical).split(sep).filter(Boolean);
	for (const part of relativeParts) {
		current = resolve(current, part);
		const metadata = await lstat(current);
		if (metadata.isSymbolicLink()) throw new Error("symbolic links are not allowed in analyzer input");
	}

	const canonical = await realpath(lexical);
	if (!isContained(root, canonical)) {
		throw new Error("path is outside the analyzer input");
	}
	const metadata = await lstat(canonical);
	if (expectedKind === "file" && !metadata.isFile()) throw new Error("path is not a regular file");
	if (expectedKind === "directory" && !metadata.isDirectory()) throw new Error("path is not a directory");
	if (expectedKind === "file_or_directory" && !metadata.isFile() && !metadata.isDirectory()) {
		throw new Error("path is not a regular file or directory");
	}

	const normalizedRelative = relative(root, canonical).split(sep).join("/") || ".";
	return { absolute: canonical, relative: normalizedRelative, metadata };
}

async function finishNativeTool(
	toolCallId,
	tool,
	path,
	outcome,
	errorCode,
	outputBytes,
	resultCount,
	signal,
) {
	try {
		const result = await proxyRequest(
			"native_tool_end",
			{
				tool_call_id: toolCallId,
				tool,
				path,
				outcome,
				error_code: errorCode,
				output_bytes: outputBytes,
				result_count: resultCount,
			},
			signal,
		);
		requireAccepted(result);
	} catch {
		latchIntegrityFailure();
		throw integrityFailure;
	}
}

async function executeNativeTool(toolCallIdValue, tool, relativePath, signal, operation) {
	let toolCallId;
	try {
		toolCallId = normalizedToolCallId(toolCallIdValue);
	} catch {
		latchIntegrityFailure();
		throw integrityFailure;
	}
	try {
		const result = await proxyRequest(
			"native_tool_begin",
			{ tool_call_id: toolCallId, tool, path: relativePath },
			signal,
		);
		requireAccepted(result);
	} catch {
		latchIntegrityFailure();
		throw integrityFailure;
	}

	try {
		const result = await operation();
		const outputBytes = Buffer.byteLength(result.text, "utf8");
		if (
			outputBytes > MAX_NATIVE_TOOL_OUTPUT_BYTES ||
			!Number.isSafeInteger(result.resultCount) ||
			result.resultCount < 0
		) {
			throw new Error("native tool returned an invalid bounded result");
		}
		await finishNativeTool(
			toolCallId,
			tool,
			relativePath,
			"completed",
			null,
			outputBytes,
			result.resultCount,
			signal,
		);
		return toolResult(result.text, result.details);
	} catch (error) {
		if (error instanceof RecoverableNativeToolError) {
			await finishNativeTool(
				toolCallId,
				tool,
				relativePath,
				"recoverable_error",
				"invalid_arguments",
				0,
				0,
				signal,
			);
			return toolResult(error.message, { recoverable: true, errorCode: "invalid_arguments" });
		}
		if (error === integrityFailure) throw error;
		try {
			await finishNativeTool(
				toolCallId,
				tool,
				relativePath,
				"fatal_error",
				"execution_failed",
				0,
				0,
				signal,
			);
		} finally {
			latchIntegrityFailure();
		}
		throw integrityFailure;
	}
}

function truncateUtf8(value, maximumBytes) {
	const bytes = Buffer.from(value, "utf8");
	if (bytes.length <= maximumBytes) return { text: value, truncated: false };
	let end = maximumBytes;
	while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
	return { text: bytes.subarray(0, end).toString("utf8"), truncated: true };
}

function boundedLineOutput(lines, emptyText, logicalLimitReached, logicalLimit, logicalKind) {
	const maximumDataBytes = MAX_NATIVE_TOOL_OUTPUT_BYTES - MAX_NATIVE_NOTICE_BYTES;
	const accepted = [];
	let acceptedBytes = 0;
	let outputByteLimitReached = false;
	for (const line of lines) {
		const separatorBytes = accepted.length === 0 ? 0 : 1;
		const lineBytes = Buffer.byteLength(line, "utf8");
		if (acceptedBytes + separatorBytes + lineBytes > maximumDataBytes) {
			outputByteLimitReached = true;
			break;
		}
		accepted.push(line);
		acceptedBytes += separatorBytes + lineBytes;
	}
	const notice = outputByteLimitReached
		? `\n\n[Truncated: ${MAX_NATIVE_TOOL_OUTPUT_BYTES} output byte limit]`
		: logicalLimitReached
			? `\n\n[Truncated: ${logicalLimit} ${logicalKind} limit]`
			: "";
	return {
		text: `${accepted.join("\n") || emptyText}${notice}`,
		resultCount: accepted.length,
		details: outputByteLimitReached
			? { outputByteLimitReached: MAX_NATIVE_TOOL_OUTPUT_BYTES }
			: logicalLimitReached
				? { [`${logicalKind}LimitReached`]: logicalLimit }
				: {},
	};
}

function runHelper(
	program,
	argumentsList,
	signal,
	acceptedExitCodes,
	recoverableExitCodes,
	resultLimit,
	limitKind,
) {
	return new Promise((resolvePromise, reject) => {
		let settled = false;
		let stdout = Buffer.alloc(0);
		let stderrBytes = 0;
		let completeLineCount = 0;
		let killedForResultLimit = false;
		let killedForOutputLimit = false;
		const child = spawn(program, argumentsList, {
			cwd: INPUT_ROOT,
			env: {},
			stdio: ["ignore", "pipe", "pipe"],
		});

		const timer = setTimeout(() => fail("helper timed out"), HELPER_TIMEOUT_MILLIS);
		const cleanup = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
		};
		const finish = (callback, value) => {
			if (settled) return;
			settled = true;
			cleanup();
			callback(value);
		};
		const kill = () => {
			if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
		};
		const fail = (message) => {
			kill();
			finish(reject, new Error(message));
		};
		const abort = () => fail("helper aborted");

		if (signal?.aborted) {
			abort();
			return;
		}
		signal?.addEventListener("abort", abort, { once: true });
		child.once("error", () => fail("helper failed to start"));
		child.stdout.on("data", (chunk) => {
			if (settled || killedForResultLimit || killedForOutputLimit) return;
			const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			const maximumDataBytes = MAX_NATIVE_TOOL_OUTPUT_BYTES - MAX_NATIVE_NOTICE_BYTES;
			const remaining = maximumDataBytes - stdout.length;
			stdout = Buffer.concat([stdout, bytes.subarray(0, Math.max(remaining, 0))]);
			completeLineCount += bytes
				.subarray(0, Math.max(remaining, 0))
				.reduce((count, byte) => count + (byte === 0x0a ? 1 : 0), 0);
			if (bytes.length > remaining) {
				killedForOutputLimit = true;
				kill();
			} else if (completeLineCount >= resultLimit) {
				killedForResultLimit = true;
				kill();
			}
		});
		child.stderr.on("data", (chunk) => {
			stderrBytes += chunk.length;
			if (stderrBytes > MAX_HELPER_STDERR_BYTES) fail("helper diagnostic exceeded its limit");
		});
		child.once("close", (code) => {
			if (settled) return;
			if (!killedForResultLimit && !killedForOutputLimit && recoverableExitCodes.has(code)) {
				finish(reject, new RecoverableNativeToolError("Invalid search arguments. Revise them and retry."));
				return;
			}
			if (!killedForResultLimit && !killedForOutputLimit && !acceptedExitCodes.has(code)) {
				fail("helper exited unsuccessfully");
				return;
			}
			let rawText = stdout.toString("utf8").replace(/\r\n/g, "\n");
			if (killedForOutputLimit) {
				const lastCompleteLine = rawText.lastIndexOf("\n");
				rawText = lastCompleteLine < 0 ? "" : rawText.slice(0, lastCompleteLine);
			}
			const lines = (rawText === "" ? [] : rawText.replace(/\n$/, "").split("\n")).slice(
				0,
				resultLimit,
			);
			const resultLimitReached = killedForResultLimit || lines.length >= resultLimit;
			const notice = killedForOutputLimit
				? `\n\n[Truncated: ${MAX_NATIVE_TOOL_OUTPUT_BYTES} output byte limit]`
				: resultLimitReached
					? `\n\n[Truncated: ${resultLimit} ${limitKind} limit]`
					: "";
			finish(resolvePromise, {
				text: `${lines.join("\n") || "No results found"}${notice}`,
				resultCount: lines.length,
				details: killedForOutputLimit
					? { outputByteLimitReached: MAX_NATIVE_TOOL_OUTPUT_BYTES }
					: resultLimitReached
						? { [`${limitKind}LimitReached`]: resultLimit }
						: {},
			});
		});
	});
}

const RelativePath = Type.String({ minLength: 1, maxLength: MAX_PATH_CHARACTERS });

const ReadParameters = strictObject({
	path: RelativePath,
	offset: Type.Optional(Type.Integer({ minimum: 1, maximum: Number.MAX_SAFE_INTEGER })),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: MAX_READ_LINES })),
});

const GrepParameters = strictObject({
	pattern: Type.String({ minLength: 1, maxLength: 4096 }),
	path: Type.Optional(RelativePath),
	glob: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })),
	ignoreCase: Type.Optional(Type.Boolean()),
	literal: Type.Optional(Type.Boolean()),
	context: Type.Optional(Type.Integer({ minimum: 0, maximum: 20 })),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: maxSearchResults })),
});

const FindParameters = strictObject({
	pattern: Type.String({ minLength: 1, maxLength: 1024 }),
	path: Type.Optional(RelativePath),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: maxSearchResults })),
});

const LsParameters = strictObject({
	path: Type.Optional(RelativePath),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: maxSearchResults })),
});

const ArtifactId = Type.String({ minLength: 3, maxLength: 128, pattern: "^a_[A-Za-z0-9_.:-]{1,126}$" });
const SafeCode = Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9_.:/-]+$" });
const ReasonCodes = Type.Array(SafeCode, { maxItems: 256, uniqueItems: true });
const SubjectArtifactIds = Type.Array(ArtifactId, { maxItems: 100000, uniqueItems: true });

const Classification = strictObject({
	code: SafeCode,
	confidence: SafeCode,
	reason_codes: ReasonCodes,
	subject_artifact_ids: SubjectArtifactIds,
});

const ArtifactClassification = strictObject({
	artifact_id: ArtifactId,
	code: SafeCode,
	confidence: SafeCode,
	reason_codes: ReasonCodes,
});

const TerminalClassification = strictObject({
	schema_version: Type.Literal("file-guardian-pi-classifier/1"),
	status: Type.Literal("complete"),
	manifest_identity: Type.String({ minLength: 71, maxLength: 71, pattern: "^sha256:[0-9a-f]{64}$" }),
	classification: Classification,
	artifact_classifications: Type.Array(ArtifactClassification, { maxItems: 100000 }),
	coverage: strictObject({
		assigned_artifact_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
		status: Type.Literal("complete"),
	}),
});

export default function fileGuardianClassifierExtension(pi) {
	function assertExactToolGrant() {
		const activeTools = [...pi.getActiveTools()].sort();
		if (
			activeTools.length !== REQUIRED_TOOLS.length ||
			activeTools.some((tool, index) => tool !== REQUIRED_TOOLS[index])
		) {
			throw new Error("Pi active tool set does not match the File Guardian grant");
		}
		return activeTools;
	}

	pi.registerTool({
		name: "read",
		label: "read",
		description: "Read a UTF-8 text file from the immutable analyzer input. Use offset and limit for large files.",
		parameters: ReadParameters,
		executionMode: "sequential",
		async execute(toolCallId, { path, offset = 1, limit = MAX_READ_LINES }, signal) {
			let resolvedPath;
			try {
				resolvedPath = await resolveInputPath(path, "file");
			} catch {
				latchIntegrityFailure();
				throw integrityFailure;
			}
			return executeNativeTool(toolCallId, "read", resolvedPath.relative, signal, async () => {
				if (resolvedPath.metadata.size > MAX_NATIVE_READ_FILE_BYTES) throw new Error("file exceeds read limit");
				const bytes = await readFile(resolvedPath.absolute);
				const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
				const selected = readLineWindow(content, offset, limit);
				const truncated = truncateUtf8(selected, MAX_NATIVE_TOOL_OUTPUT_BYTES);
				return {
					text: truncated.text,
					resultCount: 1,
					details: { truncated: truncated.truncated },
				};
			});
		},
	});

	pi.registerTool({
		name: "grep",
		label: "grep",
		description: "Search immutable analyzer input text with ripgrep. Ignore files cannot hide assigned content.",
		parameters: GrepParameters,
		executionMode: "sequential",
		async execute(toolCallId, params, signal) {
			let resolvedPath;
			try {
				resolvedPath = await resolveInputPath(params.path ?? ".", "file_or_directory");
			} catch {
				latchIntegrityFailure();
				throw integrityFailure;
			}
			return executeNativeTool(toolCallId, "grep", resolvedPath.relative, signal, async () => {
				const args = [
					"--line-number",
					"--with-filename",
					"--color=never",
					"--hidden",
					"--no-ignore",
					"--max-columns",
					String(MAX_GREP_COLUMNS),
					"--max-columns-preview",
				];
				if (params.ignoreCase) args.push("--ignore-case");
				if (params.literal) args.push("--fixed-strings");
				if (params.glob) args.push("--glob", params.glob);
				if (params.context) args.push("--context", String(params.context));
				args.push("--", params.pattern, resolvedPath.relative);
				return runHelper(
					RG,
					args,
					signal,
					new Set([0, 1]),
					new Set([2]),
					params.limit ?? Math.min(DEFAULT_GREP_MATCHES, maxSearchResults),
					"match",
				);
			});
		},
	});

	pi.registerTool({
		name: "find",
		label: "find",
		description: "Find paths in the immutable analyzer input by glob. Ignore files cannot hide assigned content.",
		parameters: FindParameters,
		executionMode: "sequential",
		async execute(
			toolCallId,
			{ pattern, path = ".", limit = Math.min(DEFAULT_FIND_RESULTS, maxSearchResults) },
			signal,
		) {
			let resolvedPath;
			try {
				resolvedPath = await resolveInputPath(path, "directory");
			} catch {
				latchIntegrityFailure();
				throw integrityFailure;
			}
			return executeNativeTool(toolCallId, "find", resolvedPath.relative, signal, async () => {
				const args = [
					"--glob",
					"--color=never",
					"--hidden",
					"--no-ignore",
					"--max-results",
					String(limit),
					"--",
					pattern,
					resolvedPath.relative,
				];
				return runHelper(FD, args, signal, new Set([0]), new Set([1, 2]), limit, "result");
			});
		},
	});

	pi.registerTool({
		name: "ls",
		label: "ls",
		description: "List an immutable analyzer input directory, including dotfiles.",
		parameters: LsParameters,
		executionMode: "sequential",
		async execute(
			toolCallId,
			{ path = ".", limit = Math.min(DEFAULT_LS_ENTRIES, maxSearchResults) },
			signal,
		) {
			let resolvedPath;
			try {
				resolvedPath = await resolveInputPath(path, "directory");
			} catch {
				latchIntegrityFailure();
				throw integrityFailure;
			}
			return executeNativeTool(toolCallId, "ls", resolvedPath.relative, signal, async () => {
				const entries = await readdir(resolvedPath.absolute, { withFileTypes: true });
				entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
				const selected = entries.slice(0, limit).map((entry) => {
					if (!entry.isFile() && !entry.isDirectory()) throw new Error("unsupported analyzer input entry");
					return `${entry.name}${entry.isDirectory() ? "/" : ""}`;
				});
				const entryLimitReached = entries.length > limit;
				return boundedLineOutput(selected, "(empty directory)", entryLimitReached, limit, "entry");
			});
		},
	});

	pi.registerTool({
		name: "manifest_list",
		label: "List assigned artifacts",
		description:
			"List the next bounded page of presentation paths and immutable artifact IDs. Call repeatedly until next_cursor is null.",
		parameters: strictObject({}),
		executionMode: "sequential",
		async execute(_toolCallId, _params, signal) {
			const cursor = nextManifestCursor;
			const page = await proxyRequest("manifest_list", { cursor }, signal);
			return proxyToolResult(consumeManifestPage(page));
		},
	});

	pi.registerTool({
		name: "prior_observations",
		label: "Read prior observations",
		description: "Read bounded normalized prior observations; file contents and matched values are never included.",
		parameters: strictObject({}),
		executionMode: "sequential",
		async execute(_toolCallId, _params, signal) {
			return proxyToolResult(await proxyRequest("prior_observations", {}, signal));
		},
	});

	pi.registerTool({
		name: "submit_classification",
		label: "Submit classification",
		description: "Submit the one final structured artifact-ID classification and end the run.",
		parameters: TerminalClassification,
		executionMode: "sequential",
		async execute(_toolCallId, params, signal) {
			if (integrityFailure) throw integrityFailure;
			if (terminalState !== "open") throw new Error("classification has already been submitted");
			terminalState = "submitting";
			const result = await proxyRequest("submit_classification", { payload: params }, signal);
			requireAccepted(result);
			terminalState = "accepted";
			return {
				content: [{ type: "text", text: "Classification accepted." }],
				details: {},
				terminate: true,
			};
		},
	});

	async function announceRuntime(ctx) {
		const model = ctx.model;
		const activeTools = assertExactToolGrant();
		const readyResult = await proxyRequest("runtime_ready", {
			pi_version: VERSION,
			provider: model?.provider ?? "",
			model: model?.id ?? "",
			thinking: ctx.thinkingLevel ?? pi.getThinkingLevel(),
			mode: ctx.mode,
			model_in_catalog: Boolean(model && ctx.modelRegistry.find(model.provider, model.id)),
			active_tools: activeTools,
		});
		requireAccepted(readyResult);
		const instructionResult = await proxyRequest("instruction");
		if (
			!instructionResult ||
			typeof instructionResult !== "object" ||
			Array.isArray(instructionResult) ||
			typeof instructionResult.instruction !== "string"
		) {
			throw new Error("File Guardian proxy omitted the trusted instruction");
		}
		runtimeInstruction = instructionResult.instruction;
	}

	async function failOnRuntimeMutation(ctx) {
		try {
			await announceRuntime(ctx);
		} catch {
			// Avoid surfacing transport detail that may contain host-private data.
		}
		integrityFailure = new Error("Pi runtime identity changed after authentication");
		ctx.abort();
		ctx.shutdown();
	}

	pi.on("session_start", async (_event, ctx) => announceRuntime(ctx));
	pi.on("model_select", async (_event, ctx) => failOnRuntimeMutation(ctx));
	pi.on("thinking_level_select", async (_event, ctx) => failOnRuntimeMutation(ctx));
	pi.on("tool_call", (event) => {
		if (!REQUIRED_TOOLS.includes(event.toolName) || (NATIVE_TOOLS.has(event.toolName) && integrityFailure)) {
			return { block: true, reason: "File Guardian tool integrity check failed" };
		}
		return undefined;
	});
	pi.on("before_agent_start", async () => {
		if (integrityFailure) throw integrityFailure;
		assertExactToolGrant();
		if (typeof runtimeInstruction !== "string") throw new Error("Pi runtime handshake did not complete");
		return { systemPrompt: runtimeInstruction };
	});
}
