// Trusted File Guardian triage extension for Pi 0.83.0.
//
// Pi's built-ins remain disabled. This extension exposes sandboxed analysis
// tools over the immutable analyzer view mounted at /input.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createConnection } from "node:net";
import { isAbsolute, posix } from "node:path";
import { createInterface } from "node:readline";
import { VERSION } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PROTOCOL = "file-guardian-pi-proxy/3";
const SIDECAR_PROTOCOL = "file-guardian-tool-sidecar/1";
const SIDECAR_RUNNER_TARGET = "/policy/tool-sidecar-runner.mjs";
const MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PATH_CHARACTERS = 4096;
const MAX_NATIVE_TOOL_OUTPUT_BYTES = 64 * 1024;
const MAX_READ_LINES = 2000;
const MAX_CONFIGURED_SEARCH_RESULTS = 10000;
const DEFAULT_GREP_MATCHES = 100;
const DEFAULT_FIND_RESULTS = 1000;
const DEFAULT_LS_ENTRIES = 500;
const REQUIRED_TOOLS = Object.freeze([
	"bash",
	"find",
	"grep",
	"ls",
	"manifest_list",
	"triage_request",
	"read",
	"submit_triage",
]);
const NATIVE_TOOLS = new Set(["bash", "read", "grep", "find", "ls"]);

const socketPath = requiredEnvironment("FILE_GUARDIAN_PI_PROXY_SOCKET");
const runToken = requiredEnvironment("FILE_GUARDIAN_PI_RUN_TOKEN");
const runId = requiredEnvironment("FILE_GUARDIAN_PI_RUN_ID");
const manifestIdentity = requiredEnvironment("FILE_GUARDIAN_PI_MANIFEST_IDENTITY");
const analyzerId = requiredEnvironment("FILE_GUARDIAN_PI_ANALYZER_ID");
const maxSearchResults = requiredBoundedIntegerEnvironment(
	"FILE_GUARDIAN_PI_MAX_SEARCH_RESULTS",
	MAX_CONFIGURED_SEARCH_RESULTS,
);
const bubblewrapExecutable = requiredEnvironment("FILE_GUARDIAN_PI_BUBBLEWRAP");
const runtimeRoot = requiredEnvironment("FILE_GUARDIAN_PI_RUNTIME_ROOT");
const runtimeLauncher = requiredEnvironment("FILE_GUARDIAN_PI_RUNTIME_LAUNCHER");
const inputView = requiredEnvironment("FILE_GUARDIAN_PI_INPUT_VIEW");
const toolSidecarRunner = requiredEnvironment("FILE_GUARDIAN_PI_TOOL_SIDECAR_RUNNER");

let nextRequestId = 1;
let terminalState = "open";
let runtimeInstruction;
let integrityFailure;
let nextManifestCursor = 0;
let toolSidecar;
let nextSidecarRequestId = 1;

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
	if (terminalState !== "open" && type !== "submit_triage") {
		return Promise.reject(new Error("triage has already been submitted"));
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
	integrityFailure ??= new Error("Pi sandboxed tool integrity check failed");
}

class RecoverableNativeToolError extends Error {
	constructor(message) {
		super(message);
		this.name = "RecoverableNativeToolError";
	}
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

async function executeNativeTool(toolCallIdValue, tool, relativePath, params, signal) {
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
		const result = await sidecarRequest(tool, params, signal);
		const outputBytes = Buffer.byteLength(result.text, "utf8");
		if (
			!hasExactKeys(result, ["path", "text", "result_count", "details"]) ||
			result.path !== relativePath ||
			typeof result.text !== "string" ||
			outputBytes > MAX_NATIVE_TOOL_OUTPUT_BYTES ||
			!Number.isSafeInteger(result.result_count) ||
			result.result_count < 0
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
			result.result_count,
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

function normalizedInputPath(rawPath, defaultPath = null) {
	const value = rawPath ?? defaultPath;
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_PATH_CHARACTERS ||
		Buffer.byteLength(value, "utf8") > MAX_PATH_CHARACTERS ||
		value.includes("\0") ||
		isAbsolute(value) ||
		value.startsWith("~") ||
		value.startsWith("@") ||
		value.split("/").includes("..")
	) {
		throw new RecoverableNativeToolError("Path must be relative to the immutable input.");
	}
	const normalized = posix.normalize(value);
	if (normalized === ".." || normalized.startsWith("../") || normalized.startsWith("/")) {
		throw new RecoverableNativeToolError("Path must be relative to the immutable input.");
	}
	// node:path preserves a trailing separator (for example, "src/" remains
	// "src/"). The host proxy accepts one canonical spelling only, while the
	// sidecar's realpath-derived result is separator-free. Normalize both ends
	// to that same spelling before the proxy accounts the call.
	return normalized === "." ? normalized : normalized.replace(/\/+$/, "");
}

function sidecarArguments() {
	if (
		!isAbsolute(bubblewrapExecutable) ||
		!isAbsolute(runtimeRoot) ||
		!isAbsolute(inputView) ||
		!isAbsolute(toolSidecarRunner) ||
		isAbsolute(runtimeLauncher) ||
		runtimeLauncher.split("/").some((part) => part === "" || part === "." || part === "..")
	) {
		throw new Error("invalid File Guardian sidecar launch setting");
	}
	return [
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
		"--ro-bind",
		runtimeRoot,
		"/runtime",
		"--ro-bind",
		toolSidecarRunner,
		SIDECAR_RUNNER_TARGET,
		"--ro-bind",
		inputView,
		"/input",
		"--tmpfs",
		"/work",
		"--tmpfs",
		"/tmp",
		"--chdir",
		"/work",
		"--",
		`/runtime/${runtimeLauncher}`,
		SIDECAR_RUNNER_TARGET,
	];
}

async function waitForSidecarLine(iterator, timeoutMillis = 12_000) {
	let timer;
	try {
		return await Promise.race([
			iterator.next(),
			new Promise((_, reject) => {
				timer = setTimeout(
					() => reject(new Error("tool sidecar response timed out")),
					timeoutMillis,
				);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

function waitForSidecarClose(child, timeoutMillis) {
	if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
	return new Promise((resolvePromise) => {
		let settled = false;
		const finish = (closed) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			child.removeListener("close", close);
			child.removeListener("error", error);
			resolvePromise(closed);
		};
		const close = () => finish(true);
		const error = () => finish(false);
		const timer = setTimeout(() => finish(false), timeoutMillis);
		child.once("close", close);
		child.once("error", error);
	});
}

function waitForSidecarReady(child, iterator, timeoutMillis = 12_000) {
	return new Promise((resolvePromise, reject) => {
		let settled = false;
		const finish = (callback, value) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			child.removeListener("error", error);
			child.removeListener("exit", exit);
			callback(value);
		};
		const error = () => finish(reject, new Error("tool sidecar could not start"));
		const exit = () => finish(reject, new Error("tool sidecar exited before readiness"));
		const timer = setTimeout(
			() => finish(reject, new Error("tool sidecar response timed out")),
			timeoutMillis,
		);
		child.once("error", error);
		child.once("exit", exit);
		iterator.next().then(
			(value) => finish(resolvePromise, value),
			() => finish(reject, new Error("tool sidecar response failed")),
		);
	});
}

async function terminateToolSidecar(child) {
	child.stdin.destroy();
	if (await waitForSidecarClose(child, 1_000)) return;
	child.kill("SIGKILL");
	if (!(await waitForSidecarClose(child, 1_000))) {
		throw new Error("tool sidecar did not terminate");
	}
}

async function startToolSidecar() {
	if (toolSidecar) return toolSidecar;
	const child = spawn(bubblewrapExecutable, sidecarArguments(), {
		env: {},
		// Keep this exact three-descriptor map. Node/libuv closes every other
		// descriptor in the child, including Pi's inherited proxy-directory fd.
		stdio: ["pipe", "pipe", "pipe"],
	});
	let stderrBytes = 0;
	child.stderr.on("data", (chunk) => {
		stderrBytes += chunk.length;
		if (stderrBytes > MAX_NATIVE_TOOL_OUTPUT_BYTES) child.kill("SIGKILL");
	});
	const lines = createInterface({ input: child.stdout, crlfDelay: Infinity, terminal: false });
	const iterator = lines[Symbol.asyncIterator]();
	let ready;
	try {
		ready = await waitForSidecarReady(child, iterator);
	} catch {
		await terminateToolSidecar(child);
		throw new Error("tool sidecar did not become ready");
	}
	let value;
	try {
		value = JSON.parse(ready.value ?? "");
	} catch {
		await terminateToolSidecar(child);
		throw new Error("tool sidecar returned an invalid startup response");
	}
	if (ready.done || !hasExactKeys(value, ["protocol", "type"]) || value.protocol !== SIDECAR_PROTOCOL || value.type !== "ready") {
		await terminateToolSidecar(child);
		throw new Error("tool sidecar did not become ready");
	}
	toolSidecar = { child, iterator };
	return toolSidecar;
}

async function sidecarRequest(tool, params, signal) {
	if (signal?.aborted) throw new Error("tool sidecar request aborted");
	const sidecar = await startToolSidecar();
	const requestId = nextSidecarRequestId++;
	const request = JSON.stringify({ protocol: SIDECAR_PROTOCOL, request_id: requestId, tool, params });
	if (Buffer.byteLength(request, "utf8") > MAX_PROXY_RESPONSE_BYTES) {
		throw new RecoverableNativeToolError("Tool arguments are too large.");
	}
	await new Promise((resolvePromise, reject) => {
		sidecar.child.stdin.write(`${request}\n`, (error) => (error ? reject(error) : resolvePromise()));
	});
	const responseLine = await waitForSidecarLine(sidecar.iterator);
	if (responseLine.done || Buffer.byteLength(responseLine.value ?? "", "utf8") > MAX_PROXY_RESPONSE_BYTES) {
		throw new Error("tool sidecar response was unavailable or oversized");
	}
	let response;
	try {
		response = JSON.parse(responseLine.value);
	} catch {
		throw new Error("tool sidecar returned invalid JSON");
	}
	if (response.protocol !== SIDECAR_PROTOCOL || response.request_id !== requestId) {
		throw new Error("tool sidecar response identity mismatch");
	}
	if (response.status === "recoverable_error") {
		throw new RecoverableNativeToolError(response.message ?? "Tool arguments were rejected. Revise them and retry.");
	}
	if (response.status !== "ok" || !hasExactKeys(response, ["protocol", "request_id", "status", "result"])) {
		throw new Error("tool sidecar execution failed");
	}
	return response.result;
}

async function stopToolSidecar() {
	if (!toolSidecar) return;
	const sidecar = toolSidecar;
	toolSidecar = undefined;
	const requestId = nextSidecarRequestId++;
	const request = JSON.stringify({ protocol: SIDECAR_PROTOCOL, request_id: requestId, tool: "shutdown", params: {} });
	try {
		await new Promise((resolvePromise, reject) => {
			sidecar.child.stdin.write(`${request}\n`, (error) => (error ? reject(error) : resolvePromise()));
		});
		const responseLine = await waitForSidecarLine(sidecar.iterator);
		let response;
		try {
			response = JSON.parse(responseLine.value ?? "");
		} catch {
			throw new Error("tool sidecar shutdown failed");
		}
		if (
			responseLine.done ||
			!hasExactKeys(response, ["protocol", "request_id", "status", "result"]) ||
			response.protocol !== SIDECAR_PROTOCOL ||
			response.request_id !== requestId ||
			response.status !== "ok" ||
			!hasExactKeys(response.result, ["stopped"]) ||
			response.result.stopped !== true
		) {
			throw new Error("tool sidecar shutdown failed");
		}
		sidecar.child.stdin.end();
		if (!(await waitForSidecarClose(sidecar.child, 1_000))) {
			throw new Error("tool sidecar shutdown timed out");
		}
	} catch {
		await terminateToolSidecar(sidecar.child);
		throw new Error("tool sidecar shutdown failed");
	}
}

const RelativePath = Type.String({ minLength: 1, maxLength: MAX_PATH_CHARACTERS });

const BashParameters = strictObject({
	command: Type.String({ minLength: 1, maxLength: 16 * 1024 }),
});

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

const SafeCode = Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9_.:/-]+$" });
const ReasonCodes = Type.Array(SafeCode, { maxItems: 256, uniqueItems: true });
const FindingId = Type.String({ minLength: 5, maxLength: 100, pattern: "^fnd_[A-Za-z0-9_-]{1,96}$" });
const Digest = Type.String({ minLength: 71, maxLength: 71, pattern: "^sha256:[0-9a-f]{64}$" });
const InvocationId = Type.String({ minLength: 5, maxLength: 100, pattern: "^pii_[A-Za-z0-9_-]{1,96}$" });

const FindingAssessment = strictObject({
	finding_id: FindingId,
	classification: Type.Union([
		Type.Literal("confirmed"),
		Type.Literal("likely_true_positive"),
		Type.Literal("likely_false_positive"),
		Type.Literal("false_positive"),
		Type.Literal("uncertain"),
		Type.Literal("unable_to_assess"),
	]),
	confidence: Type.Union([Type.Literal("low"), Type.Literal("medium"), Type.Literal("high")]),
	reason_codes: ReasonCodes,
	duplicate_of: Type.Union([FindingId, Type.Null()]),
	recommended_action: Type.Union([
		Type.Literal("none"),
		Type.Literal("audit"),
		Type.Literal("delete"),
		Type.Literal("quarantine"),
	]),
});

const TerminalTriage = strictObject({
	schema_version: Type.Literal("file-guardian-pi-triage/1"),
	invocation_id: InvocationId,
	phase: Type.Union([Type.Literal("initial"), Type.Literal("verification")]),
	manifest_identity: Digest,
	request_identity: Digest,
	prior_observations_identity: Digest,
	status: Type.Literal("complete"),
	assessments: Type.Array(FindingAssessment, { maxItems: 100000 }),
	stage_attestation: Type.Union([
		Type.Literal("no_blocking_concerns_observed"),
		Type.Literal("blocking_concerns_observed"),
		Type.Literal("unable_to_assert"),
	]),
	coverage: strictObject({
		assigned_artifact_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
		completed_artifact_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
		not_applicable_artifact_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
		assigned_finding_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
		assessed_finding_count: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
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
		name: "bash",
		label: "bash",
		description:
			"Run a shell command in the persistent networkless tool sandbox. /input is immutable and /work is writable and persists between calls.",
		parameters: BashParameters,
		executionMode: "sequential",
		async execute(toolCallId, { command }, signal) {
			return executeNativeTool(toolCallId, "bash", ".", { command }, signal);
		},
	});

	pi.registerTool({
		name: "read",
		label: "read",
		description: "Read a UTF-8 text file from the immutable analyzer input. Use offset and limit for large files.",
		parameters: ReadParameters,
		executionMode: "sequential",
		async execute(toolCallId, { path, offset = 1, limit = MAX_READ_LINES }, signal) {
			try {
				path = normalizedInputPath(path);
			} catch (error) {
				return toolResult(error.message, { recoverable: true, errorCode: "invalid_arguments" });
			}
			return executeNativeTool(toolCallId, "read", path, { path, offset, limit }, signal);
		},
	});

	pi.registerTool({
		name: "grep",
		label: "grep",
		description: "Search immutable analyzer input text with ripgrep. Ignore files cannot hide assigned content.",
		parameters: GrepParameters,
		executionMode: "sequential",
		async execute(toolCallId, params, signal) {
			try {
				params.path = normalizedInputPath(params.path, ".");
			} catch (error) {
				return toolResult(error.message, { recoverable: true, errorCode: "invalid_arguments" });
			}
			const sidecarParams = {
				pattern: params.pattern,
				path: params.path,
				glob: params.glob ?? null,
				ignore_case: params.ignoreCase ?? false,
				literal: params.literal ?? false,
				context: params.context ?? 0,
				limit: params.limit ?? Math.min(DEFAULT_GREP_MATCHES, maxSearchResults),
			};
			return executeNativeTool(toolCallId, "grep", params.path, sidecarParams, signal);
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
			try {
				path = normalizedInputPath(path, ".");
			} catch (error) {
				return toolResult(error.message, { recoverable: true, errorCode: "invalid_arguments" });
			}
			return executeNativeTool(toolCallId, "find", path, { pattern, path, limit }, signal);
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
			try {
				path = normalizedInputPath(path, ".");
			} catch (error) {
				return toolResult(error.message, { recoverable: true, errorCode: "invalid_arguments" });
			}
			return executeNativeTool(toolCallId, "ls", path, { path, limit }, signal);
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
		name: "triage_request",
		label: "Read triage request",
		description: "Read the bounded, identity-bound prior-finding triage request; content and matched values are never included.",
		parameters: strictObject({}),
		executionMode: "sequential",
		async execute(_toolCallId, _params, signal) {
			return proxyToolResult(await proxyRequest("triage_request", {}, signal));
		},
	});

	pi.registerTool({
		name: "submit_triage",
		label: "Submit triage",
		description: "Submit one candidate-free, finding-ID-bound triage result and end the run.",
		parameters: TerminalTriage,
		executionMode: "sequential",
		async execute(_toolCallId, params, signal) {
			if (integrityFailure) throw integrityFailure;
			if (terminalState !== "open") throw new Error("triage has already been submitted");
			terminalState = "submitting";
			try {
				await stopToolSidecar();
			} catch {
				latchIntegrityFailure();
				throw integrityFailure;
			}
			const result = await proxyRequest("submit_triage", { payload: params }, signal);
			requireAccepted(result);
			terminalState = "accepted";
			return {
				content: [{ type: "text", text: "Triage accepted." }],
				details: {},
				terminate: true,
			};
		},
	});

	async function announceRuntime(ctx) {
		const model = ctx.model;
		const activeTools = assertExactToolGrant();
		await startToolSidecar();
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
