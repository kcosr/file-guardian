// Trusted File Guardian classifier extension for Pi 0.83.0.
//
// This module deliberately has no filesystem, subprocess, HTTP, session, or
// configuration-discovery capability. The sole transport is the invocation-
// scoped Unix socket supplied by File Guardian.

import { createConnection } from "node:net";
import { VERSION } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const PROTOCOL = "file-guardian-pi-proxy/1";
const MAX_PROXY_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUIRED_TOOLS = Object.freeze([
	"artifact_metadata",
	"artifact_read",
	"artifact_read_range",
	"artifact_search",
	"manifest_list",
	"prior_observations",
	"submit_classification",
]);

const socketPath = requiredEnvironment("FILE_GUARDIAN_PI_PROXY_SOCKET");
const runToken = requiredEnvironment("FILE_GUARDIAN_PI_RUN_TOKEN");
const runId = requiredEnvironment("FILE_GUARDIAN_PI_RUN_ID");
const manifestIdentity = requiredEnvironment("FILE_GUARDIAN_PI_MANIFEST_IDENTITY");
const analyzerId = requiredEnvironment("FILE_GUARDIAN_PI_ANALYZER_ID");

let nextRequestId = 1;
let terminalState = "open";
let runtimeInstruction;
let integrityFailure;

function requiredEnvironment(name) {
	const value = process.env[name];
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`missing required File Guardian runtime setting: ${name}`);
	}
	return value;
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

function proxyRequest(type, fields = {}, signal) {
	if (integrityFailure) return Promise.reject(integrityFailure);
	if (terminalState !== "open" && type !== "submit_classification") {
		return Promise.reject(new Error("classification has already been submitted"));
	}

	const requestId = nextRequestId++;
	const request = {
		protocol: PROTOCOL,
		run_token: runToken,
		run_id: runId,
		manifest_identity: manifestIdentity,
		request_id: requestId,
		analyzer_id: analyzerId,
		type,
		...fields,
	};

	return new Promise((resolve, reject) => {
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

			if (
				response?.protocol !== PROTOCOL ||
				response.request_id !== requestId
			) {
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
			finish(resolve, response.result);
		});
	});
}

function toolResult(result) {
	return {
		content: [{ type: "text", text: JSON.stringify(result) }],
		details: {},
	};
}

function registerProxyTool(pi, definition) {
	pi.registerTool({
		...definition,
		executionMode: "sequential",
		async execute(_toolCallId, params, signal) {
			return toolResult(await proxyRequest(definition.name, params, signal));
		},
	});
}

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
	artifact_classifications: Type.Array(ArtifactClassification, {
		maxItems: 100000,
	}),
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

	registerProxyTool(pi, {
		name: "manifest_list",
		label: "List assigned artifacts",
		description: "List the immutable artifacts assigned to this classification run.",
		parameters: strictObject({}),
	});

	registerProxyTool(pi, {
		name: "artifact_metadata",
		label: "Read artifact metadata",
		description: "Read bounded metadata for one assigned immutable artifact ID.",
		parameters: strictObject({ artifact_id: ArtifactId }),
	});

	registerProxyTool(pi, {
		name: "artifact_read",
		label: "Read artifact",
		description: "Read one assigned immutable artifact within the host-enforced byte budget.",
		parameters: strictObject({ artifact_id: ArtifactId }),
	});

	registerProxyTool(pi, {
		name: "artifact_read_range",
		label: "Read artifact range",
		description: "Read a bounded byte range from one assigned immutable artifact.",
		parameters: strictObject({
			artifact_id: ArtifactId,
			offset: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
			length: Type.Integer({ minimum: 1, maximum: 16 * 1024 * 1024 }),
		}),
	});

	registerProxyTool(pi, {
		name: "artifact_search",
		label: "Search artifact",
		description: "Search an assigned artifact for a bounded literal base64url byte pattern.",
		parameters: strictObject({
			artifact_id: ArtifactId,
			literal: Type.String({ minLength: 1, maxLength: 5462, pattern: "^[A-Za-z0-9_-]+$" }),
			max_matches: Type.Integer({ minimum: 1, maximum: 10000 }),
		}),
	});

	registerProxyTool(pi, {
		name: "prior_observations",
		label: "Read prior observations",
		description: "Read the host-projected prior observations for this pipeline stage.",
		parameters: strictObject({}),
	});

	pi.registerTool({
		name: "submit_classification",
		label: "Submit classification",
		description: "Submit the one final structured classification and end the run.",
		parameters: TerminalClassification,
		executionMode: "sequential",
		async execute(_toolCallId, params, signal) {
			if (terminalState !== "open") {
				throw new Error("classification has already been submitted");
			}
			terminalState = "submitting";
			await proxyRequest("submit_classification", { payload: params }, signal);
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
		await proxyRequest("runtime_ready", {
			pi_version: VERSION,
			provider: model?.provider ?? "",
			model: model?.id ?? "",
			thinking: ctx.thinkingLevel ?? pi.getThinkingLevel(),
			mode: ctx.mode,
			model_in_catalog: Boolean(model && ctx.modelRegistry.find(model.provider, model.id)),
			active_tools: activeTools,
		});
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
			// The original failure is intentionally not echoed: it can contain host
			// transport detail. A stable integrity error is surfaced instead.
		}
		integrityFailure = new Error("Pi runtime identity changed after authentication");
		ctx.abort();
		ctx.shutdown();
	}

	pi.on("session_start", async (_event, ctx) => announceRuntime(ctx));
	pi.on("model_select", async (_event, ctx) => failOnRuntimeMutation(ctx));
	pi.on("thinking_level_select", async (_event, ctx) => failOnRuntimeMutation(ctx));
	pi.on("before_agent_start", async () => {
		if (integrityFailure) throw integrityFailure;
		assertExactToolGrant();
		if (typeof runtimeInstruction !== "string") {
			throw new Error("Pi runtime handshake did not complete");
		}
		return { systemPrompt: runtimeInstruction };
	});
}
