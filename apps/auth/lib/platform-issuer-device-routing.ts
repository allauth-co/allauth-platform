import type { Pool } from "pg";
import { MCP_DEVICE_CLIENT_ID } from "./features/mcp-device";
import type { PreparedIssuerDeviceBody } from "./projects/owned-project-issuer-device";
import { deviceUserCodeCandidates } from "./projects/owned-project-issuer-device";
import {
	maximumIssuerFormBytes,
	ProjectOAuthError,
} from "./projects/owned-project-issuer-http";
import { timedProjectProtocolStream } from "./projects/project-protocol-body";

type OAuthDevicePath =
	| "/device/code"
	| "/device"
	| "/device/approve"
	| "/device/deny";
type PlatformDeviceRoute =
	| { kind: "native"; request: Request }
	| {
			kind: "oauth";
			path: OAuthDevicePath;
			request: Request;
			prepared?: PreparedIssuerDeviceBody;
	  }
	| { kind: "response"; response: Response };

export function platformIssuerDevicePath(
	request: Request,
): OAuthDevicePath | undefined {
	const path = new URL(request.url).pathname;
	if (request.method === "GET" && path === "/api/auth/device") return "/device";
	if (request.method !== "POST") return;
	switch (path) {
		case "/api/auth/device/code":
			return "/device/code";
		case "/api/auth/device/approve":
			return "/device/approve";
		case "/api/auth/device/deny":
			return "/device/deny";
	}
}

async function readDeviceBody(request: Request) {
	const tooLarge = () =>
		new ProjectOAuthError("invalid_request", "The OAuth request is too large.");
	const declared = request.headers.get("content-length");
	if (
		declared &&
		(!/^\d+$/.test(declared) || Number(declared) > maximumIssuerFormBytes)
	) {
		void request.body?.cancel().catch(() => undefined);
		throw tooLarge();
	}
	const bytes = new Uint8Array(maximumIssuerFormBytes);
	if (!request.body) return bytes.subarray(0, 0);
	const reader = timedProjectProtocolStream(request.body).stream.getReader();
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) return bytes.subarray(0, size);
			if (size + value.byteLength > bytes.length) {
				void reader.cancel().catch(() => undefined);
				throw tooLarge();
			}
			bytes.set(value, size);
			size += value.byteLength;
		}
	} catch (error) {
		if (error instanceof ProjectOAuthError) throw error;
		throw new ProjectOAuthError(
			"invalid_request",
			"The OAuth request is malformed.",
		);
	} finally {
		reader.releaseLock();
	}
}

function jsonBody(text: string): Record<string, unknown> | undefined {
	try {
		const value = JSON.parse(text);
		if (value && typeof value === "object" && !Array.isArray(value))
			return value;
	} catch {
		// The selected endpoint handles malformed bodies in its public error format.
	}
}

function standaloneClient(
	request: Request,
	body: URLSearchParams | Record<string, unknown> | undefined,
) {
	if (!body || request.headers.has("authorization")) return false;
	const authFields = [
		"client_secret",
		"client_assertion",
		"client_assertion_type",
	];
	if (body instanceof URLSearchParams) {
		const ids = body.getAll("client_id").filter(Boolean);
		return (
			ids.length === 1 &&
			ids[0] === MCP_DEVICE_CLIENT_ID &&
			!authFields.some((name) => body.getAll(name).some(Boolean))
		);
	}
	return (
		body.client_id === MCP_DEVICE_CLIENT_ID &&
		!authFields.some((name) => Object.hasOwn(body, name) && body[name] !== "")
	);
}

async function registeredUserCode(
	database: Pick<Pool, "query">,
	userCode: unknown,
) {
	const candidates = deviceUserCodeCandidates(userCode);
	if (!candidates) return false;
	const {
		rows: [row],
	} = await database.query<{ registered: boolean }>(
		`SELECT "oauthClientId" IS NOT NULL AS registered FROM public."deviceCode"
		 WHERE "userCode" = ANY($1::text[]) ORDER BY ("userCode" = $2) DESC LIMIT 1`,
		[candidates, candidates[0]],
	);
	return row?.registered === true;
}

/** Select the device writer after the caller binds the request to the platform. */
export async function routePlatformIssuerDevice(
	database: Pick<Pool, "query">,
	request: Request,
): Promise<PlatformDeviceRoute | undefined> {
	const path = platformIssuerDevicePath(request);
	if (!path) {
		if (
			request.method === "POST" &&
			new URL(request.url).pathname === "/api/auth/device/token"
		)
			return { kind: "native", request };
		return;
	}
	if (path === "/device") {
		const codes = new URL(request.url).searchParams.getAll("user_code");
		return codes.length === 1 && (await registeredUserCode(database, codes[0]))
			? { kind: "oauth", path, request }
			: { kind: "native", request };
	}

	const media = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	if (
		media !== "application/json" &&
		media !== "application/x-www-form-urlencoded"
	)
		return path === "/device/code"
			? { kind: "oauth", path, request, prepared: { body: undefined } }
			: { kind: "native", request };

	let bytes: Uint8Array<ArrayBuffer>;
	let body: URLSearchParams | Record<string, unknown> | undefined;
	try {
		bytes = await readDeviceBody(request);
		const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		body =
			media === "application/x-www-form-urlencoded"
				? new URLSearchParams(text)
				: jsonBody(text);
	} catch (error) {
		return {
			kind: "response",
			response: (error instanceof ProjectOAuthError
				? error
				: new ProjectOAuthError(
						"invalid_request",
						"The OAuth request is malformed.",
					)
			).response(),
		};
	}
	if (path === "/device/code") {
		if (!standaloneClient(request, body))
			return { kind: "oauth", path, request, prepared: { body } };
		const {
			rows: [row],
		} = await database.query<{ registered: boolean }>(
			`SELECT EXISTS (SELECT 1 FROM public."oauthClient" WHERE "clientId" = $1) AS registered`,
			[MCP_DEVICE_CLIENT_ID],
		);
		if (row?.registered)
			return { kind: "oauth", path, request, prepared: { body } };
	} else {
		const codes =
			body instanceof URLSearchParams ? body.getAll("userCode") : null;
		const userCode = codes
			? codes.length === 1
				? codes[0]
				: undefined
			: (body as Record<string, unknown> | undefined)?.userCode;
		if (await registeredUserCode(database, userCode))
			return { kind: "oauth", path, request, prepared: { body: { userCode } } };
	}
	// The legacy endpoint receives the original bytes and content type.
	return { kind: "native", request: new Request(request, { body: bytes }) };
}
