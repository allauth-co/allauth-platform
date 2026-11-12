import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { APIError } from "better-auth";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { Project } from "./registry";

const maximumProxyBodyBytes = 262144;
const proxyBodyDeadlineMs = 5000;
const proxyHeaders = [
	"allauth-proxy-signature",
	"allauth-proxy-timestamp",
	"allauth-proxy-origin",
	"allauth-proxy-ip",
] as const;

/** Ordinary project requests carry no app-proxy assertions. */
export function withoutProjectProxyAssertions(request: Request): Request {
	if (!proxyHeaders.some((name) => request.headers.has(name))) return request;
	const headers = new Headers(request.headers);
	for (const name of proxyHeaders) headers.delete(name);
	return new Request(request, { headers });
}

async function readProxyBody(reader: ReadableStreamDefaultReader<Uint8Array>) {
	const chunks: Uint8Array[] = [];
	let length = 0;
	while (true) {
		const result = await reader.read();
		if (result.done) break;
		length += result.value.byteLength;
		if (length > maximumProxyBodyBytes) {
			void reader.cancel().catch(() => {});
			throw new APIError("PAYLOAD_TOO_LARGE");
		}
		chunks.push(result.value);
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return bytes;
}

async function boundedProxyBody(request: Request, consumeBody: boolean) {
	const declaredLength = request.headers.get("content-length");
	if (
		declaredLength &&
		(!/^\d+$/.test(declaredLength) ||
			Number(declaredLength) > maximumProxyBodyBytes)
	)
		throw new APIError("PAYLOAD_TOO_LARGE");
	const reader = (consumeBody ? request : request.clone()).body?.getReader();
	if (!reader) return new Uint8Array();
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			reject(
				new APIError(408, { message: "The app proxy request body timed out." }),
			);
			void reader.cancel().catch(() => {});
		}, proxyBodyDeadlineMs);
	});
	try {
		return await Promise.race([readProxyBody(reader), timeout]);
	} finally {
		clearTimeout(timer);
		reader.releaseLock();
	}
}

/** A scoped transport key authenticates app-proxy IP/origin assertions; it grants no user or admin role. */
export function projectProxySecret(
	project: Project,
	env: AuthEnvironment,
): string {
	return createHmac("sha256", setting(env, "BETTER_AUTH_SECRET"))
		.update(`allauth:proxy:${project.id}:${project.proxyVersion}`)
		.digest("hex");
}

/** Only a signed app server may replace the Railway-provided client IP with its end user's IP. */
export async function verifiedProjectRequest(
	request: Request,
	project: Project,
	env: AuthEnvironment,
	{ consumeBody = false }: { consumeBody?: boolean } = {},
): Promise<Request> {
	const signature = request.headers.get("allauth-proxy-signature");
	if (signature === null) return withoutProjectProxyAssertions(request);
	const timestamp = request.headers.get("allauth-proxy-timestamp") || "";
	const origin = request.headers.get("allauth-proxy-origin") || "";
	const ip = request.headers.get("allauth-proxy-ip") || "";
	if (
		!/^\d{10}$/.test(timestamp) ||
		Math.abs(Date.now() / 1000 - Number(timestamp)) > 60 ||
		!project.origins.includes(origin) ||
		(ip && !isIP(ip)) ||
		!/^[a-f0-9]{64}$/.test(signature)
	)
		throw new APIError("FORBIDDEN", { message: "Invalid app proxy request." });
	const body = await boundedProxyBody(request, consumeBody);
	const url = new URL(request.url);
	const input = [
		timestamp,
		request.method,
		`${url.pathname}${url.search}`,
		origin,
		ip,
		createHash("sha256").update(body).digest("hex"),
	].join("\n");
	const expected = createHmac("sha256", projectProxySecret(project, env))
		.update(input)
		.digest();
	const actual = Uint8Array.from(
		signature.match(/../g)!.map((value) => parseInt(value, 16)),
	);
	if (!timingSafeEqual(expected, actual))
		throw new APIError("FORBIDDEN", { message: "Invalid app proxy request." });
	const headers = new Headers(request.headers);
	if (ip) headers.set("x-real-ip", ip);
	if (!headers.has("origin")) headers.set("origin", origin);
	// Signed proxy requests only carry this project's cookies, including callbacks.
	const prefix = `allauth_project_${project.slug}.`;
	const cookies = (headers.get("cookie") || "")
		.split(";")
		.map((value) => value.trim())
		.filter((value) =>
			value
				.split("=", 1)[0]
				?.replace(/^__Secure-/, "")
				.startsWith(prefix),
		);
	headers.set("cookie", cookies.join("; "));
	return new Request(request, {
		headers,
		// The HTTP boundary has exclusive ownership of this body and forwards the
		// exact bytes verified above. Independent downstream checks may keep their input.
		...(consumeBody && request.body ? { body } : {}),
	});
}
