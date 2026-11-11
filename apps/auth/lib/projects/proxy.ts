import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { APIError } from "better-auth";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import type { Project } from "./registry";

const maximumProxyBodyBytes = 262144;
async function boundedProxyBody(request: Request): Promise<Uint8Array> {
	const declaredLength = request.headers.get("content-length");
	if (declaredLength && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumProxyBodyBytes)) throw new APIError("PAYLOAD_TOO_LARGE");
	const reader = request.clone().body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const result = await reader.read();
			if (result.done) break;
			length += result.value.byteLength;
			if (length > maximumProxyBodyBytes) { void reader.cancel().catch(() => {}); throw new APIError("PAYLOAD_TOO_LARGE"); }
			chunks.push(result.value);
		}
	} finally { reader.releaseLock(); }
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	return bytes;
}

/** A scoped transport key authenticates app-proxy IP/origin assertions; it grants no user or admin role. */
export function projectProxySecret(project: Project, env: AuthEnvironment): string {
	return createHmac("sha256", setting(env, "BETTER_AUTH_SECRET")).update(`allauth:proxy:${project.id}:${project.proxyVersion}`).digest("hex");
}

/** Only a signed app server may replace the Railway-provided client IP with its end user's IP. */
export async function verifiedProjectRequest(request: Request, project: Project, env: AuthEnvironment): Promise<Request> {
	const signature = request.headers.get("allauth-proxy-signature");
	if (!signature) return request;
	const timestamp = request.headers.get("allauth-proxy-timestamp") || "";
	const origin = request.headers.get("allauth-proxy-origin") || "";
	const ip = request.headers.get("allauth-proxy-ip") || "";
	if (!/^\d{10}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 60 || !project.origins.includes(origin) || (ip && !isIP(ip)) || !/^[a-f0-9]{64}$/.test(signature)) throw new APIError("FORBIDDEN", { message: "Invalid app proxy request." });
	const body = await boundedProxyBody(request);
	const url = new URL(request.url);
	const input = [timestamp, request.method, `${url.pathname}${url.search}`, origin, ip, createHash("sha256").update(body).digest("hex")].join("\n");
	const expected = createHmac("sha256", projectProxySecret(project, env)).update(input).digest();
	const actual = Uint8Array.from(signature.match(/../g)!.map((value) => parseInt(value, 16)));
	if (!timingSafeEqual(expected, actual)) throw new APIError("FORBIDDEN", { message: "Invalid app proxy request." });
	const headers = new Headers(request.headers);
	if (ip) headers.set("x-real-ip", ip);
	if (!headers.has("origin")) headers.set("origin", origin);
	// Signed proxy requests only carry this project's cookies, including callbacks.
	const prefix = `allauth_project_${project.slug}.`;
	const cookies = (headers.get("cookie") || "").split(";").map((value) => value.trim()).filter((value) => value.split("=", 1)[0]?.replace(/^__Secure-/, "").startsWith(prefix));
	headers.set("cookie", cookies.join("; "));
	return new Request(request, { headers });
}
