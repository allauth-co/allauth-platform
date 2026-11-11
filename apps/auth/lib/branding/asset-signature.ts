/** Server-only uploads use a body-bound envelope; public branding reads need no credential. */
export const maxAssetBody = 2 * 1024 * 1024;
export const assetHeaders = ["x-allauth-asset-time", "x-allauth-asset-signature"] as const;
const encoder = new TextEncoder();
const hex = (value: ArrayBuffer) => Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
const signatureBytes = (value: string) => new Uint8Array(value.match(/.{2}/g)!.map((part) => Number.parseInt(part, 16)));
const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const assetPath = new RegExp(`^/branding/${uuid}/${uuid}/${uuid}\\.(png|jpg|webp|ico)$`);
export function validAssetPath(pathname: string) { return assetPath.test(pathname); }
async function signingKey(secret: string) {
	if (secret.length < 32) throw new Error("Brand asset storage is not configured.");
	return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
export async function boundedAssetBody(request: Request): Promise<Uint8Array<ArrayBuffer>> {
	const declared = request.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > maxAssetBody)) throw new Error("Brand assets must be no larger than 2 MB.");
	const reader = request.clone().body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = []; let length = 0;
	try {
		for (;;) {
			const part = await reader.read(); if (part.done) break;
			length += part.value.length;
			if (length > maxAssetBody) { void reader.cancel().catch(() => {}); throw new Error("Brand assets must be no larger than 2 MB."); }
			chunks.push(part.value);
		}
	} finally { reader.releaseLock(); }
	const result = new Uint8Array(length); let offset = 0;
	for (const part of chunks) { result.set(part, offset); offset += part.length; }
	return result;
}
async function envelope(request: Request, timestamp: string, body: Uint8Array<ArrayBuffer>) {
	const url = new URL(request.url);
	if (request.method !== "PUT" || !validAssetPath(url.pathname) || url.search) throw new Error("Invalid asset upload path.");
	const type = request.headers.get("content-type") || "";
	if (!["image/png", "image/jpeg", "image/webp", "image/x-icon"].includes(type)) throw new Error("Unsupported brand asset format.");
	return encoder.encode(JSON.stringify(["allauth-assets-v1", "PUT", url.pathname, type, timestamp, hex(await crypto.subtle.digest("SHA-256", body))]));
}
export async function signAssetHeaders(request: Request, secret: string, time = Date.now()): Promise<Headers> {
	const timestamp = String(Math.floor(time / 1000));
	const body = await boundedAssetBody(request);
	const signature = hex(await crypto.subtle.sign("HMAC", await signingKey(secret), await envelope(request, timestamp, body)));
	const headers = new Headers(request.headers);
	headers.set(assetHeaders[0], timestamp); headers.set(assetHeaders[1], signature);
	return headers;
}
export async function verifyAssetRequest(request: Request, secret: string, time = Date.now()): Promise<Uint8Array<ArrayBuffer> | null> {
	try {
		const timestamp = request.headers.get(assetHeaders[0]) || "";
		const signature = request.headers.get(assetHeaders[1]) || "";
		if (!/^\d{10}$/.test(timestamp) || Math.abs(Math.floor(time / 1000) - Number(timestamp)) > 60 || !/^[a-f0-9]{64}$/.test(signature)) return null;
		const body = await boundedAssetBody(request);
		return await crypto.subtle.verify("HMAC", await signingKey(secret), signatureBytes(signature), await envelope(request, timestamp, body)) ? body : null;
	} catch { return null; }
}
