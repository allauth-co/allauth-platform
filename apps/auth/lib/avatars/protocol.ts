/** Separate signed protocol: branding credentials never authorize arbitrary object removal. */
export const avatarProtocol = 1;
export const avatarCapabilityPath = "/avatars/capabilities";
export const avatarMaxBytes = 131072;
const uuid = "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
const pathPattern = new RegExp(
	`^/avatars/${uuid}/${uuid}/${uuid}/${uuid}\\.(png|jpg|webp)$`,
);
const encoder = new TextEncoder();
const hex = (data: ArrayBuffer) =>
	Array.from(new Uint8Array(data), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
export const validAvatarPath = (value: string) => pathPattern.test(value);
/** Resolve browser URL aliases before the SQL owner guard checks the original asset URL. */
export function validAvatarProfileImage(
	image: unknown,
	operation: "create" | "update",
	baseURL: string,
) {
	if (typeof image !== "string") return true;
	let url: URL;
	try {
		url = new URL(image, baseURL);
	} catch {
		return true;
	}
	return (
		!validAvatarPath(url.pathname) ||
		(operation === "update" &&
			url.protocol === "https:" &&
			image === url.origin + url.pathname)
	);
}
async function body(request: Request): Promise<Uint8Array<ArrayBuffer>> {
	const reader = request.clone().body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		for (;;) {
			const part = await reader.read();
			if (part.done) break;
			length += part.value.length;
			if (length > avatarMaxBytes) {
				void reader.cancel().catch(() => {});
				throw new Error("Avatar body exceeded its limit.");
			}
			chunks.push(part.value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.length;
	}
	return bytes;
}
async function payload(
	request: Request,
	time: string,
	bytes: Uint8Array<ArrayBuffer>,
) {
	const url = new URL(request.url),
		capability =
			url.pathname === avatarCapabilityPath && request.method === "GET";
	if (
		url.search ||
		url.hash ||
		url.username ||
		url.password ||
		(!capability &&
			(!validAvatarPath(url.pathname) ||
				!["PUT", "DELETE"].includes(request.method)))
	)
		throw new Error("Invalid owned-avatar request.");
	const type = request.headers.get("content-type") || "";
	if (
		request.method !== "PUT"
			? bytes.length !== 0 || type !== ""
			: !["image/png", "image/jpeg", "image/webp"].includes(type)
	)
		throw new Error("Invalid owned-avatar body.");
	return encoder.encode(
		JSON.stringify([
			"allauth-owned-avatars-v1",
			request.method,
			url.pathname,
			type,
			time,
			hex(await crypto.subtle.digest("SHA-256", bytes)),
		]),
	);
}
async function key(secret: string) {
	if (secret.length < 32)
		throw new Error("Owned-avatar storage is unavailable.");
	return crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);
}
export async function signAvatarRequest(
	request: Request,
	secret: string,
	now = Date.now(),
) {
	const time = String(Math.floor(now / 1000)),
		bytes = await body(request),
		headers = new Headers(request.headers);
	headers.set("x-allauth-avatar-time", time);
	headers.set(
		"x-allauth-avatar-signature",
		hex(
			await crypto.subtle.sign(
				"HMAC",
				await key(secret),
				await payload(request, time, bytes),
			),
		),
	);
	return headers;
}
export async function verifyAvatarRequest(
	request: Request,
	secret: string,
	now = Date.now(),
): Promise<Uint8Array<ArrayBuffer> | null> {
	try {
		const time = request.headers.get("x-allauth-avatar-time") || "",
			signature = request.headers.get("x-allauth-avatar-signature") || "";
		if (
			!/^\d{10}$/.test(time) ||
			Math.abs(Math.floor(now / 1000) - Number(time)) > 60 ||
			!/^[a-f0-9]{64}$/.test(signature)
		)
			return null;
		const bytes = await body(request),
			signed = Uint8Array.from(signature.match(/.{2}/g)!, (part) =>
				Number.parseInt(part, 16),
			);
		return (await crypto.subtle.verify(
			"HMAC",
			await key(secret),
			signed,
			await payload(request, time, bytes),
		))
			? bytes
			: null;
	} catch {
		return null;
	}
}
