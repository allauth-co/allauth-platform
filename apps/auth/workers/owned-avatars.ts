import {
	avatarCapabilityPath,
	avatarProtocol,
	validAvatarPath,
	verifyAvatarRequest,
} from "../lib/avatars/protocol";
export interface OwnedAvatarEnvironment {
	OWNED_AVATARS?: R2Bucket;
	ALLAUTH_AVATAR_SECRET?: string;
	OWNED_AVATAR_PRIVATE_STORAGE?: string;
}
const headers = () =>
	new Headers({
		"cache-control": "private, no-store",
		pragma: "no-cache",
		"x-content-type-options": "nosniff",
		"content-security-policy": "default-src 'none'; sandbox",
		"cross-origin-resource-policy": "cross-origin",
		"access-control-allow-origin": "*",
	});
const error = (status: number) =>
	new Response("Owned avatar unavailable.", { status, headers: headers() });
/** A separate private bucket prevents bypass through legacy branding's public storage domains. */
export async function ownedAvatarResponse(
	request: Request,
	env: OwnedAvatarEnvironment,
): Promise<Response | null> {
	const url = new URL(request.url);
	if (!url.pathname.startsWith("/avatars/")) return null;
	if (
		url.search ||
		(!validAvatarPath(url.pathname) && url.pathname !== avatarCapabilityPath)
	)
		return error(404);
	if (
		!env.OWNED_AVATARS ||
		env.OWNED_AVATAR_PRIVATE_STORAGE !== "true" ||
		!env.ALLAUTH_AVATAR_SECRET ||
		env.ALLAUTH_AVATAR_SECRET.length < 32
	)
		return error(503);
	if (url.pathname === avatarCapabilityPath) {
		if (
			request.method !== "GET" ||
			!(await verifyAvatarRequest(request, env.ALLAUTH_AVATAR_SECRET))
		)
			return error(401);
		// Verify actual bucket write/read/erase access with an empty, non-user object before heartbeat.
		const probe = `avatar-lifecycle-probes/${crypto.randomUUID()}`;
		await env.OWNED_AVATARS.put(probe, new Uint8Array(), {
			customMetadata: { lifecycleProbe: "true" },
			httpMetadata: { cacheControl: "private, no-store" },
		});
		if (
			(await env.OWNED_AVATARS.head(probe))?.customMetadata?.lifecycleProbe !==
			"true"
		)
			return error(503);
		await env.OWNED_AVATARS.delete(probe);
		if (await env.OWNED_AVATARS.head(probe)) return error(503);
		return Response.json(
			{ profileImageOwnershipAndDeletionProtocol: avatarProtocol },
			{ headers: headers() },
		);
	}
	const key = url.pathname.slice(1);
	if (["PUT", "DELETE"].includes(request.method)) {
		const bytes = await verifyAvatarRequest(request, env.ALLAUTH_AVATAR_SECRET);
		if (!bytes) return error(401);
		if (request.method === "DELETE") {
			// Retain no image bytes: an opaque zero-byte marker also prevents a delayed immutable PUT.
			const marker = await env.OWNED_AVATARS.put(key, new Uint8Array(), {
				customMetadata: { erased: "true" },
				httpMetadata: {
					contentType: "application/octet-stream",
					cacheControl: "private, no-store",
				},
			});
			if (
				!marker ||
				marker.size !== 0 ||
				marker.customMetadata?.erased !== "true"
			)
				return error(503);
			return new Response(null, { status: 204, headers: headers() });
		}
		const type = request.headers.get("content-type"),
			extension = url.pathname.split(".").pop();
		const valid =
			(type === "image/png" &&
				extension === "png" &&
				bytes.length >= 24 &&
				[137, 80, 78, 71, 13, 10, 26, 10].every(
					(byte, index) => bytes[index] === byte,
				)) ||
			(type === "image/jpeg" &&
				extension === "jpg" &&
				bytes.length >= 4 &&
				bytes[0] === 255 &&
				bytes[1] === 216 &&
				bytes[2] === 255) ||
			(type === "image/webp" &&
				extension === "webp" &&
				bytes.length >= 20 &&
				String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
				String.fromCharCode(...bytes.slice(8, 12)) === "WEBP");
		if (!valid) return error(400);
		const result = await env.OWNED_AVATARS.put(key, bytes, {
			onlyIf: new Headers({ "if-none-match": "*" }),
			httpMetadata: { contentType: type!, cacheControl: "private, no-store" },
		});
		return result
			? Response.json({ url: url.href }, { status: 201, headers: headers() })
			: error(409);
	}
	if (!["GET", "HEAD"].includes(request.method)) return error(405);
	const object =
		request.method === "HEAD"
			? await env.OWNED_AVATARS.head(key)
			: await env.OWNED_AVATARS.get(key);
	if (!object || object.customMetadata?.erased === "true") return error(404);
	const responseHeaders = headers();
	object.writeHttpMetadata(responseHeaders);
	responseHeaders.set("cache-control", "private, no-store");
	responseHeaders.set("etag", object.httpEtag);
	return new Response(
		request.method === "HEAD" ? null : (object as R2ObjectBody).body,
		{ headers: responseHeaders },
	);
}
