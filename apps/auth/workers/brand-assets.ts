import { validAssetPath, verifyAssetRequest } from "../lib/branding/asset-signature";
import {ownedAvatarResponse} from "./owned-avatars";
import type {OwnedAvatarEnvironment} from "./owned-avatars";
interface BrandAssetEnvironment extends OwnedAvatarEnvironment { BRAND_ASSETS: R2Bucket; ALLAUTH_ASSET_SECRET: string }
function validImage(body: Uint8Array, type: string) {
	if (type === "image/png") return body.length >= 24 && [137,80,78,71,13,10,26,10].every((value, index) => body[index] === value);
	if (type === "image/jpeg") return body.length >= 4 && body[0] === 255 && body[1] === 216 && body[2] === 255;
	if (type === "image/webp") return body.length >= 16 && String.fromCharCode(...body.slice(0,4)) === "RIFF" && String.fromCharCode(...body.slice(8,12)) === "WEBP";
	return type === "image/x-icon" && body.length >= 22 && body[0] === 0 && body[1] === 0 && body[2] === 1 && body[3] === 0;
}
const publicHeaders = () => new Headers({ "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; sandbox", "cross-origin-resource-policy": "cross-origin", "access-control-allow-origin": "*" });
export default {
	async fetch(request: Request, env: BrandAssetEnvironment): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname.startsWith('/avatars/')) {
			try {return await ownedAvatarResponse(request,env) || new Response('Owned avatar unavailable.',{status:404,headers:{'cache-control':'private, no-store'}});}
			catch {return new Response('Owned avatar unavailable.',{status:503,headers:{'cache-control':'private, no-store','pragma':'no-cache','x-content-type-options':'nosniff'}});}
		}
		if (!validAssetPath(url.pathname) || url.search) return new Response("Not found", { status: 404 });
		const objectKey = url.pathname.slice(1);
		if (request.method === "PUT") {
			const body = await verifyAssetRequest(request, env.ALLAUTH_ASSET_SECRET);
			if (!body) return Response.json({ error: "A signed server upload is required." }, { status: 401, headers: { "cache-control": "no-store" } });
			const type = request.headers.get("content-type") || "";
			const extension = url.pathname.split(".").pop();
			const expected: Record<string, string> = { png: "image/png", jpg: "image/jpeg", webp: "image/webp", ico: "image/x-icon" };
			if (!body.length || !validImage(body, type) || expected[extension || ""] !== type) return Response.json({ error: "Invalid image file." }, { status: 400 });
			const object = await env.BRAND_ASSETS.put(objectKey, body, { onlyIf: new Headers({ "if-none-match": "*" }), httpMetadata: { contentType: type, cacheControl: "public, max-age=31536000, immutable" } });
			if (!object) return Response.json({ error: "This asset already exists." }, { status: 409 });
			return Response.json({ url: url.href }, { status: 201, headers: { "cache-control": "no-store" } });
		}
		if (!["GET", "HEAD"].includes(request.method)) return new Response("Method not allowed", { status: 405, headers: { allow: "GET, HEAD, PUT" } });
		const object = request.method === "HEAD" ? await env.BRAND_ASSETS.head(objectKey) : await env.BRAND_ASSETS.get(objectKey);
		if (!object) return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
		const headers = publicHeaders(); object.writeHttpMetadata(headers); headers.set("etag", object.httpEtag);
		if (request.headers.get("if-none-match") === object.httpEtag) return new Response(null, { status: 304, headers });
		return new Response(request.method === "HEAD" ? null : (object as R2ObjectBody).body, { headers });
	},
};
