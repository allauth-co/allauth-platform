import { describe, expect, it } from "vitest";
import { signAssetHeaders } from "../lib/branding/asset-signature";
import worker from "./brand-assets";

const secret = "test-asset-secret-long-enough-to-sign-test-uploads";
const url = "https://assets.allauth.co/branding/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002/00000000-0000-4000-8000-000000000003.png";
const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, ...Array(16).fill(0)]);
function fixture() {
	let saved: Uint8Array | undefined;
	let writes = 0;
	const object = () => saved ? { body: new Blob([new Uint8Array(saved)]).stream(), httpEtag: '"asset"', writeHttpMetadata: (headers: Headers) => headers.set("content-type", "image/png") } : null;
	const bucket = {
		put: async (_key: string, bytes: Uint8Array, options: { onlyIf: Headers }) => {
			expect(options.onlyIf.get("if-none-match")).toBe("*");
			writes++; if (saved) return null; saved = bytes; return object();
		}, get: async () => object(), head: async () => object(),
	};
	return { env: { BRAND_ASSETS: bucket as unknown as R2Bucket, ALLAUTH_ASSET_SECRET: secret }, writes: () => writes };
}
async function signed(bytes = png) {
	const request = new Request(url, { method: "PUT", headers: { "content-type": "image/png" }, body: bytes });
	return new Request(url, { method: "PUT", headers: await signAssetHeaders(request, secret), body: bytes });
}
describe("Cloudflare brand asset gateway", () => {
	it("rejects unsigned, invalid-file and out-of-scope uploads before any storage write", async () => {
		const { env, writes } = fixture();
		expect((await worker.fetch(new Request(url, { method: "PUT", body: png }), env)).status).toBe(401);
		expect((await worker.fetch(await signed(new Uint8Array(24)), env)).status).toBe(400);
		expect((await worker.fetch(new Request("https://assets.allauth.co/list"), env)).status).toBe(404);
		expect((await worker.fetch(new Request(url, { method: "DELETE" }), env)).status).toBe(405);
		expect(writes()).toBe(0);
	});
	it("publishes immutable image bytes and refuses replacement, with safe cache and content headers", async () => {
		const { env } = fixture();
		expect((await worker.fetch(await signed(), env)).status).toBe(201);
		expect((await worker.fetch(await signed(), env)).status).toBe(409);
		const response = await worker.fetch(new Request(url), env);
		expect(new Uint8Array(await response.arrayBuffer())).toEqual(png);
		expect(response.headers.get("content-type")).toBe("image/png");
		expect(response.headers.get("cache-control")).toContain("immutable");
		expect(response.headers.get("x-content-type-options")).toBe("nosniff");
		expect(response.headers.get("content-security-policy")).toContain("sandbox");
		expect(await (await worker.fetch(new Request(url, { method: "HEAD" }), env)).text()).toBe("");
		expect((await worker.fetch(new Request(url, { headers: { "if-none-match": '"asset"' } }), env)).status).toBe(304);
	});
});
