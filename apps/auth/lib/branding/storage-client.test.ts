import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyAssetRequest } from "./asset-signature";
import { storeBrandingAsset } from "./storage-client";
import { validateBrandingAsset } from "./validation";

const scope = { workspaceId: "75458045-7c45-49cc-83de-a56a7b5d19c3", applicationId: "0da0e1b9-bb92-4182-8bfb-cbed290b0c19" };
const secret = "fixture-storage-credential-longer-than-thirty-two";
const env = { ALLAUTH_ASSET_ORIGIN: "https://assets.allauth.co", ALLAUTH_ASSET_SECRET: secret };
const asset = () => validateBrandingAsset("logo", Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh1kAAAAASUVORK5CYII=", "base64")), "image/png");
afterEach(() => vi.unstubAllGlobals());
describe("private asset storage client", () => {
	it("sends only body-bound signed immutable PUTs and validates the Worker URL", async () => {
		const urls: string[] = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const request = new Request(input, init); urls.push(request.url);
			expect(request.method).toBe("PUT"); expect(request.headers.get("authorization")).toBeNull();
			expect(await verifyAssetRequest(request, secret)).toEqual(asset().bytes);
			expect(init?.redirect).toBe("error"); expect(init?.cache).toBe("no-store");
			return Response.json({ url: request.url }, { status: 201 });
		});
		const first = await storeBrandingAsset(asset(), scope, env); const second = await storeBrandingAsset(asset(), scope, env);
		expect(first).toContain(`/branding/${scope.workspaceId}/${scope.applicationId}/`); expect(first).not.toBe(second); expect(urls).toHaveLength(2);
	});
	it("fails closed on absent storage, wrong URLs, redirects/errors without returning provider secrets", async () => {
		const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
		await expect(storeBrandingAsset(asset(), scope, { ...env, ALLAUTH_ASSET_SECRET: "" })).rejects.toMatchObject({ statusCode: 503 }); expect(fetch).not.toHaveBeenCalled();
		fetch.mockResolvedValue(Response.json({ url: "https://foreign.example/asset.png" }, { status: 201 })); await expect(storeBrandingAsset(asset(), scope, env)).rejects.toMatchObject({ statusCode: 503 });
		fetch.mockRejectedValue(new Error(secret));
		try { await storeBrandingAsset(asset(), scope, env); throw new Error("Expected rejection"); } catch (error) { expect(JSON.stringify(error)).not.toContain(secret); expect(error).toMatchObject({ statusCode: 503 }); }
	});
});
