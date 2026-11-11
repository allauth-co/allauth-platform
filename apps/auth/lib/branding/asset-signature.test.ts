import { describe, expect, it } from "vitest";
import { boundedAssetBody, maxAssetBody, signAssetHeaders, validAssetPath, verifyAssetRequest } from "./asset-signature";
const origin = "https://assets.allauth.co";
const path = "/branding/75458045-7c45-49cc-83de-a56a7b5d19c3/0da0e1b9-bb92-4182-8bfb-cbed290b0c19/00000000-0000-4000-8000-000000000005.png";
const secret = "isolated-asset-test-secret-with-32-or-more-characters";
const time = Date.UTC(2026, 9, 7, 8, 0, 0);
function upload(url = origin + path, body = "fixture image bytes", type = "image/png") { return new Request(url, { method: "PUT", headers: { "content-type": type }, body }); }
async function signed() { const request = upload(); return new Request(request, { headers: await signAssetHeaders(request, secret, time) }); }
describe("private brand asset upload envelope", () => {
	it("accepts an intact body and rejects unsigned writes or a different credential", async () => {
		expect(new TextDecoder().decode((await verifyAssetRequest(await signed(), secret, time))!)).toBe("fixture image bytes");
		expect(await verifyAssetRequest(upload(), secret, time)).toBeNull();
		expect(await verifyAssetRequest(await signed(), secret + "foreign", time)).toBeNull();
	});
	it("binds the exact body, tenant asset path, MIME type and method", async () => {
		const headers = (await signed()).headers;
		for (const request of [
			new Request(origin + path, { method: "PUT", headers, body: "changed" }),
			new Request(origin + path.replace("000000000005", "000000000006"), { method: "PUT", headers, body: "fixture image bytes" }),
			new Request(origin + path, { method: "PUT", headers: { ...Object.fromEntries(headers), "content-type": "image/jpeg" }, body: "fixture image bytes" }),
			new Request(origin + path, { method: "POST", headers, body: "fixture image bytes" }),
		]) expect(await verifyAssetRequest(request, secret, time)).toBeNull();
	});
	it("expires envelopes and rejects query-string aliases", async () => {
		expect(await verifyAssetRequest(await signed(), secret, time + 61000)).toBeNull();
		expect(await verifyAssetRequest(await signed(), secret, time - 61000)).toBeNull();
		await expect(signAssetHeaders(upload(origin + path + "?alias=1"), secret, time)).rejects.toThrow("Invalid asset upload path");
	});
	it("allows only flat image keys inside the immutable tenant/application namespace", () => {
		expect(validAssetPath(path)).toBe(true);
		for (const invalid of ["/", path.replace(".png", ".svg"), path.replace(".png", ".html"), path + "/suffix", "/branding/../" + path, path.replace("75458045", "not-an-id")]) expect(validAssetPath(invalid)).toBe(false);
	});
	it("bounds both declared and streamed request bodies before storage", async () => {
		await expect(boundedAssetBody(new Request(origin + path, { method: "PUT", headers: { "content-length": String(maxAssetBody + 1) }, body: "small" }))).rejects.toThrow("2 MB");
		await expect(boundedAssetBody(new Request(origin + path, { method: "PUT", body: new Uint8Array(maxAssetBody + 1) }))).rejects.toThrow("2 MB");
		expect((await boundedAssetBody(new Request(origin + path, { method: "PUT", body: new Uint8Array(maxAssetBody) }))).length).toBe(maxAssetBody);
	});
});
