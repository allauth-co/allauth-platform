import { describe, expect, it } from "vitest";
import {
	parseApplicationBinding,
	parseRedirectUris,
} from "./applications-utils";

describe("application redirect registration", () => {
	it("keeps exact callbacks, trims lines, and removes duplicates", () => {
		expect(
			parseRedirectUris(
				" https://app.example.com/callback?source=auth\n\nhttps://app.example.com/callback?source=auth\nhttp://localhost:3000/callback ",
				true,
			),
		).toEqual([
			"https://app.example.com/callback?source=auth",
			"http://localhost:3000/callback",
		]);
	});
	it("rejects HTTP localhost without an explicit per-client permission", () => {
		expect(() => parseRedirectUris("http://localhost:3000/callback")).toThrow();
	});
	it.each([
		"http://localhost:3000/callback",
		"http://127.0.0.1:5173/callback",
		"http://[::1]:3000/callback",
	])("permits exact development callback %s when approved", (uri) => {
		expect(parseRedirectUris(uri, true)).toEqual([uri]);
	});
	it.each([
		"http://127.1/callback",
		"http://2130706433/callback",
		"http://0x7f000001/callback",
		"http://0177.0.0.1/callback",
		"http://[0:0:0:0:0:0:0:1]/callback",
		"http://localhost.example.com/callback",
		"http://localhost./callback",
		"http://127.0.0.1\\evil/callback",
		"http://localhost:3000/callback#token",
		"https://%2A.example.com/callback",
	])("rejects alias or unsafe callback %s even when localhost is approved", (uri) => {
		expect(() => parseRedirectUris(uri, true)).toThrow();
	});
	it.each([
		"",
		"not-a-url",
		"http://app.example.com/callback",
		"https://app.example.com/callback#token",
		"https://user:secret@app.example.com/callback",
		"https://*.example.com/callback",
		"javascript:alert(1)",
	])("rejects unsafe or absent callback %s", (uri) => {
		expect(() => parseRedirectUris(uri)).toThrow();
	});
});

describe("application resource and organization bindings", () => {
	it("preserves the exact audience URI and deduplicates organization IDs", () => {
		expect(
			parseApplicationBinding(
				" org-one\norg-two\norg-one ",
				" https://app.example.com/api ",
			),
		).toEqual({
			organizationIds: ["org-one", "org-two"],
			resourceURI: "https://app.example.com/api",
		});
		expect(
			parseApplicationBinding("org-one", "https://app.example.com/api/")
				.resourceURI,
		).toBe("https://app.example.com/api/");
	});
	it("supports an explicit resource audience without organization claims", () => {
		expect(parseApplicationBinding("", "https://app.example.com/api")).toEqual({
			organizationIds: [],
			resourceURI: "https://app.example.com/api",
		});
	});
	it("supports an unbound identity-only client", () => {
		expect(parseApplicationBinding("", "")).toEqual({ organizationIds: [] });
	});
	it("requires an audience for every organization-bound client", () => {
		expect(() => parseApplicationBinding("org-one", "")).toThrow();
	});
	it.each([
		"http://app.example.com/api",
		"https://user:secret@app.example.com/api",
		"https://app.example.com/api#tenant",
		"https://*.example.com/api",
		"https://%2A.example.com/api",
		"not-a-url",
	])("rejects unsafe audience %s", (uri) => {
		expect(() => parseApplicationBinding("org-one", uri)).toThrow();
	});
	it("bounds the number and size of approved organizations", () => {
		expect(() =>
			parseApplicationBinding(
				Array.from({ length: 101 }, (_, index) => `org-${index}`).join("\n"),
				"https://app.example.com/api",
			),
		).toThrow();
		expect(() =>
			parseApplicationBinding("a".repeat(201), "https://app.example.com/api"),
		).toThrow();
	});
});
