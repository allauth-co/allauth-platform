import { describe, expect, it } from "vitest";
import { hasOrganizationAdminRole, requireHTTPSURL } from "./sso-utils";

describe("organization SSO management access", () => {
	it.each([
		"owner",
		"admin",
		"member, admin",
		" owner , member",
	])("allows the exact organization manager role %s", (role) => {
		expect(hasOrganizationAdminRole(role)).toBe(true);
	});
	it.each([
		undefined,
		null,
		"",
		"member",
		"superadmin",
		"application-admin",
		"viewer,member",
	])("denies non-manager membership %s", (role) => {
		expect(hasOrganizationAdminRole(role)).toBe(false);
	});
});

describe("production SSO authority URLs", () => {
	it("preserves the issuer exactly rather than normalizing its trailing slash", () => {
		expect(
			requireHTTPSURL(" https://login.example.com/tenant ", "Issuer"),
		).toBe("https://login.example.com/tenant");
	});
	it.each([
		"http://login.example.com",
		"file:///issuer",
		"https://user:secret@login.example.com",
		"https://login.example.com#issuer",
		"login.example.com",
	])("rejects an unsafe issuer %s", (url) => {
		expect(() => requireHTTPSURL(url, "Issuer")).toThrow();
	});
});
