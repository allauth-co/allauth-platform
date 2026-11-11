import { oauthProvider, verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createHash } from "node:crypto";
import { jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { isAuthenticationPath, localNavigation } from "../components/better-auth-ui/lib/navigation";

const origin = "http://localhost:3000";
const secret = "fixture-ui-oauth-secret-longer-than-thirty-two-characters";

/** @see https://www.better-auth.com/docs/plugins/oauth-provider#authorization-endpoint */
describe("official UI signed authorization continuation", () => {
	it("preserves the actual native signature, repeated manifest/resources and encoded plus across password, passkey and MFA views", async () => {
		const resources = ["https://api.fixture.example/a", "https://api.fixture.example/b"];
		const instance = await getTestInstance({ secret, logger: { disabled: true }, plugins: [jwt({ disableSettingJwtHeader: true }), oauthProvider({ loginPage: "/sign-in", consentPage: "/oauth/consent", resources, clientRegistrationDefaultResources: resources })] });
		const { headers } = await instance.signInWithTestUser();
		const client = await instance.auth.api.adminCreateOAuthClient({ headers, body: { client_name: "UI fixture", redirect_uris: ["https://app.fixture.example/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], require_pkce: true, skip_consent: true, scope: "openid profile" } });
		const verifier = "fixture-ui-pkce-verifier-with-at-least-forty-three-characters";
		let signed: URLSearchParams | undefined;
		for (let attempt = 0; attempt < 64; attempt++) {
			const params = new URLSearchParams({ client_id: client.client_id, response_type: "code", redirect_uri: "https://app.fixture.example/callback", scope: "openid profile", code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url"), state: `state+literal+${attempt}`, nonce: "nonce+literal" });
			params.append("resource", "https://api.fixture.example/a");
			params.append("resource", "https://api.fixture.example/b");
			const response = await instance.auth.handler(new Request(`${origin}/api/auth/oauth2/authorize?${params}`));
			expect(response.status).toBe(302);
			const target = new URL(response.headers.get("location") || "", origin);
			expect({ pathname: target.pathname, error: target.searchParams.get("error"), description: target.searchParams.get("error_description") }).toMatchObject({ pathname: "/sign-in", error: null });
			if (target.searchParams.get("sig")?.includes("+")) { signed = target.searchParams; break; }
		}
		if (!signed) throw new Error("The native authorization fixture did not produce a signature containing an encoded plus.");
		expect(signed.getAll("ba_param").length).toBeGreaterThan(4);
		expect(signed.getAll("resource")).toEqual(["https://api.fixture.example/a", "https://api.fixture.example/b"]);
		expect(await verifyOAuthQueryParams(signed.toString(), secret)).toBe(true);
		// Reproduce the old URLSearchParams.set loop's loss of duplicate signed entries.
		const collapsed = new URLSearchParams();
		for (const [key, value] of signed) collapsed.set(key, value);
		expect(await verifyOAuthQueryParams(collapsed.toString(), secret)).toBe(false);
		for (const path of ["/sign-up", "/sign-in", "/email-otp", "/magic-link", "/forgot-password", "/two-factor"]) {
			const destination = localNavigation(`${path}?ba_param=untrusted&resource=https%3A%2F%2Fevil.example&redirectTo=https%3A%2F%2Fevil.example`, origin, signed);
			const target = new URL(destination || "", origin);
			expect(target.searchParams.getAll("ba_param")).toEqual(signed.getAll("ba_param"));
			expect(target.searchParams.getAll("resource")).toEqual(signed.getAll("resource"));
			expect(target.searchParams.get("sig")).toBe(signed.get("sig"));
			expect(target.searchParams.get("state")).toBe(signed.get("state"));
			expect(target.searchParams.get("nonce")).toBe("nonce+literal");
			expect(target.searchParams.has("redirectTo")).toBe(false);
			expect(await verifyOAuthQueryParams(target.search.slice(1), secret)).toBe(true);
		}
	});
	it("preserves provider-signed consoleReturnTo extension values across authentication and sign-out views", async () => {
		const instance = await getTestInstance({ secret, logger: { disabled: true }, plugins: [jwt({ disableSettingJwtHeader: true }), oauthProvider({ loginPage: "/sign-in", consentPage: "/oauth/consent" })] });
		const { headers } = await instance.signInWithTestUser();
		const client = await instance.auth.api.adminCreateOAuthClient({ headers, body: { client_name: "Signed extension fixture", redirect_uris: ["https://app.fixture.example/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], require_pkce: true, skip_consent: true, scope: "openid profile" } });
		const verifier = "fixture-extension-pkce-verifier-with-at-least-forty-three-characters";
		const params = new URLSearchParams({ client_id: client.client_id, response_type: "code", redirect_uri: "https://app.fixture.example/callback", scope: "openid profile", code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url"), state: "extension-state" });
		// Custom provider-signed values are authorization data, regardless of account-menu URL policy.
		const extensionValues = ["/admin/users?workspace=workspace-a&token=signed-extension", "https://client.fixture.example/custom?context=signed+value"];
		for (const value of extensionValues) params.append("consoleReturnTo", value);
		const response = await instance.auth.handler(new Request(`${origin}/api/auth/oauth2/authorize?${params}`));
		expect(response.status).toBe(302);
		const signed = new URL(response.headers.get("location") || "", origin).searchParams;
		expect(signed.getAll("ba_param")).toContain("consoleReturnTo");
		expect(signed.getAll("consoleReturnTo")).toEqual(extensionValues);
		expect(await verifyOAuthQueryParams(signed.toString(), secret)).toBe(true);
		for (const path of ["/sign-in", "/sign-up", "/two-factor", "/sign-out"]) {
			const destination = localNavigation(`${path}?consoleReturnTo=untrusted`, origin, signed);
			const target = new URL(destination || "", origin);
			expect(target.searchParams.getAll("consoleReturnTo")).toEqual(extensionValues);
			expect(target.searchParams.getAll("ba_param")).toEqual(signed.getAll("ba_param"));
			expect(await verifyOAuthQueryParams(target.search.slice(1), secret)).toBe(true);
		}
	});
	it.each(["https://evil.example/account", "//evil.example/account", "/\\evil.example/account", "https://name:password@localhost:3000/account", "/api/auth/sign-in/email", "/account/../../api/auth/get-session"]) ("does not turn %s into a same-origin UI navigation", (destination) => {
		expect(localNavigation(destination, origin, new URLSearchParams({ client_id: "fixture" }))).toBeNull();
	});
	it("keeps signed request parameters off unrelated links and recognizes only exact challenge routes", () => {
		const current = new URLSearchParams("client_id=fixture&ba_param=client_id&ba_param=exp&sig=encoded%2Bsignature&token=reset-private");
		expect(localNavigation("/account/security#devices", origin, current)).toBe("/account/security#devices");
		expect(isAuthenticationPath("/two-factor")).toBe(true);
		expect(isAuthenticationPath("/two-factor/../account")).toBe(false);
	});
});
