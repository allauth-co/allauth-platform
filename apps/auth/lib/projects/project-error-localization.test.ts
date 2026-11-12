import { i18n, locales } from "@better-auth/i18n";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, it, vi } from "vitest";
import type { AuthEngine } from "../auth-engine";
import catalog from "./legacy-auth-error-messages.json";
import { localizeProjectErrors } from "./project-error-localization";

const origin = "https://accounts.fixture.example";
const code = "INVALID_EMAIL_OR_PASSWORD";
const message = "Invalid email or password";
const login = {
	email: "unregistered@fixture.example",
	password: "Synthetic-password-42!",
};

function engine(dispatch: AuthEngine["dispatch"]): AuthEngine {
	return {
		dispatch,
		readSession: dispatch,
		readIssuerMetadata: vi.fn(),
		readOAuthContext: vi.fn(),
		readPrincipal: vi.fn(),
		listAccountSessions: vi.fn(),
		revokeAccountSession: vi.fn(),
		readDirectory: vi.fn(),
	};
}

describe("project error localization", () => {
	it("preserves installed language negotiation, status and error shape", async () => {
		expect(catalog).toEqual(Object.fromEntries(Object.entries(locales)));
		const legacy = betterAuth({
			baseURL: origin,
			secret: "isolated-project-localization-fixture-secret",
			database: memoryAdapter({
				user: [],
				session: [],
				account: [],
				verification: [],
			}),
			emailAndPassword: { enabled: true },
			plugins: [
				i18n({
					translations: locales,
					defaultLocale: "en",
					detection: ["header"],
				}),
			],
		});
		const candidate = localizeProjectErrors(
			engine(async () => Response.json({ code, message }, { status: 401 })),
		);
		for (const acceptLanguage of [
			"fr-CA, en;q=0.8",
			"es;q=0.4, de-DE;q=0.9",
			"xx, ja;q=0.9",
			"xx",
			"",
		]) {
			const request = new Request(`${origin}/api/auth/sign-in/email`, {
				method: "POST",
				headers: {
					"accept-language": acceptLanguage,
					"content-type": "application/json",
					origin,
				},
				body: JSON.stringify(login),
			});
			const [native, owned] = await Promise.all([
				legacy.api.signInEmail({
					body: login,
					headers: { "accept-language": acceptLanguage },
					asResponse: true,
				}),
				candidate.dispatch(request),
			]);
			expect(native.status).toBe(401);
			expect(owned.status).toBe(native.status);
			expect(await owned.json()).toEqual(await native.json());
		}
	});

	it("keeps cookies and headers and leaves unrelated responses intact", async () => {
		const headers = new Headers({
			"cache-control": "no-store",
			"content-length": "42",
		});
		headers.append("set-cookie", "first=1; Path=/; Secure");
		headers.append("set-cookie", "second=2; Path=/; Secure");
		const invalid = Response.json({ code, message }, { status: 401, headers });
		const protocol = Response.json({ error: "invalid_grant" }, { status: 400 });
		const other = Response.json(
			{ code: "FORBIDDEN", message: "Refused" },
			{ status: 403 },
		);
		const success = Response.json({ status: true });
		const dispatch = vi
			.fn<AuthEngine["dispatch"]>()
			.mockResolvedValueOnce(invalid)
			.mockResolvedValueOnce(protocol)
			.mockResolvedValueOnce(other)
			.mockResolvedValueOnce(success);
		const candidate = localizeProjectErrors(engine(dispatch));
		const request = new Request(`${origin}/api/auth/get-session`, {
			headers: { "accept-language": "fr" },
		});
		const localized = await candidate.readSession(request);
		expect(await localized.json()).toMatchObject({
			code,
			message: catalog.fr.INVALID_EMAIL_OR_PASSWORD,
			originalMessage: message,
		});
		expect(localized.headers.getSetCookie()).toEqual(headers.getSetCookie());
		expect(localized.headers.get("cache-control")).toBe("no-store");
		expect(localized.headers.has("content-length")).toBe(false);
		for (const expected of [protocol, other, success])
			expect(await candidate.dispatch(request)).toBe(expected);
	});
});
