import { existsSync, readFileSync } from "node:fs";
import { APIError } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { admin, haveIBeenPwned, username } from "better-auth/plugins";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { productionTwoFactor } from "../mfa";
import { allauthControl } from "./index";
import { canonicalDomain, canonicalIP, createControlSecurity, defaultSecurityPolicy, securityPolicySchema, securitySubject } from "./security";
import type { ControlDatabase, ControlEventInput, ControlPrincipal } from "./types";

describe("local security input boundaries", () => {
	it.each(["192.0.2.1", "2001:db8::1", "::1"])("accepts a literal address %s", (ip) => expect(canonicalIP(ip)).toBe(ip));
	it.each(["192.0.2.1, 203.0.113.1", "192.0.2.1:443", "192.000.2.1", "256.1.1.1", "2001:db8::1%eth0", "[::1]", " 192.0.2.1", "evil.example"])("rejects ambiguous or spoofable IP %s", (ip) => expect(canonicalIP(ip)).toBeNull());
	it("canonicalizes equivalent IPv6 and mapped IPv4", () => {
		expect(canonicalIP("2001:0DB8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
		expect(canonicalIP("::ffff:192.0.2.1")).toBe("192.0.2.1");
	});
	it("normalizes exact domains without accepting wildcard/URL/IP rules", () => {
		expect(canonicalDomain("Example.COM")).toBe("example.com");
		expect(canonicalDomain("bücher.example")).toBe("xn--bcher-kva.example");
		for (const input of ["*.example.com", "https://example.com", "example.com/path", "example.com.", "192.0.2.1", "localhost"]) expect(canonicalDomain(input)).toBeNull();
	});
	it("uses scoped secret-keyed subjects and never returns raw credentials or identities", async () => {
		const first = await securitySubject("fixture-secret-0000000000000000000000", "fail-ip-identity", "192.0.2.1\0victim@example.com");
		expect(first).toMatch(/^fail-ip-identity:[a-f\d]{64}$/);
		expect(first).not.toContain("192.0.2.1"); expect(first).not.toContain("victim");
		expect(await securitySubject("different-fixture-secret-0000000000", "fail-ip-identity", "192.0.2.1\0victim@example.com")).not.toBe(first);
	});
	it("strictly bounds policy edits", () => {
		expect(securityPolicySchema.parse(defaultSecurityPolicy)).toEqual(defaultSecurityPolicy);
		for (const change of [{ maxFailuresPerIp: 0 }, { blockSeconds: 86401 }, { logRetentionDays: 6 }, { logRetentionDays: 366 }, { injected: true }, { blockedEmailDomains: ["*.example.com"] }]) expect(securityPolicySchema.safeParse({ ...defaultSecurityPolicy, ...change }).success).toBe(false);
	});
	it("covers native username, wallet, One Tap and phone completions without counting anonymous sessions", () => {
		const security = createControlSecurity({ database: {} as ControlDatabase, secret: "fixture-secret-0000000000000000000000", baseURL: "https://allauth.example", ipHeader: "x-real-ip", requireAdmin: async () => { throw new APIError("FORBIDDEN"); }, recordEvent: async () => {} });
		const hookContext = (path: string) => ({ path }) as Parameters<typeof security.hooks.before[0]["matcher"]>[0];
		for (const path of ["/sign-in/username", "/sign-in/phone-number", "/phone-number/verify", "/siwe/verify", "/one-tap/callback", "/passkey/verify-authentication"]) {
			expect(security.hooks.before[0].matcher(hookContext(path))).toBe(true);
			expect(security.hooks.after[0].matcher(hookContext(path))).toBe(true);
			expect(security.hooks.after[1].matcher(hookContext(path))).toBe(true);
		}
		for (const path of ["/siwe/nonce", "/siwe/get-nonce", "/phone-number/send-otp", "/passkey/generate-authenticate-options"]) expect(security.hooks.before[0].matcher(hookContext(path))).toBe(true);
		expect(security.hooks.after[1].matcher(hookContext("/sign-in/anonymous"))).toBe(false);
	});
	it("checks a returning wallet's stored email even when the caller submits a different email", async () => {
		let queries = 0;
		const database = { getExecutor: () => ({ transformQuery: (query: unknown) => query, compileQuery: () => ({}), executeQuery: async () => ({ rows: queries++ === 0 ? [] : [{ id: "fixture-rule", type: "email-domain" }] }) }) } as unknown as ControlDatabase;
		const security = createControlSecurity({ database, secret: "fixture-secret-0000000000000000000000", baseURL: "https://allauth.example", ipHeader: "x-real-ip", requireAdmin: async () => { throw new APIError("FORBIDDEN"); }, recordEvent: async () => {} });
		const findOne = vi.fn(async () => ({ email: "stored@blocked.example" }));
		const ctx = { path: "/siwe/verify", body: { email: "forged@allowed.example" }, context: { adapter: { findOne } } } as unknown as Parameters<typeof security.validateSession>[1];
		await expect(security.validateSession("fixture-user", ctx)).rejects.toMatchObject({ statusCode: 429 });
		expect(findOne).toHaveBeenCalledWith({ model: "user", where: [{ field: "id", value: "fixture-user" }], select: ["email"] });
	});
	it.each(["/email-otp/verify-email", "/callback/google", "/oauth2/callback/allauth", "/sso/callback/fixture", "/sso/saml2/sp/acs/fixture"])("checks a returning identity before a primary session is admitted on %s", async (path) => {
		let queries = 0;
		const database = { getExecutor: () => ({ transformQuery: (query: unknown) => query, compileQuery: () => ({}), executeQuery: async () => ({ rows: queries++ === 0 ? [] : [{ id: "fixture-rule", type: "email-domain" }] }) }) } as unknown as ControlDatabase;
		const security = createControlSecurity({ database, secret: "fixture-secret-0000000000000000000000", baseURL: "https://allauth.example", ipHeader: "x-real-ip", requireAdmin: async () => { throw new APIError("FORBIDDEN"); }, recordEvent: async () => {} });
		const findOne = vi.fn(async () => ({ email: "stored@blocked.example" }));
		const ctx = { path, context: { adapter: { findOne } } } as unknown as Parameters<typeof security.validateSession>[1];
		await expect(security.validateSession("fixture-user", ctx)).rejects.toMatchObject({ statusCode: 429 });
		expect(findOne).toHaveBeenCalledWith({ model: "user", where: [{ field: "id", value: "fixture-user" }], select: ["email"] });
	});
});

const fixturePath = new URL("../../../../.secrets/security-test-database.json", import.meta.url);
const fixtureAvailable = existsSync(fixturePath);
describe.skipIf(!fixtureAvailable)("PostgreSQL security atomicity and native authentication", () => {
	const secret = "fixture-security-secret-longer-than-thirty-two-characters";
	const baseURL = "http://localhost:3000";
	let database: Kysely<Record<string, Record<string, unknown>>>;
	let clock = new Date("2026-10-07T10:00:00.000Z");
	const events: ControlEventInput[] = [];
	const notifications = vi.fn();
	let security: ReturnType<typeof createControlSecurity>;
	const makeInstance = () => getTestInstance({ database: { db: database, type: "postgres", transaction: true }, secret, baseURL, plugins: [admin(), username(), productionTwoFactor(baseURL), allauthControl({ database, secret, baseURL, ipHeader: "x-real-ip", requireTrustedIP: true, onVerifiedNewDevice: notifications })] }, { disableTestUser: true });
	let instance: Awaited<ReturnType<typeof makeInstance>>;
	let userId: string;
	const principal: ControlPrincipal = { session: { id: "fixture-session", userId: "fixture-user" }, user: { id: "fixture-user", name: "Fixture", email: "fixture@example.com", emailVerified: true, role: "admin" } };
	const headers = (ip = "192.0.2.10") => new Headers({ origin: baseURL, "x-real-ip": ip, "user-agent": "Fixture Browser" });
	const context = (ip = "192.0.2.10", email = "victim@example.com") => ({ path: "/sign-in/email", headers: headers(ip), body: { email, password: "a-private-fixture-password" }, context: { returned: new APIError("UNAUTHORIZED", { code: "INVALID_EMAIL_OR_PASSWORD" }), baseURL } }) as unknown as Parameters<typeof security.recordFailure>[0];
	beforeAll(async () => {
		const fixture: { fixture: string; url: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.url);
		if (fixture.fixture !== "allauth-security-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55447" || url.pathname !== "/security_fixture") throw new Error("Security tests must target their isolated local fixture.");
		database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.url, max: 8 }) }) });
		await sql`DROP SCHEMA public CASCADE; CREATE SCHEMA public`.execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/001-initial-auth.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/002-control-plane.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/005-free-plugins.sql", import.meta.url), "utf8")).execute(database);
		await sql.raw(readFileSync(new URL("../../migrations/006-analytics.sql", import.meta.url), "utf8")).execute(database);
		security = createControlSecurity({ database, secret, baseURL, ipHeader: "x-real-ip", requireTrustedIP: true, now: () => clock, requireAdmin: async () => principal, recordEvent: async (_ctx, event) => { events.push(event); }, notifyNewDevice: notifications });
		instance = await makeInstance();
		const result = await instance.auth.api.signUpEmail({ headers: headers(), body: { email: "native-fixture@example.com", password: "fixture-native-password", name: "Fixture" } });
		userId = result.user.id;
		await sql`UPDATE "user" SET "emailVerified" = true WHERE "id" = ${userId}`.execute(database);
	});
	beforeEach(async () => {
		clock = new Date("2026-10-07T10:00:00.000Z"); events.length = 0; notifications.mockClear();
		await sql`TRUNCATE "allauthSecurityPolicy", "allauthSecurityCounter", "allauthSecurityRule", "allauthKnownDevice", "allauthEvent"`.execute(database);
		await sql`UPDATE "user" SET "twoFactorEnabled" = false, "emailVerified" = true, "role" = 'user' WHERE "id" = ${userId}`.execute(database);
	});
	afterAll(async () => { await database?.destroy(); });
	it("increments simultaneous failures without losing updates and enforces the shared process limit", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxFailuresPerIp: 20 });
		await Promise.all(Array.from({ length: 30 }, (_, index) => security.recordFailure(context("192.0.2.10", `account-${index}@example.com`))));
		const row = (await sql<{ count: number; key: string }>`SELECT "count", "key" FROM "allauthSecurityCounter" WHERE "scope" = 'fail-ip'`.execute(database)).rows[0];
		expect(row.count).toBe(30); expect(row.key).not.toContain("192.0.2.10");
		await expect(security.beforeRequest(context())).rejects.toMatchObject({ statusCode: 429 });
		await expect(security.beforeRequest(context("203.0.113.10"))).resolves.toBeUndefined();
	});
	it("keeps identity counters tied to IP rather than locking a victim globally", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxFailuresPerIp: 3 });
		await Promise.all(Array.from({ length: 3 }, () => security.recordFailure(context())));
		await expect(security.beforeRequest(context())).rejects.toMatchObject({ statusCode: 429 });
		await expect(security.beforeRequest(context("203.0.113.10", "victim@example.com"))).resolves.toBeUndefined();
		const rows = (await sql<{ key: string }>`SELECT "key" FROM "allauthSecurityCounter"`.execute(database)).rows;
		expect(JSON.stringify(rows)).not.toContain("victim@example.com"); expect(JSON.stringify(rows)).not.toContain("fixture-password");
	});
	it("expires temporary blocks and resets the failure window", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxFailuresPerIp: 3, failureWindowSeconds: 60, blockSeconds: 60 });
		for (let index = 0; index < 3; index++) await security.recordFailure(context());
		clock = new Date(clock.getTime() + 60_001);
		await expect(security.beforeRequest(context())).resolves.toBeUndefined();
		await security.recordFailure(context());
		expect((await sql<{ count: number }>`SELECT "count" FROM "allauthSecurityCounter" WHERE "scope" = 'fail-ip'`.execute(database)).rows[0].count).toBe(1);
	});
	it("monitor mode records would-block matches while allowing native requests", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, mode: "monitor", maxFailuresPerIp: 3 });
		for (let index = 0; index < 3; index++) await security.recordFailure(context());
		await expect(security.beforeRequest(context())).resolves.toBeUndefined();
		expect(events.at(-1)).toMatchObject({ type: "security.blocked", outcome: "success", metadata: { monitor: true } });
	});
	it("trusts only the configured proxy header and rejects forged forwarded fallbacks", async () => {
		const spoofed = context(); spoofed.headers = new Headers({ "x-forwarded-for": "192.0.2.10", "cf-connecting-ip": "192.0.2.10" });
		await expect(security.beforeRequest(spoofed)).rejects.toMatchObject({ statusCode: 429 });
		spoofed.headers.set("x-real-ip", "192.0.2.10, 203.0.113.10");
		await expect(security.beforeRequest(spoofed)).rejects.toMatchObject({ statusCode: 429 });
	});
	it("honors explicit exact-match rules and expiry without banning parent-domain users", async () => {
		await sql`INSERT INTO "allauthSecurityRule" ("id", "type", "value", "reason", "expiresAt") VALUES (${crypto.randomUUID()}, 'email-domain', 'disposable.example', 'Fixture block', ${new Date(clock.getTime() + 60_000)})`.execute(database);
		await expect(security.beforeRequest(context("192.0.2.10", "someone@disposable.example"))).rejects.toMatchObject({ statusCode: 429 });
		await expect(security.beforeRequest(context("192.0.2.10", "someone@sub.disposable.example"))).resolves.toBeUndefined();
		clock = new Date(clock.getTime() + 60_001);
		await expect(security.beforeRequest(context("192.0.2.10", "someone@disposable.example"))).resolves.toBeUndefined();
	});
	it("atomically limits new identities including provider callbacks", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxSignUpsPerIp: 3 });
		const data = { user: { email: "signup@example.com" }, source: { action: "create-user" as const, method: "email-password" as const } };
		const results = await Promise.allSettled(Array.from({ length: 10 }, () => security.validateUserInfo(data, context())));
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(3);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(7);
		await security.updatePolicy({ ...defaultSecurityPolicy, blockedEmailDomains: ["blocked.example"] });
		await expect(security.validateUserInfo({ user: { email: "oauth@blocked.example" }, source: { action: "create-user", method: "oauth", oauth: { providerId: "google", profile: {} } } }, context("203.0.113.10"))).rejects.toMatchObject({ statusCode: 429 });
	});
	it("caps email/challenge request velocity and removes expired counter rows", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxSignUpsPerIp: 1 });
		const request = context(); request.path = "/request-password-reset";
		for (let index = 0; index < 5; index++) await security.beforeRequest(request);
		await expect(security.beforeRequest(request)).rejects.toMatchObject({ statusCode: 429 });
		clock = new Date(clock.getTime() + 3 * 86400_000);
		await security.beforeRequest(context());
		expect((await sql`SELECT "key" FROM "allauthSecurityCounter"`.execute(database)).rows).toHaveLength(0);
	});
	it("checks fresh stored identity for returning passkey sessions that have no submitted email", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, blockedEmailDomains: ["example.com"] });
		const request = context(); request.path = "/passkey/verify-authentication"; request.body = {};
		request.context.adapter = (await instance.auth.$context).adapter as typeof request.context.adapter;
		await expect(security.validateSession(userId, request)).rejects.toMatchObject({ statusCode: 429 });
		request.path = "/siwe/verify"; request.body = { email: "submitted@allowed.example" };
		await expect(security.validateSession(userId, request)).rejects.toMatchObject({ statusCode: 429 });
		request.path = "/admin/impersonate-user";
		await expect(security.validateSession(userId, request)).resolves.toBeUndefined();
	});
	it("counts real native username failures with hashed IP-scoped identities and enforces stored domains", async () => {
		await sql`UPDATE "user" SET "username" = 'nativefixture' WHERE "id" = ${userId}`.execute(database);
		const login = (submittedPassword: string) => instance.auth.handler(new Request(`${baseURL}/api/auth/sign-in/username`, { method: "POST", headers: new Headers({ ...Object.fromEntries(headers()), "content-type": "application/json" }), body: JSON.stringify({ username: "nativefixture", password: submittedPassword }) }));
		await security.updatePolicy({ ...defaultSecurityPolicy, blockedEmailDomains: ["example.com"] });
		expect((await login("fixture-native-password")).status).toBe(429);
		await sql`TRUNCATE "allauthSecurityCounter", "allauthEvent"`.execute(database);
		await security.updatePolicy({ ...defaultSecurityPolicy, maxFailuresPerIp: 3 });
		for (let index = 0; index < 3; index++) expect((await login("wrong-fixture-password")).status).toBe(401);
		const rows = (await sql<{ key: string; scope: string; count: number }>`SELECT "key", "scope", "count" FROM "allauthSecurityCounter"`.execute(database)).rows;
		expect(rows).toHaveLength(2); expect(rows.every((row) => row.count === 3)).toBe(true); expect(JSON.stringify(rows)).not.toContain("nativefixture"); expect(JSON.stringify(rows)).not.toContain("192.0.2.10");
		expect((await login("fixture-native-password")).status).toBe(429);
	});
	const signIn = async (extraHeaders?: Headers) => {
		const requestHeaders = extraHeaders ?? headers(); requestHeaders.set("content-type", "application/json");
		return instance.auth.handler(new Request(`${baseURL}/api/auth/sign-in/email`, { method: "POST", headers: requestHeaders, body: JSON.stringify({ email: "native-fixture@example.com", password: "fixture-native-password" }) }));
	};
	it("records baseline device silently and recognizes only a valid signed device token", async () => {
		const first = await signIn(); expect(first.status).toBe(200); expect(notifications).not.toHaveBeenCalled();
		const cookie = first.headers.getSetCookie().find((entry) => entry.startsWith("better-auth.control_device="))?.split(";")[0]; expect(cookie).toBeDefined();
		const sameDevice = headers(); sameDevice.set("cookie", cookie!); expect((await signIn(sameDevice)).status).toBe(200); expect(notifications).not.toHaveBeenCalled();
		const forged = headers(); forged.set("cookie", `${cookie!.slice(0, -1)}${cookie!.endsWith("a") ? "b" : "a"}`); expect((await signIn(forged)).status).toBe(200);
		expect(notifications).toHaveBeenCalledTimes(1);
		expect((await sql`SELECT "id" FROM "allauthKnownDevice"`.execute(database)).rows).toHaveLength(2);
		expect(first.headers.get("set-cookie")).toContain("HttpOnly"); expect(first.headers.get("set-cookie")).toContain("SameSite=Lax");
	});
	it("never announces a new device while the native MFA challenge is pending", async () => {
		expect((await signIn()).status).toBe(200);
		await sql`UPDATE "user" SET "twoFactorEnabled" = true WHERE "id" = ${userId}`.execute(database);
		const response = await signIn(); expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ twoFactorRedirect: true });
		expect(notifications).not.toHaveBeenCalled(); expect(response.headers.getSetCookie().some((entry) => entry.startsWith("better-auth.control_device="))).toBe(false);
		expect((await sql`SELECT "id" FROM "allauthKnownDevice"`.execute(database)).rows).toHaveLength(1);
	});
	it("tracks native failed password responses and blocks the subsequent request", async () => {
		await security.updatePolicy({ ...defaultSecurityPolicy, maxFailuresPerIp: 3 });
		for (let index = 0; index < 3; index++) {
			const result = await instance.auth.handler(new Request(`${baseURL}/api/auth/sign-in/email`, { method: "POST", headers: new Headers({ ...Object.fromEntries(headers()), "content-type": "application/json" }), body: JSON.stringify({ email: "native-fixture@example.com", password: "wrong-fixture-password" }) }));
			expect(result.status).toBe(401);
		}
		expect((await signIn()).status).toBe(429); expect(notifications).not.toHaveBeenCalled();
		expect((await sql`SELECT "id" FROM "allauthEvent" WHERE "type" = 'security.sign-in-failed'`.execute(database)).rows).toHaveLength(3);
	});
	it("exposes security controls only to a fresh verified administrator and rejects cross-origin writes", async () => {
		const anon = await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security`, { headers: headers() })); expect(anon.status).toBe(401);
		const login = await signIn(); const cookies = login.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; ");
		const administratorHeaders = headers(); administratorHeaders.set("cookie", cookies);
		expect((await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security`, { headers: administratorHeaders }))).status).toBe(403);
		await sql`UPDATE "user" SET "role" = 'user,admin' WHERE "id" = ${userId}`.execute(database);
		const allowed = await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security`, { headers: administratorHeaders })); expect(allowed.status).toBe(200); expect(allowed.headers.get("cache-control")).toBe("no-store");
		const body = await allowed.json(); expect(body).toMatchObject({ policy: defaultSecurityPolicy, capabilities: { botChallenge: false, impossibleTravel: false, breachedPasswords: false, newDeviceNotifications: true } });
		const wrongOrigin = new Headers(administratorHeaders); wrongOrigin.set("origin", "https://evil.example"); wrongOrigin.set("content-type", "application/json");
		const forbidden = await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security/update`, { method: "POST", headers: wrongOrigin, body: JSON.stringify({ policy: { ...defaultSecurityPolicy, mode: "monitor" } }) })); expect(forbidden.status).toBe(403);
		administratorHeaders.set("content-type", "application/json");
		const edited = await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security/update`, { method: "POST", headers: administratorHeaders, body: JSON.stringify({ policy: { ...defaultSecurityPolicy, mode: "monitor" } }) })); expect(edited.status).toBe(200);
		await sql`UPDATE "user" SET "emailVerified" = false WHERE "id" = ${userId}`.execute(database);
		expect((await instance.auth.handler(new Request(`${baseURL}/api/auth/control/security`, { headers: administratorHeaders }))).status).toBe(403);
	});
	it("validates and canonicalizes native rule writes, then removes only the selected rule", async () => {
		await sql`UPDATE "user" SET "role" = 'admin' WHERE "id" = ${userId}`.execute(database);
		const login = await signIn(); const adminHeaders = headers(); adminHeaders.set("cookie", login.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; ")); adminHeaders.set("content-type", "application/json");
		const post = (path: string, body: unknown) => instance.auth.handler(new Request(`${baseURL}/api/auth${path}`, { method: "POST", headers: adminHeaders, body: JSON.stringify(body) }));
		expect((await post("/control/security/rules/add", { type: "ip", value: "192.0.2.20, 192.0.2.21", reason: "Invalid fixture" })).status).toBe(400);
		const add = await post("/control/security/rules/add", { type: "ip", value: "2001:0DB8:0000:0000:0000:0000:0000:0020", reason: "Fixture block" }); expect(add.status).toBe(200);
		const { rule } = await add.json() as { rule: { id: string; value: string } }; expect(rule.value).toBe("2001:db8::20");
		const expired = await post("/control/security/rules/add", { type: "email-domain", value: "example.com", reason: "Expired fixture", expiresAt: "2000-01-01T00:00:00.000Z" }); expect(expired.status).toBe(400);
		const remove = await post("/control/security/rules/remove", { id: rule.id }); expect(remove.status).toBe(200); expect(await remove.json()).toEqual({ success: true });
		expect((await sql`SELECT "id" FROM "allauthSecurityRule"`.execute(database)).rows).toHaveLength(0);
	});
	it("reports breached-password protection only when the native check is actually enabled", async () => {
		await sql`UPDATE "user" SET "role" = 'admin' WHERE "id" = ${userId}`.execute(database);
		const login = await signIn(); const adminHeaders = headers(); adminHeaders.set("cookie", login.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; "));
		for (const enabled of [true, false]) {
			const checked = await getTestInstance({ database: { db: database, type: "postgres", transaction: true }, secret, baseURL, plugins: [admin(), haveIBeenPwned({ enabled }), allauthControl({ database, secret, baseURL, ipHeader: "x-real-ip", requireTrustedIP: true })] }, { disableTestUser: true });
			const response = await checked.auth.handler(new Request(`${baseURL}/api/auth/control/security`, { headers: adminHeaders }));
			expect(response.status).toBe(200); expect(await response.json()).toMatchObject({ capabilities: { breachedPasswords: enabled } });
		}
	});
});
