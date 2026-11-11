import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { passkey } from "@better-auth/passkey";
import type { BetterAuthPlugin } from "@better-auth/core";
import { APIError } from "better-auth";
import { symmetricDecrypt } from "better-auth/crypto";
import { parseSetCookieHeader } from "better-auth/cookies";
import { admin, emailOTP, organization, username } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { productionTwoFactor } from "../mfa";
import { isPlatformAdmin } from "../configuration";
import type { ControlPrincipal } from "./types";
import { allauthControl, controlEventsQuery } from "./index";
import { allauthControlClient } from "./client";
import { controlResponseFailure, isPrimaryAuthenticationPath, mutationEventType, publicControlEvent, sanitizeControlMetadata, writeControlEvent } from "./events";
import { pruneControlEvents } from "./queries";

const origin = "http://localhost:3000";
const applicationSchema = { id: "fixture-applications", schema: { oauthClient: { fields: { clientId: { type: "string", required: true } } } } } satisfies BetterAuthPlugin;

async function fixture(asAdmin = true) {
	const instance = await getTestInstance({ plugins: [admin(), organization(), productionTwoFactor(origin), applicationSchema, allauthControl()], emailAndPassword: { enabled: true, autoSignIn: false }, session: { cookieCache: { enabled: true } } }, { clientOptions: { plugins: [allauthControlClient()] } });
	const context = await instance.auth.$context;
	const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
	if (!user) throw new Error("The native test user was not created.");
	await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true, role: asAdmin ? "user, admin" : "user" } });
	const signedIn = await instance.signInWithTestUser();
	signedIn.headers.set("origin", origin);
	return { ...instance, context, user, headers: signedIn.headers };
}

describe("control event privacy and normalization", () => {
	it("drops request bodies, nested objects, secrets and unknown metadata keys", () => {
		const output = sanitizeControlMetadata({ path: "/sign-in/email", fields: ["name", "password", "privateMetadata", "email", "role"], password: "private-password", token: "private-token", body: { secret: "private-secret" }, policy: { clientSecret: "private-secret" }, email: "private@example.com", reason: "velocity", unknown: "private-extra" });
		expect(output).toEqual({ path: "/sign-in/email", fields: ["name", "role"], reason: "velocity" });
	});
	it("bounds approved strings and never projects added database credential fields", () => {
		const output = publicControlEvent({ id: "one", type: "auth.sign-in", outcome: "success", createdAt: new Date(), password: "private", token: "private-token", privateMetadata: { secret: "private" }, metadata: { token: "private", reason: "x".repeat(2000) }, userAgent: "a".repeat(2000) });
		expect(JSON.stringify(output)).not.toContain("private");
		expect(output.userAgent?.length).toBe(512); expect(String(output.metadata.reason).length).toBe(256);
	});
	it("recognizes native API errors and error redirects without exposing their messages", () => {
		expect(controlResponseFailure(new APIError("UNAUTHORIZED", { code: "INVALID_CREDENTIALS", message: "test@example.com: private" }))).toEqual({ failed: true, code: "INVALID_CREDENTIALS", pendingMFA: false });
		expect(controlResponseFailure({ url: "https://example.com/callback?error=invalid_grant&token=private" })).toEqual({ failed: true, code: "invalid_grant", pendingMFA: false });
		expect(controlResponseFailure({ url: "https://example.com?error=user%40example.com" }).code).toBe("AUTHENTICATION_FAILED");
	});
	it("treats MFA as pending and ordinary success redirects as successful", () => {
		expect(controlResponseFailure({ twoFactorRedirect: true }).pendingMFA).toBe(true);
		expect(controlResponseFailure(new APIError("FOUND"), new Headers({ location: "/two-factor?callbackUrl=%2Faccount" })).pendingMFA).toBe(true);
		expect(controlResponseFailure(new APIError("FOUND"), new Headers({ location: "/account" })).failed).toBe(false);
	});
	it("does not treat auth initiations or reads as completed sign-in/activity", () => {
		expect(isPrimaryAuthenticationPath("/sign-in/social")).toBe(false); expect(isPrimaryAuthenticationPath("/sign-in/magic-link")).toBe(false);
		expect(isPrimaryAuthenticationPath("/callback/google")).toBe(true); expect(isPrimaryAuthenticationPath("/two-factor/verify-totp")).toBe(true);
		expect(mutationEventType("/organization/list")).toBeUndefined(); expect(mutationEventType("/get-session")).toBeUndefined();
		expect(mutationEventType("/organization/update-member-role")).toBe("organization.member.role-updated");
	});
	it("rejects oversized/unbounded pagination and backwards dates", () => {
		expect(controlEventsQuery.safeParse({ limit: 101 }).success).toBe(false); expect(controlEventsQuery.safeParse({ offset: -1 }).success).toBe(false);
		expect(controlEventsQuery.safeParse({ q: "x".repeat(129) }).success).toBe(false);
		expect(controlEventsQuery.safeParse({ from: "2026-10-08T00:00:00Z", to: "2026-10-07T00:00:00Z" }).success).toBe(false);
		expect(controlEventsQuery.parse({})).toEqual({ scope: "user", limit: 25, offset: 0 });
	});
});

describe("native AllAuth control-plane authorization", () => {
	it.each([false, true])("audits native signed email-link verification and its optional session (autoSignIn=%s)", async (autoSignInAfterVerification) => {
		let verificationURL = "";
		const instance = await getTestInstance({ logger: { disabled: true }, plugins: [admin(), organization(), applicationSchema, allauthControl({ ipHeader: "x-real-ip" })], emailAndPassword: { enabled: true, autoSignIn: false }, emailVerification: { autoSignInAfterVerification, async sendVerificationEmail(data) { verificationURL = data.url; } } });
		const context = await instance.auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
		if (!user) throw new Error("The native email-link user was not created.");
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin", emailVerified: false } });
		await instance.auth.api.sendVerificationEmail({ body: { email: instance.testUser.email, callbackURL: `${origin}/account` } });
		const token = new URL(verificationURL).searchParams.get("token");
		if (!token) throw new Error("Native verification must mint a signed token.");
		const verified = await instance.auth.handler(new Request(verificationURL, { headers: { "x-real-ip": "192.0.2.7", "user-agent": "Native verification fixture" } }));
		expect(verified.status).toBe(302);
		const events = await context.adapter.findMany<{ type: string; outcome: string; userId?: string; ipAddress?: string; metadata: Record<string, unknown> }>({ model: "allauthEvent" });
		expect(events.some((event) => event.type === "user.email-verified" && event.userId === user.id && event.ipAddress === "192.0.2.7" && event.metadata.path === "/verify-email")).toBe(true);
		expect(events.some((event) => event.type === "auth.sign-in" && event.outcome === "success" && event.userId === user.id && event.metadata.path === "/verify-email")).toBe(autoSignInAfterVerification);
		expect(JSON.stringify(events)).not.toContain(token);
	});

	it.each([false, true])("audits native email verification and its optional auto-sign-in (autoSignIn=%s)", async (autoSignInAfterVerification) => {
		let otp = "";
		const instance = await getTestInstance({ logger: { disabled: true }, plugins: [admin(), organization(), emailOTP({ async sendVerificationOTP(data) { otp = data.otp; } }), applicationSchema, allauthControl()], emailAndPassword: { enabled: true, autoSignIn: false }, emailVerification: { autoSignInAfterVerification } });
		const context = await instance.auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
		if (!user) throw new Error("The native verification user was not created.");
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin", emailVerified: false } });
		await instance.auth.api.sendVerificationOTP({ body: { email: instance.testUser.email, type: "email-verification" } });
		expect(otp).toMatch(/^\d{6}$/);
		const verified = await instance.auth.api.verifyEmailOTP({ body: { email: instance.testUser.email, otp }, returnHeaders: true });
		expect(verified.response.user.emailVerified).toBe(true);
		const events = await context.adapter.findMany<{ type: string; outcome: string; userId?: string; metadata: Record<string, unknown> }>({ model: "allauthEvent" });
		expect(events.some((event) => event.type === "user.email-verified" && event.userId === user.id && event.metadata.path === "/email-otp/verify-email")).toBe(true);
		expect(events.some((event) => event.type === "auth.sign-in" && event.outcome === "success" && event.userId === user.id && event.metadata.path === "/email-otp/verify-email")).toBe(autoSignInAfterVerification);
		expect(JSON.stringify(events)).not.toContain(otp);
	});

	it("audits the native cryptographically verified passkey completion route", async () => {
		const instance = await getTestInstance({ plugins: [admin(), organization(), passkey({ rpID: "localhost", origin }), applicationSchema, allauthControl()], emailAndPassword: { enabled: true, autoSignIn: false } });
		const context = await instance.auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
		if (!user) throw new Error("The native passkey user was not created.");
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true, role: "admin" } });
		const credentialId = randomBytes(32).toString("base64url");
		const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
		const publicJwk = keyPair.publicKey.export({ format: "jwk" });
		if (!publicJwk.x || !publicJwk.y) throw new Error("The fixture public key is invalid.");
		const coseKey = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(publicJwk.x, "base64url"), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(publicJwk.y, "base64url")]);
		await context.adapter.create({ model: "passkey", data: { name: "Local assertion fixture", userId: user.id, credentialID: credentialId, publicKey: coseKey.toString("base64"), counter: 0, deviceType: "singleDevice", backedUp: false, transports: "internal", createdAt: new Date() } });
		const options = await instance.auth.api.generatePasskeyAuthenticationOptions({ returnHeaders: true });
		const headers = new Headers({ origin });
		headers.set("cookie", [...parseSetCookieHeader(options.headers.get("set-cookie") || "")].map(([name, value]) => `${name}=${value.value}`).join("; "));
		const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: options.response.challenge, origin, crossOrigin: false }));
		const authenticatorData = Buffer.concat([createHash("sha256").update("localhost").digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
		const signature = sign("sha256", Buffer.concat([authenticatorData, createHash("sha256").update(clientData).digest()]), keyPair.privateKey);
		const verified = await instance.auth.api.verifyPasskeyAuthentication({ headers, body: { response: { id: credentialId, rawId: credentialId, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: clientData.toString("base64url"), authenticatorData: authenticatorData.toString("base64url"), signature: signature.toString("base64url"), userHandle: Buffer.from(user.id).toString("base64url") } } }, returnHeaders: true });
		headers.set("cookie", [...parseSetCookieHeader(verified.headers.get("set-cookie") || "")].map(([name, value]) => `${name}=${value.value}`).join("; "));
		const events = await instance.auth.api.controlEvents({ headers, query: { scope: "admin", type: "auth.sign-in" } });
		expect(events.events.some((event) => event.outcome === "success" && event.userId === user.id && event.metadata.path === "/passkey/verify-authentication")).toBe(true);
		expect(JSON.stringify(events)).not.toContain(credentialId);
	});

	it("audits username authentication without persisting submitted identities or passwords", async () => {
		const instance = await getTestInstance({ plugins: [admin(), organization(), username(), applicationSchema, allauthControl()], emailAndPassword: { enabled: true, autoSignIn: false } });
		const context = await instance.auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: instance.testUser.email }] });
		if (!user) throw new Error("The native test user was not created.");
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true, username: "fixtureusername", role: "admin" } });
		await expect(instance.auth.api.signInUsername({ body: { username: "fixtureusername", password: "wrong-fixture-password" } })).rejects.toMatchObject({ statusCode: 401 });
		const signed = await instance.auth.api.signInUsername({ body: { username: "fixtureusername", password: instance.testUser.password }, returnHeaders: true });
		const headers = new Headers({ origin });
		headers.set("cookie", [...parseSetCookieHeader(signed.headers.get("set-cookie") || "")].map(([name, value]) => `${name}=${value.value}`).join("; "));
		const events = await instance.auth.api.controlEvents({ headers, query: { scope: "admin", type: "auth.sign-in" } });
		expect(events.events.some((event) => event.outcome === "success" && event.userId === user.id && event.metadata.path === "/sign-in/username")).toBe(true);
		expect(events.events.some((event) => event.outcome === "failure" && !event.userId && event.metadata.path === "/sign-in/username")).toBe(true);
		expect(JSON.stringify(events)).not.toMatch(/fixtureusername|wrong-fixture-password/);
	});
	it("permits a freshly authorized platform owner to administer an isolated project without a tenant user", async () => {
		const owner = await fixture();
		const project = await getTestInstance({ secret: "isolated-project-secret-that-differs-from-the-owner", plugins: [organization(), productionTwoFactor(origin), applicationSchema, allauthControl({ authorizeAdmin: async (headers) => {
			const current = await owner.auth.api.getSession({ headers, query: { disableCookieCache: true } });
			return current && isPlatformAdmin(current.user, current.session) ? current as ControlPrincipal : null;
		} })] }, { disableTestUser: true });
		const overview = await project.auth.api.controlOverview({ headers: owner.headers });
		expect(overview.totals.users).toBe(0); expect(overview.totals.activeSessions).toBe(0);
		expect(await project.auth.api.controlEvents({ headers: owner.headers, query: { scope: "admin" } })).toMatchObject({ events: [], total: 0 });
		await expect(project.auth.api.controlOverview({ headers: new Headers() })).rejects.toMatchObject({ statusCode: 403 });
		await expect(project.auth.api.controlEvents({ headers: owner.headers })).rejects.toMatchObject({ statusCode: 401 });
		await owner.context.adapter.update({ model: "user", where: [{ field: "id", value: owner.user.id }], update: { role: "user" } });
		await expect(project.auth.api.controlOverview({ headers: owner.headers })).rejects.toMatchObject({ statusCode: 403 });
	});
	it("rejects anonymous and ordinary users from platform overview/session APIs", async () => {
		const instance = await fixture(false);
		await expect(instance.auth.api.controlOverview({ headers: new Headers() })).rejects.toMatchObject({ statusCode: 401 });
		await expect(instance.auth.api.controlOverview({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
		await expect(instance.auth.api.controlSessions({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
		await expect(instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "admin" } })).rejects.toMatchObject({ statusCode: 403 });
	});
	it("re-reads revoked/demoted administrators even when cookie caching is enabled", async () => {
		const instance = await fixture();
		expect((await instance.auth.api.controlOverview({ headers: instance.headers })).totals.users).toBe(1);
		await instance.context.adapter.update({ model: "user", where: [{ field: "id", value: instance.user.id }], update: { role: "user" } });
		await expect(instance.auth.api.controlOverview({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
		await instance.context.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: instance.user.id }] });
		await expect(instance.auth.api.controlEvents({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 401 });
	});
	it("rejects unverified, banned and impersonated administrators", async () => {
		const instance = await fixture();
		await instance.context.adapter.update({ model: "user", where: [{ field: "id", value: instance.user.id }], update: { emailVerified: false } });
		await expect(instance.auth.api.controlOverview({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
		await instance.context.adapter.update({ model: "user", where: [{ field: "id", value: instance.user.id }], update: { emailVerified: true } });
		await instance.context.adapter.updateMany({ model: "session", where: [{ field: "userId", value: instance.user.id }], update: { impersonatedBy: "other-admin" } });
		await expect(instance.auth.api.controlOverview({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
		await instance.context.adapter.update({ model: "user", where: [{ field: "id", value: instance.user.id }], update: { banned: true } });
		await expect(instance.auth.api.controlOverview({ headers: instance.headers })).rejects.toMatchObject({ statusCode: 403 });
	});
	it("isolates personal and organization history from unrelated users/tenants", async () => {
		const instance = await fixture(false);
		await writeControlEvent(instance.context.adapter, { type: "fixture.personal", outcome: "success", userId: instance.user.id });
		await writeControlEvent(instance.context.adapter, { type: "fixture.other", outcome: "success", userId: "another-user", organizationId: "another-organization" });
		const own = await instance.auth.api.controlEvents({ headers: instance.headers });
		expect(own.events.some((event) => event.type === "fixture.personal")).toBe(true); expect(own.events.some((event) => event.type === "fixture.other")).toBe(false);
		await expect(instance.auth.api.controlEvents({ headers: instance.headers, query: { userId: "another-user" } })).rejects.toMatchObject({ statusCode: 403 });
		await expect(instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "organization", organizationId: "another-organization" } })).rejects.toMatchObject({ statusCode: 403 });
		await expect(instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "organization" } })).rejects.toMatchObject({ statusCode: 400 });
	});
	it("permits only organization owners/admins to read their own tenant history", async () => {
		const instance = await fixture(false);
		const organization = await instance.auth.api.createOrganization({ headers: instance.headers, body: { name: "First", slug: "first" } });
		if (!organization) throw new Error("Native organization creation failed.");
		await writeControlEvent(instance.context.adapter, { type: "fixture.tenant", outcome: "success", organizationId: organization.id, userId: "another-member" });
		const result = await instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "organization", organizationId: organization.id } });
		expect(result.events.some((event) => event.type === "fixture.tenant")).toBe(true);
		expect(result.events.every((event) => event.organizationId === organization.id)).toBe(true);
		await instance.context.adapter.updateMany({ model: "member", where: [{ field: "organizationId", value: organization.id }], update: { role: "member" } });
		await expect(instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "organization", organizationId: organization.id } })).rejects.toMatchObject({ statusCode: 403 });
	});
	it("projects safe active session fields and blocks cross-origin revocation", async () => {
		const instance = await fixture();
		const result = await instance.auth.api.controlSessions({ headers: instance.headers });
		expect(result.total).toBe(1); expect(result.sessions[0]).toMatchObject({ userId: instance.user.id, email: instance.testUser.email });
		expect(JSON.stringify(result)).not.toMatch(/token|privateMetadata|password/);
		const crossOrigin = new Headers(instance.headers); crossOrigin.set("origin", "https://attacker.example");
		await expect(instance.auth.api.controlRevokeSession({ headers: crossOrigin, body: { id: result.sessions[0].id } })).rejects.toMatchObject({ statusCode: 403 });
		expect(await instance.context.adapter.count({ model: "session" })).toBe(1);
		await instance.auth.api.controlRevokeSession({ headers: instance.headers, body: { id: result.sessions[0].id } });
		expect(await instance.context.adapter.count({ model: "session" })).toBe(0);
		const event = await instance.context.adapter.findOne<{ actorId: string; userId: string }>({ model: "allauthEvent", where: [{ field: "type", value: "session.revoked" }] });
		expect(event).toMatchObject({ actorId: instance.user.id, userId: instance.user.id });
	});
	it("returns non-cacheable audit data with bounded pages and excludes expired retention", async () => {
		const instance = await fixture();
		for (let index = 0; index < 4; index++) await writeControlEvent(instance.context.adapter, { type: "fixture.page", outcome: "success", userId: instance.user.id, createdAt: new Date(Date.now() - index * 1000) });
		await writeControlEvent(instance.context.adapter, { type: "fixture.page", outcome: "success", userId: instance.user.id, createdAt: new Date(Date.now() - 91 * 86400_000) });
		const result = await instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "admin", type: "fixture.page", limit: 2, offset: 1 } });
		expect(result).toMatchObject({ total: 4, limit: 2, offset: 1, retentionDays: 90 }); expect(result.events).toHaveLength(2);
		const response = await instance.auth.api.controlEvents({ headers: instance.headers, asResponse: true }); expect(response.headers.get("cache-control")).toBe("no-store");
		expect(await pruneControlEvents(instance.context.adapter, 90, 1)).toBe(1);
		expect(await pruneControlEvents(instance.context.adapter, 90, 1)).toBe(0);
	});
});

describe("authentication audit lifecycle", () => {
	it("records successful/failed native authentication while protecting submitted identities/secrets", async () => {
		const instance = await fixture();
		await instance.client.signIn.email({ email: "does-not-exist@example.com", password: "private-password" });
		const events = await instance.auth.api.controlEvents({ headers: instance.headers, query: { scope: "admin", type: "auth.sign-in" } });
		expect(events.events.some((event) => event.outcome === "success" && event.userId === instance.user.id)).toBe(true);
		const failure = events.events.find((event) => event.outcome === "failure"); expect(failure).toBeDefined(); expect(failure?.userId).toBeUndefined();
		expect(JSON.stringify(events)).not.toMatch(/does-not-exist|private-password|test123456|token/);
		const overview = await instance.auth.api.controlOverview({ headers: instance.headers }); expect(overview.series).toHaveLength(7); expect(overview.today.signIns).toBe(1); expect(overview.today.failedSignIns).toBe(1); expect(overview.today.signUps).toBe(1);
	});
	it("does not create audit activity for ordinary session/audit reads", async () => {
		const instance = await fixture();
		const before = await instance.context.adapter.count({ model: "allauthEvent" });
		await instance.auth.api.getSession({ headers: instance.headers }); await instance.auth.api.controlEvents({ headers: instance.headers }); await instance.auth.api.controlOverview({ headers: instance.headers });
		expect(await instance.context.adapter.count({ model: "allauthEvent" })).toBe(before);
	});
	it("does not count an MFA provisional session as completed authentication", async () => {
		const instance = await fixture();
		const factor = await instance.auth.api.enableTwoFactor({ headers: instance.headers, body: { password: instance.testUser.password }, asResponse: true });
		const cookies = parseSetCookieHeader(factor.headers.get("set-cookie") || "");
		const sessionCookie = cookies.get("better-auth.session_token")?.value;
		if (sessionCookie) instance.headers.set("cookie", `better-auth.session_token=${sessionCookie}`);
		const row = await instance.context.adapter.findOne<{ secret: string }>({ model: "twoFactor", where: [{ field: "userId", value: instance.user.id }] });
		if (!row) throw new Error("Native enrollment omitted its factor.");
		const secret = await symmetricDecrypt({ key: instance.context.secretConfig, data: row.secret });
		const otp = await instance.auth.api.generateTOTP({ body: { secret } });
		await instance.auth.api.verifyTOTP({ headers: instance.headers, body: { code: otp.code } });
		const before = await instance.context.adapter.count({ model: "allauthEvent", where: [{ field: "type", value: "auth.sign-in" }, { field: "outcome", value: "success" }] });
		expect(before).toBe(1);
		const challenged = await instance.client.signIn.email({ email: instance.testUser.email, password: instance.testUser.password });
		expect(challenged.data).toMatchObject({ twoFactorRedirect: true });
		expect(await instance.context.adapter.count({ model: "allauthEvent", where: [{ field: "type", value: "auth.sign-in" }, { field: "outcome", value: "success" }] })).toBe(before);
		expect(await instance.context.adapter.count({ model: "allauthEvent", where: [{ field: "type", value: "auth.mfa-required" }] })).toBe(1);
	});
});
