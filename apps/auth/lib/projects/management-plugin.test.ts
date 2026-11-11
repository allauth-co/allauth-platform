import type { GenericEndpointContext } from "@better-auth/core";
import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { productionTwoFactor } from "../mfa";
import { isPlatformAdmin } from "../configuration";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { defaultPasswordPolicy } from "../auth-policy/password";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { projectManagement, publicProjectUser } from "./management-plugin";
import { hash as bcryptHash } from "bcryptjs";
import { clerkCompatiblePasswords } from "../clerk-password";

const origin = "http://localhost:3000";
const password = "fixture-project-password";
const fixtureHeaders = (cookie?: string) => new Headers({ origin, ...(cookie ? { cookie } : {}) });
const cookieHeader = (response: Response) => response.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; ");

async function setup() {
	const root = await getTestInstance({ secret: "platform-fixture-secret-longer-than-thirty-two-characters", advanced: { cookiePrefix: "platform" }, plugins: [admin()] }, { disableTestUser: true });
	const platform = await root.auth.api.signUpEmail({ body: { email: "owner@example.com", password, name: "Owner" }, headers: fixtureHeaders() });
	const rootAdapter = (await root.auth.$context).adapter;
	await rootAdapter.update({ model: "user", where: [{ field: "id", value: platform.user.id }], update: { role: "user,admin", emailVerified: true } });
	const authenticateRoot = async (ctx: GenericEndpointContext): Promise<ControlPrincipal> => {
		const current = await runWithAdapter((await root.auth.$context).adapter, () => root.auth.api.getSession({ headers: ctx.headers || ctx.request?.headers || new Headers(), query: { disableCookieCache: true } }));
		if (!current) throw new APIError("UNAUTHORIZED");
		if (!isPlatformAdmin(current.user, current.session)) throw new APIError("FORBIDDEN");
		return current as ControlPrincipal;
	};
	const revokeA = vi.fn(async () => {});
	const a = await getTestInstance({ emailAndPassword: { enabled: true, password: clerkCompatiblePasswords }, secret: "project-a-fixture-secret-longer-than-thirty-two-characters", advanced: { cookiePrefix: "project-a" }, trustedOrigins: [origin, "https://app.example"], user: { additionalFields: { privateMetadata: { type: "json", required: false, returned: false, input: false }, publicMetadata: { type: "json", required: false, input: false } } }, plugins: [admin(), productionTwoFactor(origin), allauthControl(), projectManagement({ projectId: "project-a", projectSlug: "project-a-development", baseURL: origin, requirePlatformAdmin: authenticateRoot, onRevokeUser: revokeA })] }, { disableTestUser: true });
	const b = await getTestInstance({ secret: "project-b-fixture-secret-longer-than-thirty-two-characters", advanced: { cookiePrefix: "project-b" }, plugins: [admin(), productionTwoFactor(origin), allauthControl(), projectManagement({ projectId: "project-b", projectSlug: "project-b-development", baseURL: origin, requirePlatformAdmin: authenticateRoot })] }, { disableTestUser: true });
	const createTarget = async (realm: typeof a, email = "shared@example.com") => {
		const result = await realm.auth.api.signUpEmail({ body: { email, password, name: "Project User" }, headers: fixtureHeaders() });
		await (await realm.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: result.user.id }], update: { emailVerified: true } });
		return result.user.id;
	};
	const userA = await createTarget(a);
	const userB = await createTarget(b as unknown as typeof a);
	const rootLogin = await root.auth.api.signInEmail({ body: { email: "owner@example.com", password }, headers: fixtureHeaders(), asResponse: true });
	const rootCookie = cookieHeader(rootLogin);
	if (!(await root.auth.api.getSession({ headers: fixtureHeaders(rootCookie) }))) throw new Error("The fixture root sign-in cookie did not produce a real root session.");
	const native = async (realm: { auth: { handler: (request: Request) => Promise<Response> } }, path: string, body?: unknown, cookie = rootCookie, requestOrigin = origin) => {
		const headers = fixtureHeaders(cookie); headers.set("origin", requestOrigin);
		if (body !== undefined) headers.set("content-type", "application/json");
		return realm.auth.handler(new Request(`${origin}/api/auth${path}`, { method: body === undefined ? "GET" : "POST", headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
	};
	const signInA = (email = "shared@example.com", cookie = "") => native(a, "/sign-in/email", { email, password }, cookie);
	return { root, a, b, platform, rootAdapter, userA, userB, rootCookie, native, signInA, revokeA, authenticateRoot };
}

describe("project management isolation", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => { state = await setup(); });
	it("lists only the selected project's independently stored users", async () => {
		expect(state.userA).not.toBe(state.userB);
		const response = await state.native(state.a, "/project-admin/list-users"); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
		const data = await response.json() as { users: { id: string; email: string }[]; total: number };
		expect(data.total).toBe(1); expect(data.users[0]).toMatchObject({ id: state.userA, email: "shared@example.com" }); expect(JSON.stringify(data)).not.toContain(state.platform.user.id);
		const foreign = await state.native(state.b, "/project-admin/ban-user", { userId: state.userA, banReason: "Foreign identity" }); expect(foreign.status).toBe(404);
		expect((await state.native(state.a, "/project-admin/list-users")).status).toBe(200);
	});
	it("never treats a tenant administrator or a same-email identity as platform authority", async () => {
		await (await state.a.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: state.userA }], update: { role: "admin", email: "owner@example.com" } });
		const tenantLogin = await state.signInA("owner@example.com"); expect(tenantLogin.status).toBe(200);
		expect((await state.native(state.a, "/project-admin/list-users", undefined, cookieHeader(tenantLogin))).status).toBe(401);
		expect((await state.native(state.a, "/project-admin/list-users", undefined, "")).status).toBe(401);
	});
	it("rechecks the platform user's current role and verification instead of trusting an old cookie", async () => {
		await state.rootAdapter.update({ model: "user", where: [{ field: "id", value: state.platform.user.id }], update: { role: "user" } });
		expect((await state.native(state.a, "/project-admin/list-users")).status).toBe(403);
		await state.rootAdapter.update({ model: "user", where: [{ field: "id", value: state.platform.user.id }], update: { role: "admin", emailVerified: false } });
		expect((await state.native(state.a, "/project-admin/list-users")).status).toBe(403);
	});
	it("rejects cross-origin changes and caller-selected project/role escalation fields", async () => {
		expect((await state.native(state.a, "/project-admin/ban-user", { userId: state.userA }, state.rootCookie, "https://evil.example")).status).toBe(403);
		expect((await state.native(state.a, "/project-admin/set-role", { userId: state.userA, role: "superadmin" })).status).toBe(400);
		expect((await state.native(state.a, "/project-admin/remove-user", { userId: state.userA, projectId: "project-b" })).status).toBe(400);
	});
	it("creates an unverified project identity and returns no password/account/private fields", async () => {
		const response = await state.native(state.a, "/project-admin/create-user", { email: "NEW@example.com", name: "New User", password }); expect(response.status).toBe(200);
		const data = await response.json() as { user: { id: string; email: string; emailVerified: boolean; role: string } };
		expect(data.user).toMatchObject({ email: "new@example.com", emailVerified: false, role: "user" }); expect(JSON.stringify(data)).not.toContain(password);
		const account = await (await state.a.auth.$context).adapter.findOne<{ password: string }>({ model: "account", where: [{ field: "userId", value: data.user.id }] }); expect(account?.password).toBeTruthy(); expect(account?.password).not.toBe(password);
		expect((await state.native(state.b, "/project-admin/list-users")).status).toBe(200);
		const output = publicProjectUser({ id: "fixture", password, privateMetadata: { private: true }, publicMetadata: { plan: "starter" }, credential: "sensitive" }); expect(output).toEqual({ id: "fixture", publicMetadata: { plan: "starter" } });
	});
	it("bans/revokes only the selected user's sessions and leaves the other project valid", async () => {
		const loginA = await state.signInA(); const loginB = await state.native(state.b, "/sign-in/email", { email: "shared@example.com", password }, "");
		const banned = await state.native(state.a, "/project-admin/ban-user", { userId: state.userA, banReason: "Fixture restriction" }); expect(banned.status).toBe(200); expect(state.revokeA).toHaveBeenCalledTimes(1);
		expect(await (await state.native(state.a, "/get-session", undefined, cookieHeader(loginA))).json()).toBeNull();
		expect(await (await state.native(state.b, "/get-session", undefined, cookieHeader(loginB))).json()).toMatchObject({ user: { id: state.userB } });
		expect((await state.signInA()).status).toBe(403);
		expect((await state.native(state.a, "/project-admin/unban-user", { userId: state.userA })).status).toBe(200); expect((await state.signInA()).status).toBe(200);
	});
	it("role updates revoke old sessions and keep tenant role grants out of the root platform", async () => {
		const login = await state.signInA();
		expect((await state.native(state.a, "/project-admin/set-role", { userId: state.userA, role: "admin" })).status).toBe(200);
		expect(await (await state.native(state.a, "/get-session", undefined, cookieHeader(login))).json()).toBeNull();
		const rootUser = await state.rootAdapter.findOne<{ role: string }>({ model: "user", where: [{ field: "id", value: state.platform.user.id }] }); expect(rootUser?.role).toBe("user,admin");
	});
	it("issues a real bounded tenant impersonation session while preserving the real root account", async () => {
		await (await state.a.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: state.userA }], update: { twoFactorEnabled: true } });
		const response = await state.native(state.a, "/project-admin/impersonate-user", { userId: state.userA }); expect(response.status).toBe(200);
		const data = await response.json() as { session: { id: string; userId: string; expiresAt: string; impersonatedBy: string }; user: { id: string } };
		expect(data).toMatchObject({ session: { userId: state.userA, impersonatedBy: state.platform.user.id }, user: { id: state.userA } }); expect(JSON.stringify(data)).not.toContain('"token"');
		expect(new Date(data.session.expiresAt).getTime() - Date.now()).toBeLessThanOrEqual(15 * 60_000);
		const stored = await (await state.a.auth.$context).adapter.findOne<{ impersonatedBy: string }>({ model: "session", where: [{ field: "id", value: data.session.id }] }); expect(stored?.impersonatedBy).toBe(state.platform.user.id);
		expect(await (await state.a.auth.$context).adapter.findOne({ model: "user", where: [{ field: "id", value: state.platform.user.id }] })).toBeNull();
		expect(response.headers.getSetCookie().every((entry) => entry.startsWith("project-a."))).toBe(true);
		const rootSession = await state.root.auth.api.getSession({ headers: fixtureHeaders(state.rootCookie) }); expect(rootSession?.user.id).toBe(state.platform.user.id);
		const impersonatedCookie = cookieHeader(response);
		expect(await (await state.native(state.b, "/get-session", undefined, impersonatedCookie)).json()).toBeNull();
		expect((await state.native(state.a, "/project-admin/list-users", undefined, impersonatedCookie)).status).toBe(401);
	});
	it("refuses administrator or banned targets even when the root platform is authorized", async () => {
		await (await state.a.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: state.userA }], update: { role: "user,admin" } });
		expect((await state.native(state.a, "/project-admin/impersonate-user", { userId: state.userA })).status).toBe(403);
		await (await state.a.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: state.userA }], update: { role: "user", banned: true } });
		expect((await state.native(state.a, "/project-admin/impersonate-user", { userId: state.userA })).status).toBe(403);
	});
	it("stops only the current real tenant impersonation and expires only its realm cookies", async () => {
		const response = await state.native(state.a, "/project-admin/impersonate-user", { userId: state.userA }); expect(response.status).toBe(200);
		const impersonation = await response.json() as { session: { id: string } };
		const stop = await state.native(state.a, "/project-admin/stop-impersonating", {}, cookieHeader(response)); expect(stop.status).toBe(200); expect(await stop.json()).toEqual({ success: true });
		expect(stop.headers.getSetCookie().every((entry) => entry.startsWith("project-a."))).toBe(true);
		expect(await (await state.a.auth.$context).adapter.findOne({ model: "session", where: [{ field: "id", value: impersonation.session.id }] })).toBeNull();
		expect((await state.root.auth.api.getSession({ headers: fixtureHeaders(state.rootCookie) }))?.user.id).toBe(state.platform.user.id);
	});
	it("does not turn an ordinary tenant logout or a forged cookie into privileged impersonation recovery", async () => {
		const login = await state.signInA(); expect((await state.native(state.a, "/project-admin/stop-impersonating", {}, cookieHeader(login))).status).toBe(400);
		const switchedPrefix = cookieHeader(login).replaceAll("project-a.", "project-b."); expect(await (await state.native(state.b, "/get-session", undefined, switchedPrefix)).json()).toBeNull();
		expect((await state.native(state.b, "/project-admin/stop-impersonating", {}, switchedPrefix)).status).toBe(401);
	});
	/** @see apps/auth/INTEGRATION.md#identity-organizations-and-impersonation */
	it("expires support access without ending the console login or permitting a cross-origin stop", async () => {
		const started = await state.native(state.a, "/project-admin/impersonate-user", { userId: state.userA });
		expect(started.status).toBe(200);
		const session = await started.json() as { session: { id: string } };
		const cookie = cookieHeader(started);
		expect((await state.native(state.a, "/project-admin/stop-impersonating", {}, cookie, "https://evil.example")).status).toBe(403);
		await (await state.a.auth.$context).adapter.update({ model: "session", where: [{ field: "id", value: session.session.id }], update: { expiresAt: new Date(Date.now() - 1_000) } });
		const expired = await state.native(state.a, "/get-session?disableCookieCache=true&disableRefresh=true", undefined, cookie);
		expect(await expired.json()).toBeNull();
		expect((await state.native(state.a, "/project-admin/stop-impersonating", {}, cookie)).status).toBe(401);
		expect((await state.root.auth.api.getSession({ headers: fixtureHeaders(state.rootCookie) }))?.user.id).toBe(state.platform.user.id);
	});
	it("deletes only an exact selected-project identity and all its credential/session rows", async () => {
		await state.signInA(); expect((await state.native(state.a, "/project-admin/remove-user", { userId: state.userA })).status).toBe(200);
		const adapter = (await state.a.auth.$context).adapter;
		expect(await adapter.findOne({ model: "user", where: [{ field: "id", value: state.userA }] })).toBeNull(); expect(await adapter.count({ model: "account", where: [{ field: "userId", value: state.userA }] })).toBe(0); expect(await adapter.count({ model: "session", where: [{ field: "userId", value: state.userA }] })).toBe(0);
		expect(await (await state.b.auth.$context).adapter.findOne({ model: "user", where: [{ field: "id", value: state.userB }] })).toBeTruthy();
	});
	it("returns only a verified tenant's own safe sessions without raw tokens", async () => {
		expect((await state.native(state.a, "/sdk/sessions", undefined, "")).status).toBe(401);
		expect((await state.native(state.a, "/sdk/sessions")).status).toBe(401);
		const login = await state.signInA(); const cookie = cookieHeader(login);
		const response = await state.native(state.a, "/sdk/sessions", undefined, cookie); expect(response.status).toBe(200);
		const data = await response.json() as { sessions: { id: string }[]; currentSessionId: string }; expect(data.sessions.some((session) => session.id === data.currentSessionId)).toBe(true);
		expect(JSON.stringify(data)).not.toContain('"token"'); expect(JSON.stringify(data)).not.toContain("privateMetadata"); expect(JSON.stringify(data)).not.toContain("password");
		await (await state.a.auth.$context).adapter.update({ model: "user", where: [{ field: "id", value: state.userA }], update: { emailVerified: false } });
		expect((await state.native(state.a, "/sdk/sessions", undefined, cookie)).status).toBe(403);
	});
	it("revokes only the exact caller-owned session from a configured app origin and expires its cookie", async () => {
		const login = await state.signInA(); const cookie = cookieHeader(login);
		const sessions = await (await state.native(state.a, "/sdk/sessions", undefined, cookie)).json() as { currentSessionId: string };
		const foreignLogin = await state.native(state.b, "/sign-in/email", { email: "shared@example.com", password }, "");
		const foreign = await (await state.b.auth.$context).adapter.findOne<{ id: string }>({ model: "session", where: [{ field: "userId", value: state.userB }] });
		expect((await state.native(state.a, "/sdk/sessions/revoke", { id: foreign!.id }, cookie, "https://app.example")).status).toBe(404);
		const other = await state.a.auth.api.signUpEmail({ headers: fixtureHeaders(), body: { email: "other-user@example.com", name: "Other User", password } });
		const otherSession = await (await state.a.auth.$context).adapter.findOne<{ id: string }>({ model: "session", where: [{ field: "userId", value: other.user.id }] });
		expect((await state.native(state.a, "/sdk/sessions/revoke", { id: otherSession!.id }, cookie, "https://app.example")).status).toBe(404);
		expect((await state.native(state.a, "/sdk/sessions/revoke", { id: sessions.currentSessionId }, cookie, "https://evil.example")).status).toBe(403);
		const revoked = await state.native(state.a, "/sdk/sessions/revoke", { id: sessions.currentSessionId }, cookie, "https://app.example"); expect(revoked.status).toBe(200); expect(await revoked.json()).toEqual({ success: true });
		expect(revoked.headers.getSetCookie().every((entry) => entry.startsWith("project-a."))).toBe(true);
		expect(await (await state.native(state.a, "/get-session", undefined, cookie)).json()).toBeNull(); expect(await (await state.native(state.b, "/get-session", undefined, cookieHeader(foreignLogin))).json()).toMatchObject({ user: { id: state.userB } });
	});
	it("reports actual public SDK capabilities without exposing realm credentials", async () => {
		const response = await state.native(state.a, "/sdk/config", undefined, ""); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
		const config = await response.json(); expect(config).toEqual({ nativePasskeys: { enabled: false, ios: false, android: false }, emailPassword: true, signUpEnabled: true, emailVerificationRequired: false, passwordPolicy: defaultPasswordPolicy, google: true, googleProvider: "google", apple: false, appleProvider: null, microsoft: false, microsoftProvider: null, organizations: false, twoFactor: true, profileImageUpload: false, profileImageOwnershipAndDeletion: false }); expect(JSON.stringify(config)).not.toContain("secret");
	});
	/** @see ../../AUTHENTICATION_POLICY.md */
	it("exposes the selected environment signup and verification policy to the SDK", async () => {
		const restricted = await getTestInstance({ emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true }, plugins: [projectManagement({ projectId: "restricted", baseURL: origin, requirePlatformAdmin: state.authenticateRoot })] }, { disableTestUser: true });
		const response = await state.native(restricted, "/sdk/config", undefined, "");
		expect(await response.json()).toMatchObject({ emailPassword: true, signUpEnabled: false, emailVerificationRequired: true });
	});
	/** @see ../../AUTHENTICATION_POLICY.md#password-rules */
	it("advertises and enforces managed creation rules only in the selected environment", async () => {
		const passwordPolicy = { ...defaultPasswordPolicy, minLength: 6, maxLength: 16, requireSymbol: true };
		const restricted = await getTestInstance({ plugins: [authPolicyPlugin({ ...defaultAuthPolicy, passwordPolicy }), admin(), allauthControl(), projectManagement({ projectId: "password-rules", baseURL: origin, requirePlatformAdmin: state.authenticateRoot })] }, { disableTestUser: true });
		expect(await (await state.native(restricted, "/sdk/config", undefined, "")).json()).toMatchObject({ passwordPolicy });
		const request = (email: string, password: string) => state.native(restricted, "/project-admin/create-user", { email, name: "Managed", password });
		expect((await request("short@example.com", "Ab1!")).status).toBe(400);
		expect((await request("symbol@example.com", "Abc123")).status).toBe(400);
		expect((await request("long@example.com", "A".repeat(16) + "!")).status).toBe(400);
		expect(await (await restricted.auth.$context).adapter.count({ model: "user" })).toBe(0);
		expect((await request("allowed@example.com", "Abc12!")).status).toBe(200);
		expect(await (await state.native(state.b, "/sdk/config", undefined, "")).json()).toMatchObject({ passwordPolicy: defaultPasswordPolicy });
		expect((await state.native(state.b, "/project-admin/create-user", { email: "default@example.com", name: "Default", password: "abcdefgh" })).status).toBe(200);
	});
	it("rolls back identity and credential creation when the transactional audit write fails", async () => {
		const broken = await getTestInstance({ plugins: [admin(), allauthControl(), projectManagement({ projectId: "broken-fixture", baseURL: origin, requirePlatformAdmin: state.authenticateRoot, recordEvent: async () => { throw new Error("Fixture audit failure"); } })] }, { disableTestUser: true });
		const response = await state.native(broken, "/project-admin/create-user", { email: "rollback@example.com", name: "Rollback", password }); expect(response.status).toBe(500);
		const adapter = (await broken.auth.$context).adapter; expect(await adapter.count({ model: "user" })).toBe(0); expect(await adapter.count({ model: "account" })).toBe(0);
	});
	it("dry-runs Clerk imports without writes, accounts, emails or audit events", async () => {
		const adapter = (await state.a.auth.$context).adapter;
		const before = await adapter.count({ model: "allauthEvent" });
		const response = await state.native(state.a, "/project-admin/import-clerk-users", { sourceInstance: "ins_fixture", users: [{ sourceUserId: "user_clerk1", email: "imported@example.com", emailVerified: true, name: "Imported" }] });
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ project: "project-a-development", projectId: "project-a", sourceInstance: "ins_fixture", dryRun: true, created: 0, existing: 0, conflicts: 0, users: [{ sourceUserId: "user_clerk1", sourceUpdatedAt: null, status: "would_create" }] });
		expect(await adapter.count({ model: "user" })).toBe(1);
		expect(await adapter.count({ model: "allauthEvent" })).toBe(before);
	});
	it("imports verified Clerk bcrypt and social subjects once without resetting later passwords", async () => {
		const passwordHash = await bcryptHash(password, 4);
		const imported = { sourceUserId: "user_clerk2", email: "imported@example.com", emailVerified: true, name: "Imported", image: "https://images.example.com/profile.png", passwordHash, passwordHasher: "bcrypt", createdAt: "2025-01-02T03:04:05.000Z", updatedAt: "2025-01-03T03:04:05.000Z", socialAccounts: [{ provider: "google", subject: "google-stable-sub" }], privateMetadata: { legacyPlan: "member" } };
		const body = { sourceInstance: "ins_fixture", dryRun: false, users: [imported] };
		const response = await state.native(state.a, "/project-admin/import-clerk-users", body);
		expect(response.status).toBe(200);
		const result = await response.json() as { created: number; users: { userId: string; sourceUpdatedAt: string }[] };
		expect(result.created).toBe(1);
		expect(result.users[0]!.sourceUpdatedAt).toBe(imported.updatedAt);
		expect(JSON.stringify(result)).not.toMatch(/imported@example|passwordHash|legacyPlan|google-stable-sub/);
		const id = result.users[0]!.userId;
		const adapter = (await state.a.auth.$context).adapter;
		expect(await adapter.findOne({ model: "user", where: [{ field: "id", value: id }] })).toMatchObject({ emailVerified: true, image: imported.image, createdAt: new Date(imported.createdAt), privateMetadata: { legacyPlan: "member" } });
		expect(await adapter.findMany({ model: "allauthEvent", where: [{ field: "userId", value: id }] })).toMatchObject([{ type: "admin.clerk-import" }]);
		expect(await adapter.findOne({ model: "account", where: [{ field: "userId", value: id }, { field: "providerId", value: "google" }] })).toMatchObject({ accountId: "google-stable-sub" });
		expect((await state.native(state.a, "/sign-in/email", { email: imported.email, password }, "")).status).toBe(200);
		const replacement = await clerkCompatiblePasswords.hash("replacement-native-password");
		await adapter.update({ model: "account", where: [{ field: "userId", value: id }, { field: "providerId", value: "credential" }], update: { password: replacement } });
		expect(await (await state.native(state.a, "/project-admin/import-clerk-users", body)).json()).toMatchObject({ created: 0, existing: 1, conflicts: 0, users: [{ userId: id, sourceUpdatedAt: imported.updatedAt, status: "existing" }] });
		expect(await adapter.findOne({ model: "account", where: [{ field: "userId", value: id }, { field: "providerId", value: "credential" }] })).toMatchObject({ password: replacement });
		expect(await (await state.native(state.a, "/project-admin/import-clerk-users", { ...body, users: [{ ...imported, updatedAt: "2025-01-04T03:04:05.000Z" }] })).json()).toMatchObject({ conflicts: 1, users: [{ reason: "source_changed" }] });
	});
	it("blocks email ownership conflicts and MFA users without merging accounts", async () => {
		const response = await state.native(state.a, "/project-admin/import-clerk-users", { sourceInstance: "ins_fixture", dryRun: false, users: [{ sourceUserId: "user_email_conflict", email: "shared@example.com", emailVerified: true, name: "Conflict" }, { sourceUserId: "user_mfa", email: "mfa@example.com", emailVerified: true, name: "MFA", twoFactorEnabled: true }] });
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ created: 0, conflicts: 2, users: [{ reason: "email_conflict" }, { reason: "mfa_unsupported" }] });
		expect(await (await state.a.auth.$context).adapter.count({ model: "user" })).toBe(1);
	});
	it("preserves source restrictions and refuses social subjects already owned in the realm", async () => {
		const adapter = (await state.a.auth.$context).adapter;
		await adapter.create({ model: "account", data: { providerId: "apple", accountId: "existing-apple-sub", userId: state.userA, createdAt: new Date(), updatedAt: new Date() } });
		const body = { sourceInstance: "ins_fixture", dryRun: false, users: [{ sourceUserId: "user_locked", email: "locked@example.com", emailVerified: true, name: "Locked", locked: true, passwordHash: await bcryptHash(password, 4), passwordHasher: "bcrypt" }, { sourceUserId: "user_social_conflict", email: "apple@example.com", emailVerified: true, name: "Apple", socialAccounts: [{ provider: "apple", subject: "existing-apple-sub" }] }] };
		const response = await state.native(state.a, "/project-admin/import-clerk-users", body);
		expect(await response.json()).toMatchObject({ created: 1, conflicts: 1, users: [{ status: "created" }, { status: "conflict", reason: "provider_conflict" }] });
		expect((await state.native(state.a, "/sign-in/email", { email: "locked@example.com", password }, "")).status).toBe(403);
		expect(await adapter.findOne({ model: "user", where: [{ field: "email", value: "apple@example.com" }] })).toBeNull();
	});
	it("isolates imports by project and rolls back user, account and audit together on failure", async () => {
		const body = { sourceInstance: "ins_fixture", dryRun: false, users: [{ sourceUserId: "user_fixture", email: "imported@example.com", emailVerified: true, name: "Imported", passwordHash: await bcryptHash(password, 4), passwordHasher: "bcrypt" }] };
		const resultA = await (await state.native(state.a, "/project-admin/import-clerk-users", body)).json() as { users: { userId: string }[] };
		const resultB = await (await state.native(state.b, "/project-admin/import-clerk-users", { ...body, dryRun: true })).json() as { users: { userId: string }[] };
		expect(resultA.users[0]!.userId).not.toBe(resultB.users[0]!.userId);
		expect(await (await state.b.auth.$context).adapter.count({ model: "user" })).toBe(1);
		const broken = await getTestInstance({ user: { additionalFields: { privateMetadata: { type: "json", required: false, returned: false, input: false } } }, plugins: [admin(), allauthControl(), projectManagement({ projectId: "broken-import", baseURL: origin, requirePlatformAdmin: state.authenticateRoot, recordEvent: async () => { throw new Error("Private fixture audit failure"); } })] }, { disableTestUser: true });
		const response = await state.native(broken, "/project-admin/import-clerk-users", body);
		expect(await response.json()).toMatchObject({ created: 0, conflicts: 1, users: [{ reason: "write_conflict" }] });
		const adapter = (await broken.auth.$context).adapter;
		expect(await adapter.count({ model: "user" })).toBe(0);
		expect(await adapter.count({ model: "account" })).toBe(0);
	});
	it("requires fresh platform authority, same-origin requests and a bounded strict import schema", async () => {
		const body = { sourceInstance: "ins_fixture", users: [{ sourceUserId: "user_fixture", email: "imported@example.com", emailVerified: true, name: "Imported" }] };
		expect((await state.native(state.a, "/project-admin/import-clerk-users", body, "")).status).toBe(401);
		expect((await state.native(state.a, "/project-admin/import-clerk-users", body, state.rootCookie, "https://evil.example")).status).toBe(403);
		expect((await state.native(state.a, "/project-admin/import-clerk-users", { ...body, users: Array(101).fill(body.users[0]) })).status).toBe(400);
		expect((await state.native(state.a, "/project-admin/import-clerk-users", { ...body, users: [{ ...body.users[0], passwordHash: "plaintext", passwordHasher: "bcrypt" }] })).status).toBe(400);
		expect((await state.native(state.a, "/project-admin/import-clerk-users", { ...body, projectId: "project-b" })).status).toBe(400);
		await state.rootAdapter.update({ model: "user", where: [{ field: "id", value: state.platform.user.id }], update: { role: "user" } });
		expect((await state.native(state.a, "/project-admin/import-clerk-users", body)).status).toBe(403);
	});
});
