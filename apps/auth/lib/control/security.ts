import type { GenericEndpointContext, HookEndpointContext, ValidateUserInfoSource } from "@better-auth/core";
import type { User } from "@better-auth/core/db";
import { APIError } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { sql } from "kysely";
import * as z from "zod";
import { controlResponseFailure } from "./events";
import { canonicalDomain, canonicalIP, defaultSecurityPolicy, securityPolicySchema, securitySubject, type SecurityPolicy } from "./security-policy";
import type { ControlDatabase, ControlEventInput, ControlPrincipal } from "./types";

export { canonicalDomain, canonicalIP, defaultSecurityPolicy, securityPolicySchema, securitySubject, type SecurityPolicy } from "./security-policy";

export interface SecurityRule { id: string; type: "ip" | "email-domain"; value: string; reason: string; expiresAt?: string; createdAt: string }
interface CounterRow { count: number; blockedUntil: Date | null; windowStartedAt: Date }
type SecurityContext = GenericEndpointContext & { context: HookEndpointContext["context"] };
export interface ControlSecurityOptions {
	database: ControlDatabase;
	secret: string;
	baseURL: string;
	ipHeader: "x-real-ip" | "cf-connecting-ip";
	requireTrustedIP?: boolean;
	requireAdmin: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>;
	recordEvent: (ctx: GenericEndpointContext, event: ControlEventInput) => Promise<void>;
	notifyNewDevice?: (user: { id: string; name: string; email: string }, context: { ipAddress?: string; userAgent?: string }) => Promise<void>;
	/** A test clock only affects local security counters; production uses the current time. */
	now?: () => Date;
}

const failurePaths = new Set(["/sign-in/email", "/sign-in/username", "/sign-in/phone-number", "/phone-number/verify", "/siwe/verify", "/one-tap/callback", "/sign-in/email-otp", "/email-otp/verify-email", "/email-otp/verify-email-otp", "/two-factor/verify-totp", "/two-factor/verify-backup-code", "/two-factor/verify-otp", "/sign-in/passkey", "/passkey/verify-authentication", "/magic-link/verify"]);
const requestPaths = new Set(["/sign-in/magic-link", "/email-otp/send-verification-otp", "/email-otp/request-password-reset", "/email-otp/request-email-change", "/phone-number/send-otp", "/phone-number/request-password-reset", "/siwe/nonce", "/siwe/get-nonce", "/passkey/generate-authenticate-options", "/request-password-reset", "/send-verification-email"]);
const successfulPaths = new Set(["/sign-in/email", "/sign-in/username", "/sign-in/phone-number", "/phone-number/verify", "/siwe/verify", "/one-tap/callback", "/sign-in/email-otp", "/email-otp/verify-email", "/sign-in/passkey", "/passkey/verify-authentication", "/magic-link/verify", "/verify-email", "/two-factor/verify-totp", "/two-factor/verify-backup-code", "/two-factor/verify-otp"]);
const isCallback = (path: string) => path.startsWith("/callback/") || path.startsWith("/oauth2/callback/") || path.startsWith("/sso/callback/") || path.startsWith("/sso/saml2/sp/acs/");
const protectedPath = (path: string) => failurePaths.has(path) || requestPaths.has(path) || path === "/sign-up/email" || path === "/sign-in/social" || path === "/sign-in/sso" || isCallback(path);
const emailDomain = (email: unknown) => typeof email === "string" && email.includes("@") ? canonicalDomain(email.slice(email.lastIndexOf("@") + 1)) : null;
const emailIdentity = (ctx: GenericEndpointContext) => typeof ctx.body?.email === "string" ? ctx.body.email.toLowerCase().trim().slice(0, 320) : undefined;
const authenticationIdentity = (ctx: GenericEndpointContext) => {
	const email = emailIdentity(ctx);
	if (email) return `email:${email}`;
	if (typeof ctx.body?.username === "string") return `username:${ctx.body.username.toLowerCase().trim().slice(0, 320)}`;
	if (typeof ctx.body?.phoneNumber === "string") return `phone:${ctx.body.phoneNumber.trim().slice(0, 64)}`;
	return undefined;
};
const responseFailed = (ctx: SecurityContext) => controlResponseFailure(ctx.context.returned, ctx.context.responseHeaders).failed;

/** Build native Better Auth endpoints/hooks backed by an independently migrated control schema. */
export function createControlSecurity(options: ControlSecurityOptions) {
	if (options.secret.length < 32) throw new Error("Local security protections require an authentication secret of at least 32 characters.");
	const database = options.database;
	const now = options.now ?? (() => new Date());
	const origin = new URL(options.baseURL).origin;
	const cleanup = async () => {
		const cutoff = new Date(now().getTime() - 2 * 86400_000);
		await sql`DELETE FROM "allauthSecurityCounter" WHERE "key" IN (SELECT "key" FROM "allauthSecurityCounter" WHERE "updatedAt" < ${cutoff} AND ("blockedUntil" IS NULL OR "blockedUntil" < ${now()}) LIMIT 500)`.execute(database);
		await sql`DELETE FROM "allauthKnownDevice" WHERE "id" IN (SELECT "id" FROM "allauthKnownDevice" WHERE "lastSeenAt" < ${new Date(now().getTime() - 180 * 86400_000)} LIMIT 100)`.execute(database);
	};
	const getPolicy = async (): Promise<SecurityPolicy> => {
		const result = await sql<{ policy: unknown }>`SELECT "policy" FROM "allauthSecurityPolicy" WHERE "id" = 'default'`.execute(database);
		return result.rows[0] ? securityPolicySchema.parse(result.rows[0].policy) : { ...defaultSecurityPolicy, blockedEmailDomains: [] };
	};
	const updatePolicy = async (input: unknown) => {
		const policy = securityPolicySchema.parse(input);
		policy.blockedEmailDomains = [...new Set(policy.blockedEmailDomains)];
		await sql`INSERT INTO "allauthSecurityPolicy" ("id", "policy", "updatedAt") VALUES ('default', ${JSON.stringify(policy)}::jsonb, ${now()}) ON CONFLICT ("id") DO UPDATE SET "policy" = EXCLUDED."policy", "updatedAt" = EXCLUDED."updatedAt"`.execute(database);
		return policy;
	};
	const trustedIP = (ctx: GenericEndpointContext) => canonicalIP(ctx.headers?.get(options.ipHeader));
	const activeRules = async () => (await sql<{ id: string; type: "ip" | "email-domain"; value: string; reason: string; expiresAt: Date | null; createdAt: Date }>`SELECT "id", "type", "value", "reason", "expiresAt", "createdAt" FROM "allauthSecurityRule" WHERE "expiresAt" IS NULL OR "expiresAt" > ${now()} ORDER BY "createdAt" DESC LIMIT 500`.execute(database)).rows;
	const publicRule = (rule: Awaited<ReturnType<typeof activeRules>>[number]): SecurityRule => ({ id: rule.id, type: rule.type, value: rule.value, reason: rule.reason, ...(rule.expiresAt ? { expiresAt: rule.expiresAt.toISOString() } : {}), createdAt: rule.createdAt.toISOString() });
	const counter = async (scope: string, subject: string, windowSeconds: number, max: number, blockSeconds: number) => {
		const key = await securitySubject(options.secret, scope, subject);
		const current = now();
		const cutoff = new Date(current.getTime() - windowSeconds * 1000);
		const until = new Date(current.getTime() + blockSeconds * 1000);
		const result = await sql<CounterRow>`INSERT INTO "allauthSecurityCounter" ("key", "scope", "count", "windowStartedAt", "blockedUntil", "updatedAt")
			VALUES (${key}, ${scope}, 1, ${current}, CASE WHEN ${max} <= 1 THEN ${until}::timestamptz ELSE NULL END, ${current})
			ON CONFLICT ("key") DO UPDATE SET
				"count" = CASE WHEN "allauthSecurityCounter"."windowStartedAt" <= ${cutoff} THEN 1 ELSE LEAST("allauthSecurityCounter"."count" + 1, 2147483647) END,
				"windowStartedAt" = CASE WHEN "allauthSecurityCounter"."windowStartedAt" <= ${cutoff} THEN ${current} ELSE "allauthSecurityCounter"."windowStartedAt" END,
				"blockedUntil" = CASE WHEN "allauthSecurityCounter"."windowStartedAt" <= ${cutoff} THEN CASE WHEN ${max} <= 1 THEN ${until}::timestamptz ELSE NULL END WHEN "allauthSecurityCounter"."count" + 1 >= ${max} THEN ${until}::timestamptz ELSE "allauthSecurityCounter"."blockedUntil" END,
				"updatedAt" = ${current}
			RETURNING "count", "blockedUntil", "windowStartedAt"`.execute(database);
		return result.rows[0];
	};
	const isBlocked = async (scope: string, subject: string) => {
		const key = await securitySubject(options.secret, scope, subject);
		const row = (await sql<{ blockedUntil: Date | null }>`SELECT "blockedUntil" FROM "allauthSecurityCounter" WHERE "key" = ${key}`.execute(database)).rows[0];
		return Boolean(row?.blockedUntil && row.blockedUntil > now());
	};
	const rejectOrObserve = async (ctx: GenericEndpointContext, policy: SecurityPolicy, signal: string, rule?: { id: string; type: string }) => {
		await options.recordEvent(ctx, { type: "security.blocked", outcome: policy.mode === "enforce" ? "blocked" : "success", ipAddress: trustedIP(ctx) || undefined, metadata: { signal, monitor: policy.mode === "monitor", ...(rule ? { ruleId: rule.id, ruleType: rule.type } : {}) } });
		if (policy.mode === "enforce") throw new APIError("TOO_MANY_REQUESTS", { code: "ALLAUTH_SECURITY_BLOCKED", message: "This authentication request is temporarily unavailable. Try again later." });
	};
	const checkRules = async (ctx: GenericEndpointContext, policy: SecurityPolicy, email?: string, includeIP = true) => {
		const ip = includeIP ? trustedIP(ctx) : null;
		const domain = emailDomain(email);
		const rule = (await sql<{ id: string; type: string }>`SELECT "id", "type" FROM "allauthSecurityRule" WHERE ("expiresAt" IS NULL OR "expiresAt" > ${now()}) AND (("type" = 'ip' AND "value" = ${ip}) OR ("type" = 'email-domain' AND "value" = ${domain})) LIMIT 1`.execute(database)).rows[0];
		if (rule) await rejectOrObserve(ctx, policy, "explicit-rule", rule);
		else if (domain && policy.blockedEmailDomains.includes(domain)) await rejectOrObserve(ctx, policy, "email-domain-policy");
	};
	const beforeRequest = async (ctx: GenericEndpointContext) => {
		const policy = await getPolicy();
		const ip = trustedIP(ctx);
		if (!ip && options.requireTrustedIP) { await rejectOrObserve(ctx, policy, "missing-trusted-ip"); return; }
		await cleanup();
		await checkRules(ctx, policy, emailIdentity(ctx));
		if (!ip) return;
		const identity = authenticationIdentity(ctx);
		if (await isBlocked("fail-ip", ip) || (identity && await isBlocked("fail-ip-identity", `${ip}\0${identity}`))) await rejectOrObserve(ctx, policy, "credential-failure-limit");
		if (requestPaths.has(ctx.path || "")) {
			const requestCounter = await counter("request-ip", ip, policy.signUpWindowSeconds, policy.maxSignUpsPerIp * 5, policy.blockSeconds);
			if (requestCounter.count > policy.maxSignUpsPerIp * 5) await rejectOrObserve(ctx, policy, "authentication-message-velocity");
		}
	};
	const recordFailure = async (ctx: SecurityContext) => {
		if (!responseFailed(ctx) || (ctx.context.returned instanceof APIError && ctx.context.returned.body?.code === "ALLAUTH_SECURITY_BLOCKED")) return;
		const policy = await getPolicy();
		const ip = trustedIP(ctx);
		if (ip) {
			await counter("fail-ip", ip, policy.failureWindowSeconds, policy.maxFailuresPerIp, policy.blockSeconds);
			const identity = authenticationIdentity(ctx);
			if (identity) await counter("fail-ip-identity", `${ip}\0${identity}`, policy.failureWindowSeconds, policy.maxFailuresPerIp, policy.blockSeconds);
		}
		await options.recordEvent(ctx, { type: "security.sign-in-failed", outcome: "failure", ipAddress: ip || undefined, metadata: { method: ctx.path?.split("/").pop(), path: ctx.path } });
	};
	const validateUserInfo = async (data: { user: Partial<User>; source: ValidateUserInfoSource }, ctx: GenericEndpointContext) => {
		const policy = await getPolicy();
		await checkRules(ctx, policy, data.user.email);
		if (data.source.action !== "create-user" || data.source.method === "admin") return;
		const ip = trustedIP(ctx);
		if (!ip && options.requireTrustedIP) { await rejectOrObserve(ctx, policy, "missing-trusted-ip"); return; }
		if (ip && (await counter("signup-ip", ip, policy.signUpWindowSeconds, policy.maxSignUpsPerIp, policy.blockSeconds)).count > policy.maxSignUpsPerIp) await rejectOrObserve(ctx, policy, "signup-velocity");
	};
	const validateSession = async (userId: string, ctx: GenericEndpointContext) => {
		// A submitted email may differ from the wallet/username account actually authenticated.
		// Enforce domain rules against the fresh stored identity before a primary session exists.
		if (!successfulPaths.has(ctx.path || "") && !isCallback(ctx.path || "")) return;
		const user = await ctx.context.adapter.findOne<{ email: string }>({ model: "user", where: [{ field: "id", value: userId }], select: ["email"] });
		if (user) await checkRules(ctx, await getPolicy(), user.email, false);
	};
	const registerKnownDevice = async (ctx: SecurityContext) => {
		const current = ctx.context.newSession;
		if (!current || current.session.impersonatedBy || !current.user.emailVerified || responseFailed(ctx)) return;
		const live = await ctx.context.adapter.findOne<{ id: string; impersonatedBy?: string }>({ model: "session", where: [{ field: "id", value: current.session.id }] });
		// MFA hooks delete the provisional primary session. Only an authoritative surviving session is eligible.
		if (!live || live.impersonatedBy || (ctx.context.returned && typeof ctx.context.returned === "object" && "twoFactorRedirect" in ctx.context.returned && ctx.context.returned.twoFactorRedirect)) return;
		const policy = await getPolicy();
		const cookie = ctx.context.createAuthCookie("control_device");
		const cookieName = cookie.name;
		let token = await ctx.getSignedCookie(cookieName, options.secret);
		if (!token || !/^[a-f\d]{64}$/.test(token)) token = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("");
		const hash = await securitySubject(options.secret, "device", token);
		const newDevice = await database.transaction().execute(async (tx) => {
			await sql`SELECT pg_advisory_xact_lock(hashtext(${`allauth-device:${current.user.id}`}))`.execute(tx);
			const previous = (await sql<{ id: string }>`SELECT "id" FROM "allauthKnownDevice" WHERE "userId" = ${current.user.id} AND "deviceHash" = ${hash}`.execute(tx)).rows[0];
			if (previous) { await sql`UPDATE "allauthKnownDevice" SET "lastSeenAt" = ${now()} WHERE "id" = ${previous.id}`.execute(tx); return false; }
			const hadDevice = (await sql`SELECT "id" FROM "allauthKnownDevice" WHERE "userId" = ${current.user.id} LIMIT 1`.execute(tx)).rows.length > 0;
			await sql`INSERT INTO "allauthKnownDevice" ("id", "userId", "deviceHash", "createdAt", "lastSeenAt") VALUES (${crypto.randomUUID()}, ${current.user.id}, ${hash}, ${now()}, ${now()})`.execute(tx);
			await sql`DELETE FROM "allauthKnownDevice" WHERE "id" IN (SELECT "id" FROM "allauthKnownDevice" WHERE "userId" = ${current.user.id} ORDER BY "lastSeenAt" DESC OFFSET 20)`.execute(tx);
			return hadDevice;
		});
		await ctx.setSignedCookie(cookieName, token, options.secret, { ...cookie.attributes, domain: undefined, httpOnly: true, secure: origin.startsWith("https:"), sameSite: "lax", maxAge: 180 * 86400 });
		if (!newDevice) return;
		const details = { ipAddress: trustedIP(ctx) || undefined, userAgent: ctx.headers?.get("user-agent")?.slice(0, 512) };
		await options.recordEvent(ctx, { type: "security.new-device", outcome: "success", userId: current.user.id, ...details, metadata: { newDevice: true } });
		if (policy.newDeviceNotifications && options.notifyNewDevice) {
			try { await options.notifyNewDevice({ id: current.user.id, name: current.user.name, email: current.user.email }, details); }
			catch { await options.recordEvent(ctx, { type: "security.new-device-notification-failed", outcome: "failure", userId: current.user.id }); }
		}
	};
	const requireWrite = async (ctx: GenericEndpointContext) => {
		ctx.setHeader("cache-control", "no-store");
		ctx.setHeader("pragma", "no-cache");
		const principal = await options.requireAdmin(ctx);
		const requestOrigin = ctx.headers?.get("origin");
		if (!requestOrigin || requestOrigin !== origin || ctx.headers?.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN", { message: "Security changes require a same-origin request." });
		return principal;
	};
	const endpoints = {
		controlSecurity: createAuthEndpoint("/control/security", { method: "GET", requireHeaders: true }, async (ctx) => {
			ctx.setHeader("cache-control", "no-store");
			ctx.setHeader("pragma", "no-cache");
			await options.requireAdmin(ctx);
			const [policy, rules, stats] = await Promise.all([getPolicy(), activeRules(), sql<{ blockedRequests: string; last24hFailures: string }>`SELECT COUNT(*) FILTER (WHERE "type" = 'security.blocked' AND "outcome" = 'blocked') AS "blockedRequests", COUNT(*) FILTER (WHERE "type" = 'security.sign-in-failed') AS "last24hFailures" FROM "allauthEvent" WHERE "createdAt" >= ${new Date(now().getTime() - 86400_000)}`.execute(database)]);
			const breachProtection = ctx.context.getPlugin("have-i-been-pwned");
			return ctx.json({ policy, rules: rules.map(publicRule), stats: { blockedRequests: Number(stats.rows[0]?.blockedRequests || 0), last24hFailures: Number(stats.rows[0]?.last24hFailures || 0), activeRules: rules.length }, capabilities: { credentialStuffing: true, velocity: true, blockRules: true, newDeviceNotifications: Boolean(options.notifyNewDevice), botChallenge: false, impossibleTravel: false, breachedPasswords: Boolean(breachProtection && breachProtection.options?.enabled !== false) } });
		}),
		controlSecurityUpdate: createAuthEndpoint("/control/security/update", { method: "POST", requireHeaders: true, body: z.object({ policy: securityPolicySchema }).strict() }, async (ctx) => {
			const principal = await requireWrite(ctx);
			const policy = await updatePolicy(ctx.body.policy);
			await options.recordEvent(ctx, { type: "security.policy.updated", outcome: "success", actorId: principal.user.id, metadata: { fields: Object.keys(policy) } });
			return ctx.json({ policy });
		}),
		controlSecurityRulesAdd: createAuthEndpoint("/control/security/rules/add", { method: "POST", requireHeaders: true, body: z.object({ type: z.enum(["ip", "email-domain"]), value: z.string().min(1).max(253), reason: z.string().trim().min(1).max(200), expiresAt: z.iso.datetime({ offset: true }).optional() }).strict() }, async (ctx) => {
			const principal = await requireWrite(ctx);
			const value = ctx.body.type === "ip" ? canonicalIP(ctx.body.value) : canonicalDomain(ctx.body.value);
			const expiresAt = ctx.body.expiresAt ? new Date(ctx.body.expiresAt) : null;
			if (!value || (expiresAt && (expiresAt <= now() || expiresAt.getTime() > now().getTime() + 365 * 86400_000))) throw new APIError("BAD_REQUEST", { message: "Supply a valid IP or email domain and an optional expiry within one year." });
			const result = await sql<Awaited<ReturnType<typeof activeRules>>[number]>`INSERT INTO "allauthSecurityRule" ("id", "type", "value", "reason", "expiresAt", "createdAt") VALUES (${crypto.randomUUID()}, ${ctx.body.type}, ${value}, ${ctx.body.reason}, ${expiresAt}, ${now()}) ON CONFLICT ("type", "value") DO UPDATE SET "reason" = EXCLUDED."reason", "expiresAt" = EXCLUDED."expiresAt" RETURNING *`.execute(database);
			await options.recordEvent(ctx, { type: "security.rule.added", outcome: "success", actorId: principal.user.id, targetId: result.rows[0].id, metadata: { ruleType: ctx.body.type } });
			return ctx.json({ rule: publicRule(result.rows[0]) });
		}),
		controlSecurityRulesRemove: createAuthEndpoint("/control/security/rules/remove", { method: "POST", requireHeaders: true, body: z.object({ id: z.string().uuid() }).strict() }, async (ctx) => {
			const principal = await requireWrite(ctx);
			await sql`DELETE FROM "allauthSecurityRule" WHERE "id" = ${ctx.body.id}`.execute(database);
			await options.recordEvent(ctx, { type: "security.rule.removed", outcome: "success", actorId: principal.user.id, targetId: ctx.body.id });
			return ctx.json({ success: true });
		}),
	};
	return {
		endpoints,
		hooks: {
			before: [{ matcher: (ctx: HookEndpointContext) => protectedPath(ctx.path || ""), handler: createAuthMiddleware(beforeRequest) }],
			after: [
				{ matcher: (ctx: HookEndpointContext) => failurePaths.has(ctx.path || "") || isCallback(ctx.path || ""), handler: createAuthMiddleware(recordFailure) },
				{ matcher: (ctx: HookEndpointContext) => successfulPaths.has(ctx.path || "") || isCallback(ctx.path || ""), handler: createAuthMiddleware(registerKnownDevice) },
			],
		},
		getPolicy, updatePolicy, beforeRequest, recordFailure, validateUserInfo, validateSession, registerKnownDevice,
	};
}
