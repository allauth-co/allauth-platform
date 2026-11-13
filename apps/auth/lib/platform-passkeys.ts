import type { Pool, PoolClient } from "pg";
import type { AuthPolicy } from "./auth-policy/policy";
import type { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { createPlatformSessionIssuer } from "./platform-session-issuance";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import type { createOwnedPendingMfa } from "./projects/owned-mfa";
import { createOwnedProjectPasskeyHttp } from "./projects/owned-passkey-http";
import { recordOwnedProjectEvent } from "./projects/owned-project-engine-store";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import {
	createOwnedProjectSecurity,
	projectSecurityBlockedCode,
	projectSecurityBlockedMessage,
} from "./projects/owned-project-security";

export function createPlatformPasskeys(options: {
	database: Pool;
	issuer: string;
	signingSecret: string;
	securitySecret: string;
	store: ReturnType<typeof createPlatformIssuerStore>;
	sessions: ReturnType<typeof createPlatformSessionIssuer>;
	mfa: ReturnType<typeof createOwnedPendingMfa>;
	readSession: ReturnType<typeof createPlatformIssuerSessionReader>;
	readBody: (request: Request, limit: number) => Promise<unknown>;
	readPolicy: () => Promise<AuthPolicy>;
	trustedIP: (request: Request) => string | null;
	requireTrustedIP: boolean;
	trustedOrigins: readonly string[];
	notifyNewDevice?: (
		user: { name: string; email: string },
		request: Request,
	) => Promise<void>;
}) {
	const { issuer, store, signingSecret, sessions, mfa } = options;
	const prefix = `${issuer.startsWith("https:") ? "__Secure-" : ""}better-auth.`;
	const origins = new Set([issuer, ...options.trustedOrigins]);
	const security = createOwnedProjectSecurity({
		secret: options.securitySecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.requireTrustedIP,
	});
	const deviceCookies =
		options.securitySecret === signingSecret
			? sessions
			: createPlatformSessionIssuer({
					issuer,
					signingSecret: options.securitySecret,
					trustedIP: options.trustedIP,
				});
	const forbidden = () =>
		issuerJSON(
			{
				code: "FORBIDDEN",
				message: "Use your signed-in browser session for this action.",
			},
			403,
		);
	const blocked = () =>
		issuerJSON(
			{
				code: projectSecurityBlockedCode,
				message: projectSecurityBlockedMessage,
			},
			429,
		);
	const auditContext = (request: Request) => ({
		ipAddress: security.trustedIP(request) ?? undefined,
		userAgent: request.headers.get("user-agent") ?? undefined,
	});
	const assertPath = "/passkey/verify-authentication";
	const readSession = (request: Request) =>
		options.readSession(request.headers, options.database);
	async function issue(
		client: PoolClient,
		request: Request,
		userId: string,
		policy: AuthPolicy,
		path: string,
	) {
		const {
			rows: [user],
		} = await client.query<{
			id: string;
			name: string;
			email: string;
			emailVerified: boolean;
			twoFactorEnabled: boolean;
			output: Record<string, unknown>;
		}>(
			`SELECT id,name,email,"emailVerified","twoFactorEnabled",to_jsonb(u)-ARRAY['privateMetadata','directoryDisabled'] AS output
			 FROM public."user" u WHERE id=$1`,
			[userId],
		);
		if (!user) return null;
		if (
			(policy.requireEmailVerification && !user.emailVerified) ||
			(policy.mfaMode === "required" &&
				(!user.emailVerified || !user.twoFactorEnabled))
		)
			return forbidden();
		if (await security.denySession(client, request, user.email))
			return blocked();
		const cookies: string[] = [];
		if (user.twoFactorEnabled) {
			const trust = await mfa.rotateTrustedDevice(
				client,
				userId,
				request.headers,
			);
			if (trust.setCookie) cookies.push(trust.setCookie);
			if (!trust.trusted) {
				const challenge = await mfa.issue(client, userId);
				if (!challenge) return forbidden();
				const response = issuerJSON({
					twoFactorRedirect: true,
					twoFactorMethods: challenge.twoFactorMethods,
				});
				await recordOwnedProjectEvent(client, {
					type: "auth.mfa-required",
					outcome: "success",
					...auditContext(request),
					metadata: { path },
				});
				for (const cookie of [
					...cookies,
					sessions.expire("session_token"),
					sessions.expire("dont_remember"),
					challenge.setCookie,
				])
					response.headers.append("set-cookie", cookie);
				return { response };
			}
		}
		const lifetime = policy.sessionExpiresInSeconds;
		const session = await sessions.issue(client, {
			userId,
			lifetime,
			request,
			path,
		});
		const {
			rows: [stored],
		} = await client.query('SELECT * FROM public."session" WHERE id=$1', [
			session.id,
		]);
		await recordOwnedProjectEvent(client, {
			type: "auth.sign-in",
			outcome: "success",
			actorId: userId,
			userId,
			targetId: session.id,
			...auditContext(request),
			metadata: { path, method: "passkey" },
		});
		const device = user.emailVerified
			? await security.registerDevice(
					client,
					request,
					userId,
					readLegacySessionCookie(
						request.headers,
						prefix + "control_device",
						options.securitySecret,
					),
				)
			: null;
		const response = issuerJSON({ session: stored, user: user.output });
		cookies.push(
			sessions.expire("dont_remember"),
			sessions.cookie("session_token", session.token, lifetime),
		);
		if (device)
			cookies.push(
				deviceCookies.cookie("control_device", device.token, 180 * 86_400),
			);
		for (const cookie of cookies) response.headers.append("set-cookie", cookie);
		return { response, notify: device?.notify ? user : undefined };
	}

	const passkeys = createOwnedProjectPasskeyHttp({
		database: options.database,
		schemaName: store.schemaName,
		transaction: store.transaction,
		cookiePrefix: prefix,
		signingSecret,
		rp: {
			id: new URL(issuer).hostname,
			name: "AllAuth",
			origins: [issuer],
			requireUserVerification: false,
		},
		readBody: options.readBody,
		auditContext,
		writeCookie(headers, name, value, maxAge) {
			const local = name.slice(prefix.length);
			headers.append(
				"set-cookie",
				value ? sessions.cookie(local, value, maxAge) : sessions.expire(local),
			);
		},
		async readSession(request) {
			const current = await readSession(request);
			if (
				!current ||
				current.session.impersonatedBy ||
				current.user.banned ||
				current.user.directoryDisabled
			)
				return null;
			const policy = await options.readPolicy();
			if (
				policy.mfaMode === "required" &&
				(!current.user.emailVerified || !current.user.twoFactorEnabled)
			)
				return null;
			return {
				userId: current.user.id,
				email: current.user.email,
				fresh: Date.now() - current.session.createdAt.getTime() < 86_400_000,
			};
		},
		async withSession(request, userId, fresh, work) {
			const token = readLegacySessionCookie(
				request.headers,
				prefix + "session_token",
				signingSecret,
			);
			if (!token) return null;
			const policy = await options.readPolicy();
			return store.transaction(async (client) => {
				const user = await store.lockUser(client, userId);
				if (
					!user ||
					user.banned ||
					user.directoryDisabled ||
					(policy.mfaMode === "required" &&
						(!user.emailVerified || !user.twoFactorEnabled))
				)
					return null;
				const current = await client.query(
					`SELECT 1 FROM public."session" WHERE token=$1 AND "userId"=$2 AND "impersonatedBy" IS NULL
					 AND "expiresAt">statement_timestamp()
					 AND (NOT $3::boolean OR "createdAt">statement_timestamp()-interval '1 day') FOR UPDATE`,
					[token, userId, fresh],
				);
				return current.rowCount === 1 ? work(client) : null;
			});
		},
		async admit(request, operation) {
			const path = new URL(request.url).pathname.slice("/api/auth".length);
			return store.transaction(async (client) => {
				const limited = await admitOwnedProjectNativeRoute(
					client,
					options.trustedIP(request),
					path,
					{ max: 100, windowMs: 60_000 },
				);
				if (limited) return limited;
				return (path === assertPath ||
					path === "/passkey/generate-authenticate-options") &&
					(await security.admit(client, request, {
						message: operation === "options",
					}))
					? blocked()
					: null;
			});
		},
		recordFailedAuthentication: (request) =>
			store.transaction(async (client) => {
				await security.failed(client, request, assertPath);
				await recordOwnedProjectEvent(client, {
					type: "auth.sign-in",
					outcome: "failure",
					...auditContext(request),
					metadata: { path: assertPath, errorCode: "AUTHENTICATION_FAILED" },
				});
			}),
		async completeSignIn(request, userId, record) {
			const policy = await options.readPolicy();
			const result = await store.transaction(async (client) => {
				const user = await store.lockUser(client, userId);
				if (
					!user ||
					user.banned ||
					user.directoryDisabled ||
					user.directoryManaged ||
					!(await record(client))
				)
					return null;
				return issue(client, request, userId, policy, assertPath);
			});
			if (!result || result instanceof Response) return result;
			if (result.notify && options.notifyNewDevice) {
				try {
					await options.notifyNewDevice(result.notify, request);
				} catch {
					await store.transaction((client) =>
						security.notificationFailed(client, request, userId),
					);
				}
			}
			return result.response;
		},
		async completeRegistration(client, request, userId) {
			const user = await store.lockUser(client, userId);
			if (!user || user.directoryManaged) return forbidden();
			const result = await issue(
				client,
				request,
				userId,
				await options.readPolicy(),
				"/passkey/verify-registration",
			);
			return result instanceof Response
				? result
				: (result?.response ?? forbidden());
		},
	});

	return async (path: string, request: Request) => {
		if (!path.startsWith("/passkey/")) return null;
		const origin = request.headers.get("origin");
		if (
			(origin && !origins.has(origin)) ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			(request.method === "POST" && !origin)
		)
			return forbidden();
		return passkeys(path, request);
	};
}
