import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { defaultPasswordPolicy } from "./auth-policy/password";
import type { AuthPolicy } from "./auth-policy/policy";
import { clerkCompatiblePasswords } from "./clerk-password";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import type { createPlatformSessionIssuer } from "./platform-session-issuance";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import type { createOwnedPendingMfa } from "./projects/owned-mfa";
import { recordOwnedProjectEvent } from "./projects/owned-project-engine-store";
import type { createOwnedProjectIssuerAuthorization } from "./projects/owned-project-issuer-authorization";
import { readSignedProjectIssuerQuery } from "./projects/owned-project-issuer-authorization-query";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import {
	createOwnedProjectSecurity,
	projectSecurityBlockedCode,
	projectSecurityBlockedMessage,
} from "./projects/owned-project-security";

const fields = z.object({
	password: z.string().min(1).max(defaultPasswordPolicy.maxLength),
	rememberMe: z.boolean().optional(),
	callbackURL: z
		.string()
		.max(24 * 1024)
		.optional(),
	oauth_query: z.string().optional(),
});
const byEmail = fields.extend({ email: z.email().max(320) });
const byUsername = fields.extend({
	username: z
		.string()
		.min(3)
		.max(30)
		.regex(/^[a-zA-Z0-9_.]+$/),
});

interface Credential {
	id: string;
	name: string;
	email: string;
	emailVerified: boolean;
	directoryDisabled: boolean | null;
	directoryManaged: boolean | null;
	isAnonymous: boolean | null;
	banned: boolean | null;
	banExpires: Date | null;
	twoFactorEnabled: boolean | null;
	password: string;
	user: Record<string, unknown>;
}

export function createPlatformPasswordSignIn(options: {
	database: Pool;
	issuer: string;
	signingSecret: string;
	securitySecret: string;
	trustedOrigins: readonly string[];
	store: ReturnType<typeof createPlatformIssuerStore>;
	sessions: ReturnType<typeof createPlatformSessionIssuer>;
	deviceCookies: ReturnType<typeof createPlatformSessionIssuer>;
	mfa: ReturnType<typeof createOwnedPendingMfa>;
	readBody: (request: Request) => Promise<unknown>;
	readPolicy: () => Promise<AuthPolicy>;
	trustedIP: (request: Request) => string | null;
	requireTrustedIP: boolean;
	continueAuthenticated: ReturnType<
		typeof createOwnedProjectIssuerAuthorization
	>["continueAuthenticated"];
	notifyNewDevice?: (user: Credential, request: Request) => Promise<void>;
}) {
	const { store, sessions, issuer } = options;
	const origins = new Set([issuer, ...options.trustedOrigins]);
	const secure = issuer.startsWith("https:");
	const prefix = `${secure ? "__Secure-" : ""}better-auth.`;
	const security = createOwnedProjectSecurity({
		secret: options.securitySecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.requireTrustedIP,
	});
	const error = (status: number, code: string, message: string) =>
		issuerJSON({ code, message }, status);
	const blocked = () =>
		error(429, projectSecurityBlockedCode, projectSecurityBlockedMessage);

	async function credential(
		field: "email" | "username",
		value: string,
		tx?: PoolClient,
	) {
		const { rows } = await (tx ?? options.database).query<Credential>(
			`SELECT u.id,u.name,u.email,u."emailVerified",u."directoryDisabled",u."directoryManaged",
			 u."isAnonymous",u.banned,u."banExpires",u."twoFactorEnabled",a.password,
			 to_jsonb(u) - ARRAY['privateMetadata','directoryDisabled'] AS "user"
			 FROM public."user" u JOIN public."account" a ON a."userId"=u.id
			 WHERE u.${field}=$1 AND a."providerId"='credential' AND a."accountId"=u.id AND a.password IS NOT NULL
			 ORDER BY a.id LIMIT 2${tx ? " FOR UPDATE OF u,a" : ""}`,
			[value],
		);
		return rows.length === 1 ? rows[0]! : null;
	}

	return async function signIn(
		request: Request,
	): Promise<Response | undefined> {
		const pathname = new URL(request.url).pathname;
		const field =
			pathname === "/api/auth/sign-in/email"
				? "email"
				: pathname === "/api/auth/sign-in/username"
					? "username"
					: undefined;
		if (!field || request.method !== "POST") return;
		const path = `/sign-in/${field}`;
		const media = request.headers.get("content-type")?.split(";", 1)[0]?.trim();
		if (media !== "application/json") return;
		const origin = request.headers.get("origin");
		if (
			(origin && !origins.has(origin)) ||
			(!origin &&
				(request.headers.has("cookie") ||
					request.headers.has("sec-fetch-site"))) ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			request.headers.has("authorization")
		)
			return error(403, "INVALID_ORIGIN", "Invalid origin");
		const policy = await options.readPolicy();
		if (!policy.emailAndPasswordEnabled)
			return error(
				403,
				"FORBIDDEN",
				"Password authentication is disabled for this application.",
			);
		const body = (field === "email" ? byEmail : byUsername).safeParse(
			await options.readBody(request.clone() as Request),
		);
		if (!body.success)
			return error(
				400,
				"INVALID_BODY",
				"Supply a valid sign-in identifier and password.",
			);
		const login = (
			"email" in body.data ? body.data.email : body.data.username
		).toLowerCase();
		const signed =
			body.data.oauth_query === undefined
				? null
				: readSignedProjectIssuerQuery(
						body.data.oauth_query,
						options.signingSecret,
					);
		if (
			body.data.oauth_query !== undefined &&
			(!signed || signed.consentSessionId)
		)
			return issuerJSON({ error: "invalid_signature" }, 400);
		const callback = body.data.callbackURL;
		if (callback) {
			try {
				const target = new URL(callback, issuer);
				if (
					!origins.has(target.origin) ||
					target.username ||
					target.password ||
					callback.startsWith("//") ||
					callback.includes("\\")
				)
					return error(403, "INVALID_CALLBACK_URL", "Invalid callbackURL");
			} catch {
				return error(403, "INVALID_CALLBACK_URL", "Invalid callbackURL");
			}
		}
		const ip = options.trustedIP(request);
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, ip, path, {
				max: 3,
				windowMs: 10_000,
			}),
		);
		if (limited) return limited;
		const identity = field === "email" ? { email: login } : { username: login };
		if (
			await store.transaction((client) =>
				security.admit(client, request, identity),
			)
		)
			return blocked();
		const invalidCode =
			field === "email"
				? "INVALID_EMAIL_OR_PASSWORD"
				: "INVALID_USERNAME_OR_PASSWORD";
		const invalidMessage =
			field === "email"
				? "Invalid email or password"
				: "Invalid username or password";
		const auditContext = {
			ipAddress: security.trustedIP(request) ?? undefined,
			userAgent: request.headers.get("user-agent") ?? undefined,
		};
		async function failed(client: PoolClient) {
			await security.failed(client, request, path, identity);
			await recordOwnedProjectEvent(client, {
				type: "auth.sign-in",
				outcome: "failure",
				...auditContext,
				metadata: { path, errorCode: invalidCode },
			});
			return { response: error(401, invalidCode, invalidMessage) };
		}
		const observed = await credential(field, login);
		if (
			!observed ||
			!(await clerkCompatiblePasswords.verify({
				hash: observed.password,
				password: body.data.password,
			}))
		) {
			if (!observed) await clerkCompatiblePasswords.hash(body.data.password);
			return (await store.transaction(failed)).response;
		}
		const remembered = body.data.rememberMe !== false;
		const result = await store.transaction(async (client) => {
			const user = await credential(field, login, client);
			if (
				!user ||
				user.id !== observed.id ||
				user.password !== observed.password
			)
				return failed(client);
			// Email resend and expired-ban normalization remain on their installed handlers.
			if (
				(!user.emailVerified && policy.requireEmailVerification) ||
				(user.banned && user.banExpires && user.banExpires <= new Date())
			)
				return {};
			if (user.banned || user.directoryDisabled || user.isAnonymous)
				return failed(client);
			if (user.directoryManaged)
				return {
					response: error(
						403,
						"FORBIDDEN",
						"This account must sign in through its enterprise identity provider.",
					),
				};
			if (
				policy.mfaMode === "required" &&
				(!user.emailVerified || !user.twoFactorEnabled)
			)
				return {
					response: error(
						403,
						"FORBIDDEN",
						"This application requires an already verified account enrolled in MFA.",
					),
				};
			if (await security.denySession(client, request, user.email))
				return { response: blocked() };
			const cookies = remembered
				? [sessions.expire("dont_remember")]
				: [sessions.cookie("dont_remember", "true")];
			if (user.twoFactorEnabled) {
				const trusted = await options.mfa.rotateTrustedDevice(
					client,
					user.id,
					request.headers,
				);
				if (trusted.setCookie) cookies.push(trusted.setCookie);
				if (!trusted.trusted) {
					const challenge = await options.mfa.issue(client, user.id);
					if (!challenge) return {};
					await recordOwnedProjectEvent(client, {
						type: "auth.mfa-required",
						outcome: "success",
						...auditContext,
						metadata: { path },
					});
					const response = issuerJSON({
						twoFactorRedirect: true,
						twoFactorMethods: challenge.twoFactorMethods,
					});
					for (const cookie of [
						...cookies,
						sessions.expire("session_token"),
						challenge.setCookie,
					])
						response.headers.append("set-cookie", cookie);
					return { response };
				}
			}
			const lifetime = remembered ? policy.sessionExpiresInSeconds : 86_400;
			const session = await sessions.issue(client, {
				userId: user.id,
				lifetime,
				request,
				path,
			});
			await recordOwnedProjectEvent(client, {
				type: "auth.sign-in",
				outcome: "success",
				userId: user.id,
				actorId: user.id,
				targetId: session.id,
				...auditContext,
				metadata: { path, method: field },
			});
			cookies.push(
				sessions.cookie(
					"session_token",
					session.token,
					remembered ? lifetime : undefined,
				),
			);
			const device = user.emailVerified
				? await security.registerDevice(
						client,
						request,
						user.id,
						readLegacySessionCookie(
							request.headers,
							prefix + "control_device",
							options.securitySecret,
						),
					)
				: null;
			if (device)
				cookies.push(
					options.deviceCookies.cookie(
						"control_device",
						device.token,
						180 * 86_400,
					),
				);
			if (field === "email")
				cookies.push(
					`better-auth.last_used_login_method=email; Path=/; SameSite=Lax; Max-Age=2592000${secure ? "; Secure" : ""}`,
				);
			return { session, user, cookies, notify: device?.notify };
		});
		if ("response" in result) return result.response;
		if (!result.session) return;
		const { user, session, cookies } = result;
		if (result.notify && options.notifyNewDevice) {
			try {
				await options.notifyNewDevice(user, request);
			} catch {
				await store.transaction((client) =>
					security.notificationFailed(client, request, user.id),
				);
			}
		}
		if (signed) {
			const remaining = signed.params
				.get("prompt")
				?.split(" ")
				.filter((item) => item !== "login")
				.join(" ");
			if (remaining) signed.params.set("prompt", remaining);
			else signed.params.delete("prompt");
			if (session.createdAt.getTime() >= signed.issuedAt)
				signed.params.delete("max_age");
		}
		const response = signed
			? await options.continueAuthenticated(
					request,
					signed.params,
					{ id: session.id, userId: user.id },
					"json",
				)
			: issuerJSON({
					redirect: Boolean(callback),
					url: callback,
					user: user.user,
					token: session.token,
				});
		const mutable = new Response(response.body, response);
		if (!signed && callback) mutable.headers.set("location", callback);
		for (const cookie of cookies) mutable.headers.append("set-cookie", cookie);
		return mutable;
	};
}
