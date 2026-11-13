import * as z from "zod";
import type { AuthPolicy } from "./auth-policy/policy";
import type { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { createPlatformSessionIssuer } from "./platform-session-issuance";
import type { LegacyMfaKeys } from "./projects/legacy-mfa-record";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import { createOwnedPendingMfa } from "./projects/owned-mfa";
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

const input = z.object({
	code: z.string().min(1).max(128),
	trustDevice: z.boolean().optional(),
	disableSession: z.boolean().optional(),
	oauth_query: z.string().optional(),
});

const changedOwner = Symbol("platform MFA owner changed");
const blockedOwner = Symbol("platform MFA owner blocked");

export function createPlatformPendingMfa(options: {
	issuer: string;
	signingSecret: string;
	securitySecret: string;
	keys: LegacyMfaKeys;
	store: ReturnType<typeof createPlatformIssuerStore>;
	sessions: ReturnType<typeof createPlatformSessionIssuer>;
	readSession: ReturnType<typeof createPlatformIssuerSessionReader>;
	readBody: (request: Request) => Promise<unknown>;
	readPolicy: () => Promise<AuthPolicy>;
	trustedIP: (request: Request) => string | null;
	requireTrustedIP: boolean;
	trustedOrigins: readonly string[];
	continueAuthenticated: ReturnType<
		typeof createOwnedProjectIssuerAuthorization
	>["continueAuthenticated"];
	notifyNewDevice?: (
		user: { id: string; name: string; email: string },
		request: Request,
	) => Promise<void>;
}) {
	const { issuer, store, signingSecret, sessions } = options;
	const secure = issuer.startsWith("https:");
	const prefix = `${secure ? "__Secure-" : ""}better-auth.`;
	const deviceSessionCookies =
		options.securitySecret === signingSecret
			? sessions
			: createPlatformSessionIssuer({
					issuer,
					signingSecret: options.securitySecret,
					trustedIP: options.trustedIP,
				});
	const origins = new Set([issuer, ...options.trustedOrigins]);
	const mfa = createOwnedPendingMfa({
		schema: store.schemaName,
		cookiePrefix: "better-auth",
		secureCookies: secure,
		signingSecret,
		keys: options.keys,
		transaction: store.transaction,
	});
	const security = createOwnedProjectSecurity({
		secret: options.securitySecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.requireTrustedIP,
	});
	const blocked = () =>
		issuerJSON(
			{
				code: projectSecurityBlockedCode,
				message: projectSecurityBlockedMessage,
			},
			429,
		);

	return async function verify(
		request: Request,
	): Promise<Response | undefined> {
		const pathname = new URL(request.url).pathname;
		const path = pathname.slice("/api/auth".length);
		const method =
			pathname === "/api/auth/two-factor/verify-totp"
				? "totp"
				: pathname === "/api/auth/two-factor/verify-backup-code"
					? "backup"
					: undefined;
		if (!method || request.method !== "POST") return;
		// Authenticated enrollment and factor maintenance are separate operations.
		if (
			await store.transaction((client) =>
				options.readSession(request.headers, client),
			)
		)
			return;
		const origin = request.headers.get("origin");
		if (
			!origin ||
			!origins.has(origin) ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			return issuerJSON(
				{ code: "INVALID_ORIGIN", message: "Invalid origin" },
				403,
			);

		const denied = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 3,
				windowMs: 10_000,
			}),
		);
		if (denied) return denied;
		const body = input.safeParse(await options.readBody(request));
		if (!body.success)
			return issuerJSON(
				{ code: "INVALID_BODY", message: "Supply a verification code." },
				400,
			);
		const signed =
			body.data.oauth_query === undefined
				? null
				: readSignedProjectIssuerQuery(body.data.oauth_query, signingSecret);
		if (body.data.oauth_query !== undefined && !signed)
			return issuerJSON({ error: "invalid_signature" }, 400);
		if (await store.transaction((client) => security.admit(client, request)))
			return blocked();

		const policy = await options.readPolicy();
		const verifyOnly = method === "backup" && body.data.disableSession === true;
		try {
			const result = await mfa.complete(
				request.headers,
				{ method, ...body.data },
				async (client, pending) => {
					const {
						rows: [user],
					} = await client.query<{
						id: string;
						name: string;
						email: string;
						emailVerified: boolean;
					}>(
						`SELECT id,name,email,"emailVerified",image,"createdAt","updatedAt",role,banned,"banReason","banExpires",
					 "twoFactorEnabled","publicMetadata","directoryManaged","directoryDisabled","isAnonymous",username,"displayUsername"
					 FROM public."user" WHERE id=$1 AND (NOT $2::boolean OR "emailVerified")`,
						[pending.userId, policy.mfaMode === "required"],
					);
					if (!user) throw changedOwner;
					if (verifyOnly) return { user, credential: null };
					if (await security.denySession(client, request, user.email))
						throw blockedOwner;
					const lifetime = pending.dontRememberMe
						? 86_400
						: policy.sessionExpiresInSeconds;
					const session = await sessions.issue(client, {
						userId: user.id,
						lifetime,
						request,
						path,
					});
					await recordOwnedProjectEvent(client, {
						type: "auth.sign-in",
						outcome: "success",
						actorId: user.id,
						userId: user.id,
						targetId: session.id,
						ipAddress: security.trustedIP(request) ?? undefined,
						userAgent: request.headers.get("user-agent") ?? undefined,
						metadata: { path, method: path.split("/").pop() },
					});
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
					const cookies = [
						sessions.cookie(
							"session_token",
							session.token,
							pending.dontRememberMe ? undefined : lifetime,
						),
						...(pending.dontRememberMe
							? [sessions.cookie("dont_remember", "true")]
							: []),
					];
					if (device) {
						// The installed device cookie uses the security key, independently of cookie rotation.
						cookies.push(
							deviceSessionCookies.cookie(
								"control_device",
								device.token,
								180 * 86_400,
							),
						);
					}
					return {
						user,
						credential: { session, cookies, notify: device?.notify },
					};
				},
			);
			if (result.status === "rejected") {
				await store.transaction(async (client) => {
					await security.failed(client, request, path);
					await recordOwnedProjectEvent(client, {
						type: "auth.sign-in",
						outcome: "failure",
						ipAddress: security.trustedIP(request) ?? undefined,
						userAgent: request.headers.get("user-agent") ?? undefined,
						metadata: { path, errorCode: result.code },
					});
				});
				const response = issuerJSON(
					{ code: result.code, message: result.message },
					result.httpStatus,
				);
				for (const cookie of result.setCookies)
					response.headers.append("set-cookie", cookie);
				return response;
			}
			const { user, credential } = result.session;
			if (!credential) return issuerJSON({ user });
			if (credential.notify && options.notifyNewDevice) {
				try {
					await options.notifyNewDevice(user, request);
				} catch {
					await store.transaction((client) =>
						security.notificationFailed(client, request, user.id),
					);
				}
			}
			const params = signed?.params;
			if (params) {
				const prompt = params
					.get("prompt")
					?.split(" ")
					.filter((value) => value !== "login")
					.join(" ");
				if (prompt) params.set("prompt", prompt);
				else params.delete("prompt");
				if (signed && credential.session.createdAt.getTime() >= signed.issuedAt)
					params.delete("max_age");
			}
			const response = params
				? await options.continueAuthenticated(
						request,
						params,
						{ id: credential.session.id, userId: user.id },
						"json",
					)
				: issuerJSON({ user, token: credential.session.token });
			const mutable = new Response(response.body, response);
			for (const cookie of [...credential.cookies, ...result.setCookies])
				mutable.headers.append("set-cookie", cookie);
			return mutable;
		} catch (error) {
			if (error === blockedOwner) return blocked();
			if (error === changedOwner)
				return issuerJSON(
					{
						code: "INVALID_TWO_FACTOR_COOKIE",
						message: "Invalid two factor cookie",
					},
					401,
				);
			throw error;
		}
	};
}
