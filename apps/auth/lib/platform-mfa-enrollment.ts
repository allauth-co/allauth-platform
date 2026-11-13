import * as z from "zod";
import type { AuthPolicy } from "./auth-policy/policy";
import type { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import type { createPlatformSessionIssuer } from "./platform-session-issuance";
import type { LegacyMfaKeys } from "./projects/legacy-mfa-record";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import { createOwnedRealmMfaEnrollment } from "./projects/owned-mfa-enrollment";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import {
	createOwnedProjectSecurity,
	projectSecurityBlockedCode,
	projectSecurityBlockedMessage,
} from "./projects/owned-project-security";

const password = z.object({ password: z.string().optional() });
const enable = password.extend({
	issuer: z.string().max(200).optional(),
	method: z.enum(["otp", "totp"]).optional(),
});
const factor = z.object({
	code: z.string().min(1).max(128),
	trustDevice: z.boolean().optional(),
	disableSession: z.boolean().optional(),
});
const paths = new Set([
	"enable",
	"disable",
	"get-totp-uri",
	"generate-backup-codes",
	"verify-totp",
	"verify-backup-code",
]);

export function createPlatformMfaEnrollment(options: {
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
}) {
	const { issuer, signingSecret, store, sessions } = options;
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

	return async function manage(
		request: Request,
	): Promise<Response | undefined> {
		const pathname = new URL(request.url).pathname;
		if (
			request.method !== "POST" ||
			!pathname.startsWith("/api/auth/two-factor/")
		)
			return;
		const operation = pathname.slice("/api/auth/two-factor/".length);
		if (!paths.has(operation)) return;
		const verifying =
			operation === "verify-totp" || operation === "verify-backup-code";
		const current = await store.transaction((client) =>
			options.readSession(request.headers, client),
		);
		if (!current && verifying) return;
		if (
			!origins.has(request.headers.get("origin") ?? "") ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			current?.session.impersonatedBy
		)
			return error(
				403,
				"FORBIDDEN",
				"Use your signed-in browser session for this action.",
			);
		if (!current) return error(401, "UNAUTHORIZED", "Unauthorized");
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(
				client,
				options.trustedIP(request),
				`/two-factor/${operation}`,
				{ max: 3, windowMs: 10_000 },
			),
		);
		if (limited) return limited;
		if (
			verifying &&
			(await store.transaction((client) => security.admit(client, request)))
		)
			return error(
				429,
				projectSecurityBlockedCode,
				projectSecurityBlockedMessage,
			);
		const policy = await options.readPolicy();
		const input = await options.readBody(request);
		const enrollment = createOwnedRealmMfaEnrollment({
			schema: store.schemaName,
			cookiePrefix: "better-auth",
			issuer: "AllAuth",
			keys: options.keys,
			secureCookies: secure,
			transaction: store.transaction,
			mfaRequired: policy.mfaMode === "required",
			auditContext: (request) => ({
				ipAddress: security.trustedIP(request) ?? undefined,
				userAgent: request.headers.get("user-agent") ?? undefined,
			}),
			async lockAuthority(client) {
				const user = await store.lockUser(client, current.user.id);
				if (
					!user ||
					user.banned ||
					user.directoryDisabled ||
					user.isAnonymous ||
					(policy.mfaMode === "required" &&
						(!user.emailVerified || !user.twoFactorEnabled))
				)
					return null;
				const {
					rows: [session],
				} = await client.query<{
					id: string;
					token: string;
					activeOrganizationId: string | null;
					activeTeamId: string | null;
				}>(
					`SELECT id,token,"activeOrganizationId","activeTeamId" FROM public."session"
					WHERE id=$1 AND "userId"=$2 AND "expiresAt">statement_timestamp()
					AND "impersonatedBy" IS NULL FOR UPDATE`,
					[current.session.id, user.id],
				);
				return session
					? { user: { ...user, email: current.user.email }, session }
					: null;
			},
			async rotateSession(client, request, { user, session }, path) {
				const remembered = !readLegacySessionCookie(
					request.headers,
					prefix + "dont_remember",
					signingSecret,
				);
				const lifetime = remembered ? policy.sessionExpiresInSeconds : 86_400;
				const replacement = await sessions.issue(client, {
					userId: user.id,
					lifetime,
					request,
					path,
					activeOrganizationId: session.activeOrganizationId,
					activeTeamId: session.activeTeamId,
				});
				return {
					sessionId: replacement.id,
					value: {
						token: replacement.token,
						cookie: sessions.cookie(
							"session_token",
							replacement.token,
							remembered ? lifetime : undefined,
						),
					},
				};
			},
		});
		if (verifying) {
			const parsed = factor.safeParse(input);
			if (!parsed.success)
				return error(400, "INVALID_BODY", "Supply a verification code.");
			const method = operation === "verify-totp" ? "totp" : "backup";
			const result = await enrollment.verify(request, {
				method,
				code: parsed.data.code,
			});
			if (result.status === "rejected") {
				await store.transaction((client) =>
					security.failed(client, request, `/two-factor/${operation}`),
				);
				return error(result.httpStatus, result.code, result.message);
			}
			const user =
				result.status === "rotated"
					? { ...current.user, twoFactorEnabled: true }
					: current.user;
			const response = issuerJSON({
				token:
					result.status === "rotated"
						? result.value.token
						: result.authority.session.token,
				user,
			});
			if (result.status === "rotated") {
				response.headers.append("set-cookie", result.value.cookie);
				for (const cookie of result.setCookies)
					response.headers.append("set-cookie", cookie);
			}
			return response;
		}
		const parsed = (operation === "enable" ? enable : password).safeParse(
			input,
		);
		if (!parsed.success)
			return error(400, "INVALID_BODY", "Invalid two-factor request.");
		const result =
			operation === "enable"
				? await enrollment.enable(request, parsed.data)
				: operation === "disable"
					? await enrollment.disable(request, parsed.data)
					: operation === "get-totp-uri"
						? await enrollment.readTotp(request, parsed.data)
						: await enrollment.rotateBackupCodes(request, parsed.data);
		if (result.status === "rejected")
			return error(result.httpStatus, result.code, result.message);
		if (result.status === "setup")
			return issuerJSON({
				method: result.method,
				totpURI: result.totpURI,
				backupCodes: result.backupCodes,
			});
		if (result.status === "uri") return issuerJSON({ totpURI: result.totpURI });
		if (result.status === "codes")
			return issuerJSON({ status: true, backupCodes: result.backupCodes });
		const response = issuerJSON({ status: true });
		response.headers.append("set-cookie", result.value.cookie);
		for (const cookie of result.setCookies)
			response.headers.append("set-cookie", cookie);
		return response;
	};
}
