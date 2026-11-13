import type { Pool } from "pg";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, setting } from "./configuration";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";

interface PlatformIssuerSessionRow {
	sessionId: string;
	userId: string;
	createdAt: Date;
	activeOrganizationId: string | null;
	impersonatedBy: string | null;
	name: string;
	email: string;
	emailVerified: boolean;
	role: string | null;
	banned: boolean | null;
	directoryDisabled: boolean | null;
}

/** Read the stored platform identity without renewing or changing its browser session. */
export function createPlatformIssuerSessionReader(env: AuthEnvironment) {
	const origin = authOrigin(env);
	const cookie = `${origin.startsWith("https:") ? "__Secure-" : ""}better-auth.session_token`;
	const { signingSecret } = readLegacyProjectKeyring(
		setting(env, "ALLAUTH_AUTH_SECRET"),
		setting(env, "BETTER_AUTH_SECRETS"),
	);
	if (signingSecret.length < 32)
		throw new Error("A platform session signing key is required.");

	return async (headers: Headers, database: Pick<Pool, "query">) => {
		const token = readLegacySessionCookie(headers, cookie, signingSecret);
		if (!token) return null;
		const {
			rows: [row],
		} = await database.query<PlatformIssuerSessionRow>(
			`SELECT s.id AS "sessionId", s."userId", s."createdAt", s."activeOrganizationId",
			  s."impersonatedBy", u.name, u.email, u."emailVerified", u.role, u.banned,
			  u."directoryDisabled"
			 FROM public."session" s JOIN public."user" u ON u.id = s."userId"
			 WHERE s.token = $1 AND s."expiresAt" >= statement_timestamp()`,
			[token],
		);
		if (!row) return null;
		return {
			session: {
				id: row.sessionId,
				userId: row.userId,
				createdAt: row.createdAt,
				activeOrganizationId: row.activeOrganizationId,
				impersonatedBy: row.impersonatedBy,
			},
			user: {
				id: row.userId,
				name: row.name,
				email: row.email,
				emailVerified: row.emailVerified,
				role: row.role,
				banned: row.banned,
				directoryDisabled: row.directoryDisabled,
			},
		};
	};
}
