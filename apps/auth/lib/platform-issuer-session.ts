import type { Pool } from "pg";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, setting } from "./configuration";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";

interface PlatformIssuerSessionRow {
	sessionId: string;
	userId: string;
	createdAt: Date;
	expiresAt: Date;
	activeOrganizationId: string | null;
	impersonatedBy: string | null;
	name: string;
	email: string;
	emailVerified: boolean;
	twoFactorEnabled: boolean | null;
	role: string | null;
	banned: boolean | null;
	directoryDisabled: boolean | null;
	isAnonymous: boolean | null;
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

	async function readStored(
		database: Pick<Pool, "query">,
		lookup: { token: string } | { sessionId: string; userId: string },
	) {
		const predicate =
			"token" in lookup ? "s.token = $1" : 's.id = $1 AND s."userId" = $2';
		const values =
			"token" in lookup ? [lookup.token] : [lookup.sessionId, lookup.userId];
		const {
			rows: [row],
		} = await database.query<PlatformIssuerSessionRow>(
			`SELECT s.id AS "sessionId", s."userId", s."createdAt", s."expiresAt", s."activeOrganizationId",
			  s."impersonatedBy", u.name, u.email, u."emailVerified", u.role, u.banned,
			  u."directoryDisabled", u."twoFactorEnabled", u."isAnonymous"
			 FROM public."session" s JOIN public."user" u ON u.id = s."userId"
			 WHERE ${predicate} AND s."expiresAt" >= statement_timestamp()`,
			values,
		);
		if (!row) return null;
		return {
			session: {
				id: row.sessionId,
				userId: row.userId,
				createdAt: row.createdAt,
				expiresAt: row.expiresAt,
				activeOrganizationId: row.activeOrganizationId,
				impersonatedBy: row.impersonatedBy,
			},
			user: {
				id: row.userId,
				name: row.name,
				email: row.email,
				emailVerified: row.emailVerified,
				twoFactorEnabled: row.twoFactorEnabled,
				role: row.role,
				banned: row.banned,
				directoryDisabled: row.directoryDisabled,
				isAnonymous: row.isAnonymous,
			},
		};
	}
	async function readCookie(headers: Headers, database: Pick<Pool, "query">) {
		const token = readLegacySessionCookie(headers, cookie, signingSecret);
		return token ? readStored(database, { token }) : null;
	}
	return Object.assign(readCookie, {
		/** The credential handler has already verified the just-issued session. */
		readAuthenticated: (
			database: Pick<Pool, "query">,
			identity: { id: string; userId: string },
		) =>
			readStored(database, { sessionId: identity.id, userId: identity.userId }),
	});
}
