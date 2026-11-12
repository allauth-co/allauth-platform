import type { Pool } from "pg";
import type { ControlPrincipal } from "../control/types";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

interface PrincipalRow {
	sessionId: string;
	userId: string;
	impersonatedBy: string | null;
	name: string;
	email: string;
	emailVerified: boolean;
	role: string | null;
	banned: boolean | null;
}

/**
 * Read a live cookie-backed principal for an already selected project realm.
 * The caller supplies that realm's signing key and cookie policy from trusted
 * configuration. This probe does not refresh, revoke or issue credentials.
 */
export async function readProjectSessionPrincipal(
	database: Pick<Pool, "query">,
	project: Pick<Project, "schemaName" | "slug">,
	headers: Headers,
	options: { signingSecret: string; secureCookies: boolean },
): Promise<ControlPrincipal | null> {
	const schema = checkedProjectSchema(project.schemaName);
	const prefix = options.secureCookies ? "__Secure-" : "";
	const token = readLegacySessionCookie(
		headers,
		`${prefix}allauth_project_${project.slug}.session_token`,
		options.signingSecret,
	);
	if (!token) return null;

	// Explicit schemas prevent a caller's search_path from changing the realm.
	const result = await database.query<PrincipalRow>(
		`SELECT s.id AS "sessionId", s."userId", s."impersonatedBy",
			u.name, u.email, u."emailVerified", u.role, u.banned
		FROM "${schema}"."session" AS s
		JOIN "${schema}"."user" AS u ON u.id = s."userId"
		WHERE s.token = $1 AND s."expiresAt" >= statement_timestamp()`,
		[token],
	);
	const row = result.rows[0];
	if (!row) return null;
	return {
		session: {
			id: row.sessionId,
			userId: row.userId,
			impersonatedBy: row.impersonatedBy ?? undefined,
		},
		user: {
			id: row.userId,
			name: row.name,
			email: row.email,
			emailVerified: row.emailVerified,
			role: row.role ?? undefined,
			banned: row.banned ?? undefined,
		},
	};
}
