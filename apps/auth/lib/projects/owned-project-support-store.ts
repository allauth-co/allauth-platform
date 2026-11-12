import { createHash, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

export interface SupportSession {
	id: string;
	token: string;
	userId: string;
	impersonatedBy: string | null;
	expiresAt: Date;
	name: string;
	email: string;
	emailVerified: boolean;
	banned: boolean | null;
	directoryDisabled: boolean | null;
	role: string | null;
}

export const supportSessionKey = (id: string) => `support-session:${id}`;
export const supportEndedKey = (id: string) => `support-ended:${id}`;

/** Operations scoped to the server-selected project transaction. */
export function projectSupportStore(
	client: PoolClient,
	revoke?: (current: SupportSession) => Promise<boolean>,
) {
	async function session(
		value: string,
		key: "id" | "token",
		options: { allowExpired?: boolean; lock?: "read" | "write" } = {},
	) {
		const { allowExpired, lock } = options;
		const result = await client.query<SupportSession>(
			`SELECT s.id, s.token, s."userId", s."impersonatedBy", s."expiresAt",
				u.name, u.email, u."emailVerified", u.banned, u."directoryDisabled", u.role
			 FROM "session" s JOIN "user" u ON u.id = s."userId"
			 WHERE ${key === "id" ? "s.id" : "s.token"} = $1
			 ${allowExpired ? "" : 'AND s."expiresAt" > statement_timestamp()'}
			 ${lock === "write" ? "FOR UPDATE OF s" : lock === "read" ? "FOR SHARE OF s, u" : ""}`,
			[value],
		);
		return result.rows[0] ?? null;
	}

	async function verification(identifier: string) {
		const result = await client.query<{
			id: string;
			value: string;
			expiresAt: Date;
		}>(
			`SELECT id, value, "expiresAt" FROM "verification"
			 WHERE identifier = $1 ORDER BY "createdAt" DESC, id LIMIT 1`,
			[identifier],
		);
		return result.rows[0] ?? null;
	}

	async function reserve(identifier: string, binding: string, expiresAt: Date) {
		const id = createHash("sha256")
			.update(`reserve:${identifier}`)
			.digest("base64url");
		await client.query(
			`INSERT INTO "verification" (id, identifier, value, "expiresAt", "createdAt", "updatedAt")
			 VALUES ($1, $2, $3, $4, statement_timestamp(), statement_timestamp()) ON CONFLICT (id) DO NOTHING`,
			[id, identifier, binding, expiresAt],
		);
	}

	async function rememberEnded(sessionId: string, binding: string) {
		await reserve(
			supportEndedKey(sessionId),
			binding,
			new Date(Date.now() + 24 * 3600000),
		);
	}

	async function consumeVerification(identifier: string, rowId: string) {
		const result = await client.query(
			`DELETE FROM "verification" WHERE id = $1 AND identifier = $2 AND "expiresAt" > statement_timestamp()`,
			[rowId, identifier],
		);
		if (result.rowCount !== 1) return false;
		await client.query('DELETE FROM "verification" WHERE identifier = $1', [
			identifier,
		]);
		return true;
	}

	async function deleteBinding(sessionId: string) {
		await client.query('DELETE FROM "verification" WHERE identifier = $1', [
			supportSessionKey(sessionId),
		]);
	}

	async function revokeSession(current: SupportSession) {
		if (!current.impersonatedBy) return false;
		const session = await client.query(
			`SELECT id FROM "session" WHERE id = $1 AND token = $2 AND "userId" = $3 AND "impersonatedBy" = $4 FOR UPDATE`,
			[current.id, current.token, current.userId, current.impersonatedBy],
		);
		if (session.rowCount !== 1) return false;
		if (revoke) return revoke(current);
		await client.query(
			'UPDATE "oauthAccessToken" SET revoked = statement_timestamp() WHERE "sessionId" = $1 AND revoked IS NULL',
			[current.id],
		);
		await client.query(
			`UPDATE "oauthRefreshToken" SET revoked = statement_timestamp() WHERE "sessionId" = $1
			 AND revoked IS NULL AND NOT (scopes ? 'offline_access')`,
			[current.id],
		);
		await client.query('DELETE FROM "session" WHERE id = $1', [current.id]);
		return true;
	}

	async function recordEvent(
		current: SupportSession,
		userAgent: string | null,
		event: "session.impersonation-stopped" | "session.support-connected",
		metadata: Record<string, string>,
	) {
		await client.query(
			`INSERT INTO "allauthEvent" (id, type, outcome, "actorId", "userId", "targetId", "userAgent", "createdAt", metadata)
			 VALUES ($1, $2, 'success', $3, $4, $5, $6, statement_timestamp(), $7::jsonb)`,
			[
				randomUUID(),
				event,
				current.impersonatedBy,
				current.userId,
				current.id,
				userAgent?.slice(0, 512).replace(/[\u0000-\u001f]/g, "") ?? null,
				JSON.stringify(metadata),
			],
		);
	}

	async function recordEnd(
		current: SupportSession,
		userAgent: string | null,
		applicationAuditId?: string,
	) {
		const metadata: Record<string, string> =
			applicationAuditId === undefined
				? { signal: "connected-app-support" }
				: {
						signal: "application-support-revoke",
						applicationAuditId: applicationAuditId.replace(
							/[\u0000-\u001f]/g,
							"",
						),
					};
		await recordEvent(
			current,
			userAgent,
			"session.impersonation-stopped",
			metadata,
		);
	}

	return {
		session,
		verification,
		reserve,
		consumeVerification,
		recordEvent,
		rememberEnded,
		deleteBinding,
		revokeSession,
		recordEnd,
	};
}
