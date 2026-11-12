import type { Pool, PoolClient } from "pg";
import { checkedProjectSchema } from "./validation";

interface ProjectUser {
	id: string;
	name: string;
	email: string;
	emailVerified: boolean;
	image: string | null;
	createdAt: Date | string;
	updatedAt: Date | string;
	role: string | null;
	banned: boolean | null;
	twoFactorEnabled: boolean | null;
	directoryManaged: boolean | null;
	directoryDisabled: boolean | null;
	isAnonymous: boolean | null;
	publicMetadata: unknown;
	username: string | null;
	displayUsername: string | null;
}

interface ProjectSession {
	id: string;
	userId: string;
	expiresAt: string;
	createdAt: string;
	updatedAt: string;
	ipAddress: string | null;
	userAgent: string | null;
	activeOrganizationId: string | null;
	activeTeamId: string | null;
	impersonatedBy: string | null;
}

const userFields = `u.id, u.name, u.email, u."emailVerified", u.image, u."createdAt",
	u."updatedAt", u.role, u.banned, u."twoFactorEnabled", u."directoryManaged",
	u."directoryDisabled", u."isAnonymous", u."publicMetadata", u.username, u."displayUsername"`;
const sessionFields = `s.id, s."userId", s."expiresAt", s."createdAt", s."updatedAt", s."ipAddress",
	s."userAgent", s."activeOrganizationId", s."activeTeamId", s."impersonatedBy"`;

export function projectUserResponse(user: ProjectUser) {
	return {
		id: user.id,
		name: user.name,
		email: user.email,
		emailVerified: user.emailVerified,
		image: user.image,
		createdAt: new Date(user.createdAt).toISOString(),
		updatedAt: new Date(user.updatedAt).toISOString(),
		role: user.role,
		banned: user.banned,
		twoFactorEnabled: user.twoFactorEnabled,
		isAnonymous: user.isAnonymous,
		publicMetadata: user.publicMetadata,
		username: user.username,
		displayUsername: user.displayUsername,
	};
}

interface Credential extends ProjectUser {
	password: string | null;
	enrolledFactor: boolean;
}

/** All calls in a transaction, including database triggers, use the selected realm's schema. */
export function createProjectEngineStore(database: Pool, schemaName: string) {
	const schema = checkedProjectSchema(schemaName);

	async function transaction<T>(work: (client: PoolClient) => Promise<T>) {
		const client = await database.connect();
		let discardConnection = false;
		try {
			await client.query("BEGIN");
			await client.query(`SET LOCAL search_path TO "${schema}"`);
			const result = await work(client);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			try {
				await client.query("ROLLBACK");
			} catch {
				discardConnection = true;
			}
			throw error;
		} finally {
			client.release(discardConnection);
		}
	}

	async function credential(email: string, client?: PoolClient) {
		const result = await (client ?? database).query<Credential>(
			`SELECT ${userFields}, a.password, EXISTS (
				SELECT 1 FROM "${schema}"."twoFactor" f WHERE f."userId" = u.id
			) AS "enrolledFactor"
			FROM "${schema}"."user" u
			JOIN "${schema}"."account" a ON a."userId" = u.id
			WHERE u.email = $1 AND a."providerId" = 'credential' AND a."accountId" = u.id
			ORDER BY a.id LIMIT 2${client ? " FOR UPDATE OF u, a" : ""}`,
			[email],
		);
		return result.rows.length === 1 ? result.rows[0] : null;
	}

	async function session(token: string, refreshWindow: number) {
		const result = await database.query<{
			session: ProjectSession;
			user: ProjectUser;
			refreshDue: boolean;
		}>(
			`SELECT row_to_json(s) AS session, row_to_json(u) AS "user",
				s."expiresAt" <= statement_timestamp() + $2::int * interval '1 second' AS "refreshDue"
			FROM (SELECT ${sessionFields} FROM "${schema}"."session" s
				WHERE s.token = $1 AND s."expiresAt" > statement_timestamp()) s
			JOIN LATERAL (SELECT ${userFields} FROM "${schema}"."user" u WHERE u.id = s."userId") u ON true`,
			[token, refreshWindow],
		);
		return result.rows[0] ?? null;
	}

	async function createSession(
		client: PoolClient,
		data: {
			id: string;
			token: string;
			userId: string;
			expiresIn: number;
			ip: string;
			userAgent: string;
		},
	) {
		await client.query(
			`INSERT INTO "session" (id, token, "userId", "createdAt", "updatedAt", "expiresAt", "ipAddress", "userAgent")
			 VALUES ($1, $2, $3, statement_timestamp(), statement_timestamp(),
				statement_timestamp() + $4::int * interval '1 second', $5, $6)`,
			[
				data.id,
				data.token,
				data.userId,
				data.expiresIn,
				data.ip,
				data.userAgent,
			],
		);
	}

	async function refresh(token: string, expiresIn: number, updateAge: number) {
		// An expired, concurrently revoked or concurrently refreshed session cannot be extended here.
		const result = await database.query<{ expiresAt: Date; updatedAt: Date }>(
			`UPDATE "${schema}"."session" s
			SET "expiresAt" = statement_timestamp() + $2::int * interval '1 second', "updatedAt" = statement_timestamp()
			FROM "${schema}"."user" u
			WHERE s.token = $1 AND u.id = s."userId" AND s."expiresAt" > statement_timestamp()
				AND s."expiresAt" <= statement_timestamp() + ($2::int - $3::int) * interval '1 second'
				AND s."impersonatedBy" IS NULL AND u.banned IS DISTINCT FROM true
				AND u."directoryDisabled" IS DISTINCT FROM true
			RETURNING s."expiresAt", s."updatedAt"`,
			[token, expiresIn, updateAge],
		);
		const row = result.rows[0];
		return row
			? {
					expiresAt: row.expiresAt.toISOString(),
					updatedAt: row.updatedAt.toISOString(),
				}
			: null;
	}

	async function list(userId: string) {
		return (
			await database.query<
				Pick<
					ProjectSession,
					"id" | "createdAt" | "expiresAt" | "ipAddress" | "userAgent"
				>
			>(
				`SELECT id, "createdAt", "expiresAt", "ipAddress", "userAgent" FROM "${schema}"."session"
			WHERE "userId" = $1 AND "expiresAt" > statement_timestamp()
			ORDER BY "createdAt" DESC LIMIT 100`,
				[userId],
			)
		).rows;
	}

	/** Delete only sessions in this realm, recording existing audit events in the same transaction. */
	async function revoke(
		selector:
			| { tokens: string[] }
			| { id: string; userId: string; currentToken: string },
		path: string,
	) {
		return transaction(async (client) => {
			const selected =
				"tokens" in selector
					? await client.query<{ id: string; userId: string }>(
							'SELECT id, "userId" FROM "session" WHERE token = ANY($1::text[]) ORDER BY id FOR UPDATE',
							[selector.tokens],
						)
					: await client.query<{ id: string; userId: string }>(
							`SELECT s.id, s."userId" FROM "session" s
					WHERE s.id = $1 AND s."userId" = $2 AND EXISTS (
						SELECT 1 FROM "session" a JOIN "user" u ON u.id = a."userId"
						WHERE a.token = $3 AND a."userId" = s."userId" AND a."expiresAt" > statement_timestamp()
							AND u."emailVerified" AND u.banned IS DISTINCT FROM true
							AND u."directoryDisabled" IS DISTINCT FROM true AND a."impersonatedBy" IS NULL
					) FOR UPDATE OF s`,
							[selector.id, selector.userId, selector.currentToken],
						);
			const ids = selected.rows.map((row) => row.id);
			if (ids.length === 0) return ids;
			const linked = await client.query<{ present: boolean }>(
				`SELECT (EXISTS (SELECT 1 FROM "oauthRefreshToken" WHERE "sessionId" = ANY($1::text[]))
					OR EXISTS (SELECT 1 FROM "oauthAccessToken" WHERE "sessionId" = ANY($1::text[]))
					OR ($2 AND EXISTS (SELECT 1 FROM "account" WHERE "providerId" <> 'credential'
						AND "userId" = ANY($3::text[])))) AS present`,
				[ids, path === "/sign-out", selected.rows.map((row) => row.userId)],
			);
			if (linked.rows[0]?.present) return null;
			await client.query('DELETE FROM "session" WHERE id = ANY($1::text[])', [
				ids,
			]);
			for (const row of selected.rows)
				await record(
					client,
					"session.deleted",
					"success",
					path,
					row.userId,
					row.id,
				);
			return ids;
		});
	}

	async function record(
		client: PoolClient,
		type: string,
		outcome: "success" | "failure",
		path: string,
		userId?: string,
		targetId?: string,
	) {
		await client.query(
			`INSERT INTO "allauthEvent" (id, type, outcome, "actorId", "userId", "targetId", "createdAt", metadata)
			 VALUES ($1, $2, $3, $4, $4, $5, statement_timestamp(), jsonb_build_object('path', $6::text))`,
			[
				crypto.randomUUID(),
				type,
				outcome,
				userId ?? null,
				targetId ?? null,
				path,
			],
		);
	}

	async function passwordPolicySupported(client: PoolClient, userId?: string) {
		const result = await client.query<{ unsupported: boolean }>(
			`SELECT (EXISTS (SELECT 1 FROM "allauthSecurityPolicy")
				OR EXISTS (SELECT 1 FROM "allauthSecurityRule" WHERE "expiresAt" IS NULL OR "expiresAt" > statement_timestamp())
				OR EXISTS (SELECT 1 FROM "allauthSecurityCounter" WHERE "blockedUntil" > statement_timestamp())
				OR EXISTS (SELECT 1 FROM "allauthKnownDevice" WHERE "userId" = $1)) AS unsupported`,
			[userId ?? null],
		);
		return result.rows[0]?.unsupported === false;
	}

	return {
		credential,
		createSession,
		list,
		passwordPolicySupported,
		record,
		refresh,
		revoke,
		session,
		transaction,
	};
}
