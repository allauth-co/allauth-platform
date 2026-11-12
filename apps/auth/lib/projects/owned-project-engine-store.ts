import type { Pool, PoolClient } from "pg";
import type { ProjectBackchannelTarget } from "./owned-project-backchannel-logout";
import { checkedProjectSchema } from "./validation";

export interface ProjectUser {
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

export interface ProjectSession {
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

const commitEffects = new WeakMap<PoolClient, (() => void)[]>();

/** Mark an in-memory effect ready only after the transaction actually commits. */
export function afterOwnedProjectCommit(
	client: PoolClient,
	effect: () => void,
) {
	const effects = commitEffects.get(client);
	if (!effects)
		throw new Error("A project transaction is required for commit effects.");
	effects.push(effect);
}

/** All calls in a transaction, including database triggers, use the selected realm's schema. */
export function createProjectEngineStore(database: Pool, schemaName: string) {
	const schema = checkedProjectSchema(schemaName);

	async function transaction<T>(work: (client: PoolClient) => Promise<T>) {
		const client = await database.connect();
		let discardConnection = false;
		let result: T;
		const effects: (() => void)[] = [];
		commitEffects.set(client, effects);
		try {
			await client.query("BEGIN");
			await client.query(`SET LOCAL search_path TO "${schema}"`);
			result = await work(client);
			await client.query("COMMIT");
		} catch (error) {
			try {
				await client.query("ROLLBACK");
			} catch {
				discardConnection = true;
			}
			throw error;
		} finally {
			commitEffects.delete(client);
			client.release(discardConnection);
		}
		for (const effect of effects) effect();
		return result;
	}

	async function credential(
		value: string,
		client?: PoolClient,
		field: "email" | "username" = "email",
	) {
		const result = await (client ?? database).query<Credential>(
			`SELECT ${userFields}, a.password, EXISTS (
				SELECT 1 FROM "${schema}"."twoFactor" f WHERE f."userId" = u.id
			) AS "enrolledFactor"
			FROM "${schema}"."user" u
			JOIN "${schema}"."account" a ON a."userId" = u.id
			WHERE u.${field === "email" ? "email" : "username"} = $1 AND a."providerId" = 'credential' AND a."accountId" = u.id
			ORDER BY a.id LIMIT 2${client ? " FOR UPDATE OF u, a" : ""}`,
			[value],
		);
		return result.rows.length === 1 ? result.rows[0] : null;
	}

	async function lockUser(client: PoolClient, userId: string) {
		const result = await client.query<ProjectUser>(
			`SELECT ${userFields} FROM "${schema}"."user" u WHERE u.id = $1 FOR UPDATE OF u`,
			[userId],
		);
		return result.rows[0] ?? null;
	}

	async function lockSession(
		client: PoolClient,
		token: string,
		userId: string,
		fresh: boolean,
	) {
		const result = await client.query(
			`SELECT id FROM "${schema}"."session" WHERE token = $1 AND "userId" = $2
				AND "expiresAt" > statement_timestamp() AND "impersonatedBy" IS NULL
				AND (NOT $3::boolean OR "createdAt" > statement_timestamp() - interval '1 day') FOR UPDATE`,
			[token, userId, fresh],
		);
		return result.rowCount === 1;
	}

	async function session(
		token: string,
		refreshWindow: number,
		client?: PoolClient,
	) {
		const result = await (client ?? database).query<{
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
			activeOrganizationId?: string | null;
			activeTeamId?: string | null;
		},
	) {
		const result = await client.query<{ session: ProjectSession }>(
			`WITH inserted AS (INSERT INTO "session" (id, token, "userId", "createdAt", "updatedAt", "expiresAt", "ipAddress", "userAgent",
				"activeOrganizationId", "activeTeamId")
			 VALUES ($1, $2, $3, statement_timestamp(), statement_timestamp(),
				statement_timestamp() + $4::int * interval '1 second', $5, $6, $7, $8) RETURNING *)
			 SELECT row_to_json(s) AS session FROM (SELECT ${sessionFields} FROM inserted s) s`,
			[
				data.id,
				data.token,
				data.userId,
				data.expiresIn,
				data.ip,
				data.userAgent,
				data.activeOrganizationId ?? null,
				data.activeTeamId ?? null,
			],
		);
		return result.rows[0]!.session;
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
		canDeliverBackchannel = false,
		client?: PoolClient,
	) {
		async function remove(client: PoolClient) {
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
			if (!ids.length) return { ids, targets: [] };
			if (path === "/sign-out") {
				const upstream = await client.query(
					`SELECT 1 FROM "account" WHERE "providerId" NOT IN ('credential', 'allauth', 'google')
					 AND "userId" = ANY($1::text[]) LIMIT 1`,
					[selected.rows.map((row) => row.userId)],
				);
				if (upstream.rowCount) return null;
			}
			// Capture targets before session deletion clears the grant foreign keys.
			const { rows: targets } = await client.query<ProjectBackchannelTarget>(
				`SELECT s.id AS "sessionId", s."userId", c."clientId", c."backchannelLogoutUri" AS url
				 FROM (
					SELECT "sessionId", "clientId" FROM "oauthRefreshToken" WHERE "sessionId" = ANY($1::text[])
					UNION
					SELECT "sessionId", "clientId" FROM "oauthAccessToken" WHERE "sessionId" = ANY($1::text[])
				 ) affected
				 JOIN "session" s ON s.id = affected."sessionId"
				 JOIN "oauthClient" c ON c."clientId" = affected."clientId"
				 WHERE c.disabled IS DISTINCT FROM true AND NULLIF(c."backchannelLogoutUri", '') IS NOT NULL`,
				[ids],
			);
			if (targets.length && !canDeliverBackchannel) return null;

			// The session foreign key clears on deletion. Revoke the linked grants first,
			// retaining offline refresh authority as the native issuer does.
			await client.query(
				`UPDATE "oauthAccessToken" SET revoked = statement_timestamp()
				 WHERE "sessionId" = ANY($1::text[]) AND revoked IS NULL`,
				[ids],
			);
			await client.query(
				`UPDATE "oauthRefreshToken" SET revoked = statement_timestamp()
				 WHERE "sessionId" = ANY($1::text[]) AND revoked IS NULL
				   AND NOT (scopes ? 'offline_access')`,
				[ids],
			);
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
			return { ids, targets };
		}
		return client ? remove(client) : transaction(remove);
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

	return {
		credential,
		createSession,
		list,
		lockSession,
		lockUser,
		record,
		refresh,
		revoke,
		session,
		transaction,
	};
}
