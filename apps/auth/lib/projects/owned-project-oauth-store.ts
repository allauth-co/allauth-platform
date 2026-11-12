import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { sealLegacyMfaRecord } from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { checkedProjectSchema } from "./validation";

export const oauthStateAge = 600;
const providerId = z.enum(["allauth", "google"]);
export type ProjectOAuthProvider = z.infer<typeof providerId>;
const stateData = z.object({
	callbackURL: z.string().max(2048),
	newUserURL: z.string().max(2048).optional(),
	errorURL: z.string().max(2048).optional(),
	codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
	expiresAt: z.number().int().positive(),
	oauthState: z.string().optional(),
	idTokenNonce: z.string().min(1).max(128).optional(),
	requestSignUp: z.boolean().optional(),
	link: z
		.object({
			userId: z.union([z.string(), z.number().int()]).transform(String),
			email: z.string().max(320),
		})
		.optional(),
	serverContext: z
		.object({
			ownedProjectProvider: providerId.optional(),
			linkedSessionId: z.string().min(1).max(512).optional(),
		})
		.optional(),
});
export type ProjectOAuthState = z.infer<typeof stateData>;
type LinkAuthority = NonNullable<ProjectOAuthState["link"]> & {
	sessionToken: string;
};

export type ProjectOAuthIdentity = {
	provider: ProjectOAuthProvider;
	subject: string;
	email: string;
	emailVerified: boolean;
	name: string;
	image?: string;
	accessToken: string;
	refreshToken?: string;
	idToken: string;
	accessTokenExpiresAt?: Date;
	refreshTokenExpiresAt?: Date;
	scope?: string;
};

/** State and account bindings remain inside the selected immutable project's PostgreSQL schema. */
export function createProjectOAuthStore(
	database: Pool,
	schemaName: string,
	keys: LegacyMfaKeys,
) {
	const schema = checkedProjectSchema(schemaName);
	const realm = createProjectEngineStore(database, schema);

	async function issue(
		state: string,
		value: ProjectOAuthState,
		client?: PoolClient,
	) {
		await (client ?? database).query(
			`INSERT INTO "${schema}"."verification" (id, identifier, value, "expiresAt")
			VALUES ($1, $2, $3, statement_timestamp() + $4::int * interval '1 second')`,
			[
				randomUUID(),
				`auth-state:${state}`,
				JSON.stringify(value),
				oauthStateAge,
			],
		);
	}

	async function consume(
		state: string,
		provider: ProjectOAuthProvider,
		sessionToken: string | null,
	) {
		return realm.transaction(async (client) => {
			const result = await client.query<{
				id: string;
				value: string;
				live: boolean;
			}>(
				`SELECT id, value, "expiresAt" > clock_timestamp() AS live FROM "${schema}"."verification"
				WHERE identifier = $1 ORDER BY id LIMIT 2 FOR UPDATE`,
				[`auth-state:${state}`],
			);
			if (result.rows.length !== 1 || !result.rows[0]?.live) return null;
			const row = result.rows[0];
			let raw: unknown;
			try {
				raw = JSON.parse(row.value);
			} catch {
				return null;
			}
			const data = stateData.safeParse(raw);
			if (
				!data.success ||
				data.data.expiresAt <= Date.now() ||
				(data.data.link && !sessionToken) ||
				(data.data.oauthState !== undefined &&
					data.data.oauthState !== state) ||
				(data.data.serverContext?.ownedProjectProvider &&
					data.data.serverContext.ownedProjectProvider !== provider)
			)
				return null;
			if (data.data.link) {
				const owner = await client.query<{ id: string }>(
					`SELECT id FROM "${schema}"."session" WHERE token = $1 AND "userId" = $2
					AND "expiresAt" > statement_timestamp() AND "impersonatedBy" IS NULL`,
					[sessionToken, data.data.link.userId],
				);
				if (
					owner.rowCount !== 1 ||
					(data.data.serverContext?.linkedSessionId &&
						owner.rows[0]?.id !== data.data.serverContext.linkedSessionId)
				)
					return null;
			}
			const consumed = await client.query(
				`DELETE FROM "${schema}"."verification" WHERE id = $1 AND "expiresAt" > statement_timestamp()`,
				[row.id],
			);
			return consumed.rowCount === 1 ? data.data : null;
		});
	}

	async function bind(
		client: PoolClient,
		identity: ProjectOAuthIdentity,
		policy: { signUpEnabled: boolean; requireEmailVerification: boolean },
		link?: LinkAuthority,
	) {
		// The legacy schema has no unique provider/subject constraint. Serialize this engine's writes to one identity.
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`${schema}\n${identity.provider}\n${identity.subject}`],
		);
		const binding = await client.query<{
			id: string;
			userId: string;
			scope: string | null;
		}>(
			`SELECT id, "userId", scope FROM "${schema}"."account" WHERE "providerId" = $1 AND "accountId" = $2 ORDER BY id LIMIT 2`,
			[identity.provider, identity.subject],
		);
		if (binding.rows.length > 1) return null;
		const account = binding.rows[0];
		if (
			link &&
			(!identity.emailVerified ||
				link.email.toLowerCase() !== identity.email ||
				(account && account.userId !== link.userId))
		)
			return null;
		let userId = link?.userId ?? account?.userId;
		let registered = false;
		if (!userId) {
			const existing = await client.query<{ id: string }>(
				`SELECT id FROM "${schema}"."user" WHERE email = $1`,
				[identity.email],
			);
			userId = existing.rows[0]?.id;
		}
		if (!userId) {
			if (
				!policy.signUpEnabled ||
				(policy.requireEmailVerification && !identity.emailVerified)
			)
				return null;
			const created = await client.query<{ id: string }>(
				`INSERT INTO "${schema}"."user" (id, email, name, image, "emailVerified", "twoFactorEnabled", "isAnonymous")
				VALUES ($1,$2,$3,$4,$5,FALSE,FALSE) ON CONFLICT (email) DO NOTHING RETURNING id`,
				[
					randomUUID(),
					identity.email,
					identity.name,
					identity.image ?? null,
					identity.emailVerified,
				],
			);
			userId = created.rows[0]?.id;
			registered = Boolean(userId);
			if (!userId) {
				const match = await client.query<{ id: string }>(
					`SELECT id FROM "${schema}"."user" WHERE email = $1`,
					[identity.email],
				);
				userId = match.rows[0]?.id;
			}
		}
		if (!userId) return null;
		let user = await realm.lockUser(client, userId);
		if (
			!user ||
			user.banned ||
			user.directoryDisabled ||
			user.directoryManaged ||
			user.isAnonymous
		)
			return null;
		if (
			link &&
			(user.email.toLowerCase() !== identity.email ||
				!(await realm.lockSession(client, link.sessionToken, user.id, false)))
		)
			return null;
		if (account) {
			const current = await client.query(
				`SELECT 1 FROM "${schema}"."account" WHERE id = $1 AND "userId" = $2 AND "providerId" = $3 AND "accountId" = $4 FOR UPDATE`,
				[account.id, user.id, identity.provider, identity.subject],
			);
			if (current.rowCount !== 1) return null;
			if (
				!link &&
				!user.emailVerified &&
				identity.emailVerified &&
				user.email === identity.email
			) {
				await client.query(
					`UPDATE "${schema}"."user" SET "emailVerified" = TRUE, "updatedAt" = statement_timestamp() WHERE id = $1`,
					[userId],
				);
				await realm.record(
					client,
					"user.updated",
					"success",
					`/callback/${identity.provider}`,
					user.id,
					user.id,
				);
				user = await realm.lockUser(client, userId);
				if (!user) return null;
			}
		} else if (
			!link &&
			!registered &&
			(user.email !== identity.email ||
				!user.emailVerified ||
				!identity.emailVerified)
		) {
			// Project account linking has no trusted-provider bypass. Both addresses must be verified.
			return null;
		}
		if (!link && policy.requireEmailVerification && !user.emailVerified)
			return null;
		const access = sealLegacyMfaRecord(identity.accessToken, keys);
		const refresh = identity.refreshToken
			? sealLegacyMfaRecord(identity.refreshToken, keys)
			: null;
		if (account) {
			const mergedScope =
				link && identity.scope
					? [
							...new Set([
								...(account.scope?.split(",") ?? []),
								...identity.scope.split(","),
							]),
						]
							.filter(Boolean)
							.join(",")
					: null;
			await client.query(
				`UPDATE "${schema}"."account" SET "accessToken" = $1, "refreshToken" = COALESCE($2, "refreshToken"),
				"idToken" = $3, "accessTokenExpiresAt" = COALESCE($4, "accessTokenExpiresAt"),
				"refreshTokenExpiresAt" = COALESCE($5, "refreshTokenExpiresAt"), scope = COALESCE($6, scope),
				"updatedAt" = statement_timestamp() WHERE id = $7`,
				[
					access,
					refresh,
					identity.idToken,
					identity.accessTokenExpiresAt ?? null,
					identity.refreshTokenExpiresAt ?? null,
					mergedScope,
					account.id,
				],
			);
		} else {
			const accountId = randomUUID();
			await client.query(
				`INSERT INTO "${schema}"."account" (id, "userId", "providerId", "accountId", "accessToken", "refreshToken", "idToken",
				"accessTokenExpiresAt", "refreshTokenExpiresAt", scope, "updatedAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,statement_timestamp())`,
				[
					accountId,
					user.id,
					identity.provider,
					identity.subject,
					access,
					refresh,
					identity.idToken,
					identity.accessTokenExpiresAt ?? null,
					identity.refreshTokenExpiresAt ?? null,
					identity.scope ?? null,
				],
			);
			if (registered)
				await realm.record(
					client,
					"user.created",
					"success",
					`/callback/${identity.provider}`,
					user.id,
					user.id,
				);
			await realm.record(
				client,
				"account.linked",
				"success",
				`/callback/${identity.provider}`,
				user.id,
				accountId,
			);
		}
		return { user, registered };
	}

	return { issue, consume, bind, transaction: realm.transaction };
}
