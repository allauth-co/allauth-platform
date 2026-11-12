import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { passwordPolicyError } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { checkedProjectSchema } from "./validation";

type PasswordSafety = "allowed" | "breached" | "unavailable";
type PasswordResetResult =
	| { status: "reset" }
	| { status: "invalid-token" | "breached-password" | "unavailable" }
	| { status: "password-policy"; message: string };

interface PasswordResetOptions {
	database: Pool;
	schemaName: string;
	policy: AuthPolicy;
	/** Supply the realm's approved breached-password policy. The primitive has no HTTP entry point. */
	checkPasswordSafety(password: string): Promise<PasswordSafety>;
}

/** A transaction-only candidate for consuming legacy password reset links. */
export function createOwnedPasswordReset(options: PasswordResetOptions) {
	const schema = checkedProjectSchema(options.schemaName);
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEngineStore(options.database, schema);

	return async function consumePasswordReset(input: {
		token: string;
		newPassword: string;
	}): Promise<PasswordResetResult> {
		if (!policy.emailAndPasswordEnabled) return { status: "unavailable" };
		if (!/^[A-Za-z0-9]{24}$/.test(input.token))
			return { status: "invalid-token" };
		const error = passwordPolicyError(input.newPassword, policy.passwordPolicy);
		if (error) return { status: "password-policy", message: error };

		const identifier = `reset-password:${input.token}`;
		// Only a current token can trigger the breach check and password KDF.
		const verification = await options.database.query<{ value: string }>(
			`SELECT value FROM (
				SELECT value, "expiresAt" FROM "${schema}"."verification" WHERE identifier = $1
				ORDER BY "createdAt" DESC, id DESC LIMIT 1
			) v WHERE "expiresAt" > statement_timestamp()`,
			[identifier],
		);
		const userId = verification.rows[0]?.value;
		if (!userId) return { status: "invalid-token" };

		const safe = await options
			.checkPasswordSafety(input.newPassword)
			.catch(() => "unavailable" as const);
		if (safe === "breached") return { status: "breached-password" };
		if (safe !== "allowed") return { status: "unavailable" };
		const hashed = await clerkCompatiblePasswords.hash(input.newPassword);

		return store.transaction(async (client) => {
			// Serialize all reset links for this account before locking individual verification rows.
			const user = await client.query<{ id: string }>(
				`SELECT id FROM "user" WHERE id = $1 AND banned IS DISTINCT FROM true
					AND "directoryManaged" IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true
					AND "isAnonymous" IS DISTINCT FROM true FOR UPDATE`,
				[userId],
			);
			if (!user.rows[0]) return { status: "invalid-token" };
			const latest = await client.query<{ valid: boolean; value: string }>(
				`SELECT value, "expiresAt" > statement_timestamp() AS valid FROM "verification"
				WHERE identifier = $1 ORDER BY "createdAt" DESC, id DESC LIMIT 1 FOR UPDATE`,
				[identifier],
			);
			if (!latest.rows[0]?.valid || latest.rows[0].value !== userId)
				return { status: "invalid-token" };
			const accounts = await client.query<{ id: string; accountId: string }>(
				`SELECT id, "accountId" FROM "account" WHERE "userId" = $1 AND "providerId" = 'credential'
				ORDER BY id LIMIT 2 FOR UPDATE`,
				[userId],
			);
			if (
				accounts.rows.length > 1 ||
				(accounts.rows[0] && accounts.rows[0].accountId !== userId)
			)
				return { status: "unavailable" };

			await client.query(
				`DELETE FROM "verification" WHERE identifier = $1 OR (
					value = $2 AND (
						starts_with(identifier, 'reset-password:') OR starts_with(identifier, 'trust-device-')
						OR starts_with(identifier, '2fa-')
					)
				)`,
				[identifier, userId],
			);
			const account = accounts.rows[0];
			if (account) {
				await client.query(
					'UPDATE "account" SET password = $1, "updatedAt" = statement_timestamp() WHERE id = $2',
					[hashed, account.id],
				);
			} else {
				const accountId = randomUUID();
				await client.query(
					`INSERT INTO "account" (id, "userId", "accountId", "providerId", password, "updatedAt")
					VALUES ($1, $2, $2, 'credential', $3, statement_timestamp())`,
					[accountId, userId, hashed],
				);
				await store.record(
					client,
					"account.linked",
					"success",
					"/reset-password",
					userId,
					accountId,
				);
			}
			await client.query('DELETE FROM "oauthAccessToken" WHERE "userId" = $1', [
				userId,
			]);
			await client.query(
				'DELETE FROM "oauthRefreshToken" WHERE "userId" = $1',
				[userId],
			);
			const sessions = await client.query<{ id: string }>(
				'DELETE FROM "session" WHERE "userId" = $1 RETURNING id',
				[userId],
			);
			for (const session of sessions.rows)
				await store.record(
					client,
					"session.deleted",
					"success",
					"/reset-password",
					userId,
					session.id,
				);
			await client.query(
				`INSERT INTO "allauthAudit"(id, "actorId", action, "targetId", "createdAt")
				VALUES ($1, $2, 'password-reset', $2, statement_timestamp())`,
				[randomUUID(), userId],
			);
			await store.record(
				client,
				"password-reset",
				"success",
				"/reset-password",
				userId,
				userId,
			);
			await store.record(
				client,
				"user.password-reset",
				"success",
				"/reset-password",
				userId,
				userId,
			);
			return { status: "reset" };
		});
	};
}
