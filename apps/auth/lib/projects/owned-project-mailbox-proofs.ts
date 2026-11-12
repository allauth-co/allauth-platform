import type { PoolClient } from "pg";

export function projectEmailChangeGenerationKey(userId: string) {
	return `allauth-change-email-generation:${userId}`;
}

/** Retire proofs issued for the former mailbox while holding the user's row lock. */
export async function invalidateProjectMailboxProofs(
	client: PoolClient,
	userId: string,
) {
	await client.query(
		`DELETE FROM "verification" WHERE value=$1
		 AND (starts_with(identifier, 'reset-password:') OR starts_with(identifier, 'delete-account-'))`,
		[userId],
	);
	await client.query(
		`INSERT INTO "verification"(id,identifier,value,"expiresAt") VALUES ($1,$1,$2,statement_timestamp() + interval '1 hour')
		 ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, "expiresAt"=EXCLUDED."expiresAt", "updatedAt"=statement_timestamp()`,
		[projectEmailChangeGenerationKey(userId), String(Date.now())],
	);
}
