import { createRemoteJWKSet, customFetch } from "jose";
import type { Pool, PoolClient } from "pg";
import type { ProjectAppleProvider } from "../project-providers/apple";
import type { AppleAccountGrant } from "../project-providers/apple-grant-revocation";
import {
	appleRevocationMessage,
	maximumAppleAccounts,
	revokeAppleAccountGrants,
} from "../project-providers/apple-grant-revocation";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord } from "./legacy-mfa-record";
import type { AccountDeletionFence } from "./owned-project-account-deletion";
import { accountLinkError } from "./owned-project-account-links";
import { checkedProjectSchema } from "./validation";

interface SavedAppleGrant extends AppleAccountGrant {
	id: string;
}

/** A project deletion uses only the owning realm's saved Apple grants and keys. */
export function createOwnedProjectAppleDeletion({
	database,
	schemaName,
	keys,
	configured,
	request,
}: {
	database: Pool;
	schemaName: string;
	keys: LegacyMfaKeys;
	configured?: ProjectAppleProvider;
	request?: typeof fetch;
}) {
	const schema = checkedProjectSchema(schemaName);
	const key = createRemoteJWKSet(
		new URL("https://appleid.apple.com/auth/keys"),
		request ? { [customFetch]: request } : undefined,
	);

	const accounts = (
		client: Pick<PoolClient, "query">,
		userId: string,
		lock = false,
	) =>
		client.query<SavedAppleGrant>(
			`SELECT id,"userId","providerId","accountId","idToken","refreshToken"
			 FROM "${schema}"."account" WHERE "userId"=$1 AND "providerId"='apple'
			 ORDER BY id LIMIT $2${lock ? " FOR UPDATE" : ""}`,
			[userId, maximumAppleAccounts + 1],
		);

	return async (userId: string): Promise<AccountDeletionFence | Response> => {
		const saved = (await accounts(database, userId)).rows;
		const error = await revokeAppleAccountGrants({
			accounts: saved,
			userId,
			configured,
			key,
			readToken: (value) =>
				value.startsWith("$ba$") || /^(?:[0-9a-f]{2})+$/i.test(value)
					? openLegacyMfaRecord(value, keys)
					: value,
			request,
		});
		if (error) return accountLinkError(503, error, appleRevocationMessage);

		// A callback can rotate a grant while Apple is being contacted. Verify the
		// snapshot under the deletion transaction's user lock before erasure.
		return {
			async verify(client) {
				const current = (await accounts(client, userId, true)).rows;
				return JSON.stringify(saved) === JSON.stringify(current);
			},
		};
	};
}
