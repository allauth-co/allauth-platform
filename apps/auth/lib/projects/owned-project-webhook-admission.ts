import type { AuthPolicy } from "../auth-policy/policy";
import { checkedProjectSchema } from "./validation";

export const ownedMfaWebhookSubscription = "mfa.*";

type Queryable = {
	query<Row extends Record<string, unknown>>(
		query: string,
		values?: unknown[],
	): Promise<{ rows: Row[] }>;
};

/** Only optional MFA with email verification disabled has configured webhook parity. */
export function ownedMfaWebhookPolicy(policy: AuthPolicy) {
	return policy.mfaMode === "optional" && !policy.requireEmailVerification;
}

/** Fail closed for ambiguous credential records and inconsistent live sessions. */
export async function ownedMfaWebhookAccountsSupported(
	database: Queryable,
	schemaName: string,
) {
	const schema = checkedProjectSchema(schemaName);
	const { rows } = await database.query<{ supported: boolean }>(
		`SELECT NOT (
			EXISTS (SELECT 1 FROM "${schema}"."twoFactor" GROUP BY "userId" HAVING count(*) > 1) OR
			EXISTS (SELECT 1 FROM "${schema}"."account" WHERE "providerId"='credential' GROUP BY "userId" HAVING count(*) > 1) OR
			EXISTS (SELECT 1 FROM "${schema}"."session" s JOIN "${schema}"."user" u ON u.id=s."userId"
				WHERE s."expiresAt">statement_timestamp() AND (
					u.banned IS TRUE OR u."directoryDisabled" IS TRUE OR
					(u."isAnonymous" IS TRUE AND (u."directoryManaged" IS TRUE OR
						EXISTS (SELECT 1 FROM "${schema}"."scimUser" d WHERE d."userId"=u.id)))
				))
		) AS supported`,
	);
	return rows[0]?.supported === true;
}

/** Persisted rows must contain the exact selector admitted for this project policy. */
export async function assertOwnedProjectWebhookAdmission(
	database: Queryable,
	schemaName: string,
	policy: AuthPolicy,
) {
	const schema = checkedProjectSchema(schemaName);
	const {
		rows: [configuration],
	} = await database.query<{
		configured: boolean;
		unsupported: boolean;
	}>(
		`SELECT EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint") AS configured,
			EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint" WHERE "eventTypes" IS DISTINCT FROM $1::jsonb) AS unsupported`,
		[JSON.stringify([ownedMfaWebhookSubscription])],
	);
	if (
		!configuration ||
		(configuration.configured &&
			(configuration.unsupported ||
				!ownedMfaWebhookPolicy(policy) ||
				!(await ownedMfaWebhookAccountsSupported(database, schema))))
	)
		throw new Error(
			"This development project's configured webhooks are outside the candidate scope.",
		);
}
