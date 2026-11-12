import type { AuthPolicy } from "../auth-policy/policy";
import type { webhookEventTypes } from "../control/webhook-contract";
import { checkedProjectSchema } from "./validation";

const supportedSelectors = ["mfa.*", "api-key.*"] as const;
const apiKeySelectors = ["api-key.*"] as const;

type Queryable = {
	query<Row extends Record<string, unknown>>(
		query: string,
		values?: unknown[],
	): Promise<{ rows: Row[] }>;
};

export function ownedWebhookSelectors(
	policy: AuthPolicy,
): readonly (typeof webhookEventTypes)[number][] {
	return policy.mfaMode === "optional" && !policy.requireEmailVerification
		? supportedSelectors
		: apiKeySelectors;
}

export function ownedWebhookUsesPolicyGuard(selectors: readonly string[]) {
	return supportedSelectors.some((selector) => selectors.includes(selector));
}

/** Fail closed for ambiguous credential records and inconsistent live sessions. */
export async function ownedWebhookAccountsSupported(
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

export async function storedProjectWebhookSelectors(
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
			EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint"
				WHERE jsonb_typeof("eventTypes") IS DISTINCT FROM 'array'
				OR "eventTypes" = '[]'::jsonb OR NOT ("eventTypes" <@ $1::jsonb)) AS unsupported`,
		[JSON.stringify(ownedWebhookSelectors(policy))],
	);
	return configuration;
}

/** Persisted rows must use supported selectors for the current policy. */
export async function assertOwnedProjectWebhookAdmission(
	database: Queryable,
	schemaName: string,
	policy: AuthPolicy,
) {
	const configuration = await storedProjectWebhookSelectors(
		database,
		schemaName,
		policy,
	);
	if (
		!configuration ||
		(configuration.configured &&
			(configuration.unsupported ||
				!(await ownedWebhookAccountsSupported(database, schemaName))))
	)
		throw new Error(
			"This development project's configured webhooks are outside the candidate scope.",
		);
}
