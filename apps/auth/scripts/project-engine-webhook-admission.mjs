const commonSelectors = /** @type {const} */ (["api-key.*", "session.created"]);
const optionalMfaSelectors = /** @type {const} */ ([
	"mfa.*",
	...commonSelectors,
	"passkey.*",
]);

/** @typedef {Pick<import("pg").PoolClient, "query">} Database */
/** @typedef {{mfaMode: "optional" | "required", requireEmailVerification: boolean}} WebhookPolicy */

/** @param {string} schemaName */
function checkedSchema(schemaName) {
	if (!/^allauth_project_[a-f0-9]{32}$/.test(schemaName))
		throw new Error("Invalid project storage namespace.");
	return schemaName;
}

/** @param {WebhookPolicy} policy */
export function ownedWebhookSelectors(policy) {
	return policy.mfaMode === "optional" && !policy.requireEmailVerification
		? optionalMfaSelectors
		: commonSelectors;
}

/** @param {readonly string[]} selectors */
export function ownedWebhookUsesPolicyGuard(selectors) {
	return optionalMfaSelectors.some((selector) => selectors.includes(selector));
}

/** Fail closed for ambiguous credential records and inconsistent live sessions.
 * @param {Database} database
 * @param {string} schemaName
 */
export async function ownedWebhookAccountsSupported(database, schemaName) {
	const schema = checkedSchema(schemaName);
	const { rows } = await database.query(
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

/** @param {Database} database
 * @param {string} schemaName
 * @param {WebhookPolicy} policy
 * @returns {Promise<{ configured: boolean, unsupported: boolean } | undefined>}
 */
export async function storedProjectWebhookSelectors(
	database,
	schemaName,
	policy,
) {
	const schema = checkedSchema(schemaName);
	const {
		rows: [configuration],
	} = await database.query(
		`SELECT EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint") AS configured,
			EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint"
				WHERE jsonb_typeof("eventTypes") IS DISTINCT FROM 'array'
				OR "eventTypes" = '[]'::jsonb OR NOT ("eventTypes" <@ $1::jsonb)) AS unsupported`,
		[JSON.stringify(ownedWebhookSelectors(policy))],
	);
	return configuration;
}

function unavailable() {
	return new Error(
		"This development project's configured webhooks are outside the candidate scope.",
	);
}

/** @param {Database} database
 * @param {string} schemaName
 * @param {WebhookPolicy} policy
 */
export async function assertOwnedProjectWebhookAdmission(
	database,
	schemaName,
	policy,
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
		throw unavailable();
}

/** Recheck the stored policy and eligibility in the transaction that admits the writer.
 * @param {Database} database
 * @param {string} projectId
 * @param {string} schemaName
 */
export async function verifyProjectWebhookActivation(
	database,
	projectId,
	schemaName,
) {
	const { rows } = await database.query(
		`SELECT policy FROM public."allauthAuthConfiguration" WHERE id=$1`,
		[projectId],
	);
	const policy = rows.length
		? rows[0].policy
		: { mfaMode: "optional", requireEmailVerification: true };
	if (
		!policy ||
		(policy.mfaMode !== "optional" && policy.mfaMode !== "required") ||
		typeof policy.requireEmailVerification !== "boolean"
	)
		throw unavailable();
	await assertOwnedProjectWebhookAdmission(database, schemaName, policy);
}
