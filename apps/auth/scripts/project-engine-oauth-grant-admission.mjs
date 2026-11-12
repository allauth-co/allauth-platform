/** Check stored client grants without reading any client credentials.
 * @param {Pick<import("pg").PoolClient, "query">} database
 * @param {string} schemaName
 */
export async function assertProjectOAuthGrantAdmission(database, schemaName) {
	if (!/^allauth_project_[a-f0-9]{32}$/.test(schemaName))
		throw new Error("Invalid project storage namespace.");
	const {
		rows: [configuration],
	} = await database.query(
		`SELECT NOT EXISTS (
			SELECT 1 FROM "${schemaName}"."oauthClient" WHERE "grantTypes" IS NOT NULL AND (
				jsonb_typeof("grantTypes") <> 'array' OR NOT "grantTypes" <@
				'["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]'::jsonb
			)
		) AS supported`,
	);
	if (configuration?.supported !== true)
		throw new Error(
			"This development project's stored OAuth client grants are outside the candidate scope.",
		);
}
