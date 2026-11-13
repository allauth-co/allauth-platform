import type { Pool } from "pg";
import { assertStoredProjectAgentAdmission } from "../../scripts/project-agent-stored-admission.mjs";
import { checkedProjectSchema } from "./validation";

/** Read Agent admission state from one snapshot when building the candidate. */
export async function assertOwnedProjectAgentAdmission(
	database: Pool,
	schemaName: string,
) {
	const schema = checkedProjectSchema(schemaName);
	const client = await database.connect();
	try {
		await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
		await assertStoredProjectAgentAdmission(client, schema);
		await client.query("COMMIT");
	} catch (error) {
		await client.query("ROLLBACK");
		throw error;
	} finally {
		client.release();
	}
}
