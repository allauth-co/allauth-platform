import type { Pool } from "pg";
import { readOwnedAgentPublicKey } from "./owned-project-agent-enrollment";
import { parseOwnedAgentStoredJSON } from "./owned-project-agent-grants";
import { checkedProjectSchema } from "./validation";

function unsupported() {
	return new Error(
		"This development project has stored Agent Auth outside the candidate scope.",
	);
}

/** Validate the selected realm's stored empty-capability Agent configuration without changing it. */
export async function assertOwnedProjectAgentAdmission(
	database: Pool,
	schemaName: string,
) {
	const schema = checkedProjectSchema(schemaName);
	const client = await database.connect();
	try {
		await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
		const {
			rows: [state],
		} = await client.query<{ incompatible: boolean }>(`
		 SELECT (
		  EXISTS (SELECT 1 FROM "${schema}"."agentCapabilityGrant") OR
		  EXISTS (
		   SELECT 1 FROM "${schema}"."agentHost" h WHERE
		    length(h.id)>512 OR h.id !~ '^[A-Za-z0-9_-]+$' OR h."userId" IS NULL OR h."jwksUrl" IS NOT NULL OR
		    h.status NOT IN ('active','pending_enrollment','revoked','rejected') OR
		    (h.status='active' AND nullif(h."publicKey",'') IS NULL) OR
		    (h.status='revoked' AND (h."publicKey" IS DISTINCT FROM '' OR h.kid IS NOT NULL)) OR
		    (h.status='pending_enrollment' AND (h."enrollmentTokenHash" IS NULL OR h."enrollmentTokenExpiresAt" IS NULL)) OR
		    ((h."enrollmentTokenHash" IS NULL) <> (h."enrollmentTokenExpiresAt" IS NULL)) OR
		    (h."enrollmentTokenHash" IS NOT NULL AND h."enrollmentTokenHash" !~ '^[A-Za-z0-9_-]{43}$') OR
		    EXISTS (SELECT 1 FROM "${schema}"."agentHost" other WHERE other.id<>h.id AND
		     (other.kid=h.id OR h.kid=other.id OR nullif(h.kid,'')=other.kid OR h."enrollmentTokenHash"=other."enrollmentTokenHash"))
		  ) OR
		  EXISTS (
		   SELECT 1 FROM "${schema}"."agent" a JOIN "${schema}"."agentHost" h ON h.id=a."hostId" WHERE
		    length(a.id)>512 OR a.id='host' OR a.id !~ '^[A-Za-z0-9_-]+$' OR a.mode<>'delegated' OR a."jwksUrl" IS NOT NULL OR
		    a.status NOT IN ('active','expired','pending','revoked','rejected') OR
		    (a."userId" IS NOT NULL AND a."userId" IS DISTINCT FROM h."userId") OR
		    (a.status IN ('active','expired') AND a."userId" IS NULL) OR
		    (a.status IN ('active','expired','pending') AND a."publicKey"='') OR
		    (a.status='revoked' AND (a."publicKey"<>'' OR a.kid IS NOT NULL)) OR
		    (h.status<>'active' AND a.status IN ('active','expired','pending'))
		  ) OR
		  EXISTS (
		   SELECT 1 FROM "${schema}"."approvalRequest" r
		   LEFT JOIN "${schema}"."agentHost" h ON h.id=r."hostId"
		   LEFT JOIN "${schema}"."agent" a ON a.id=r."agentId" WHERE
		    h.id IS NULL OR (a.id IS NOT NULL AND a."hostId" IS DISTINCT FROM h.id) OR
		    r.method NOT IN ('device_authorization','ciba') OR r.status NOT IN ('pending','approved','denied','expired') OR
		    nullif(btrim(r.capabilities),'') IS NOT NULL OR r.interval<>5 OR
		    r."clientNotificationToken" IS NOT NULL OR r."clientNotificationEndpoint" IS NOT NULL OR
		    (r."userId" IS NOT NULL AND r."userId" IS DISTINCT FROM h."userId") OR
		    (r.method='ciba' AND (r."userId" IS NULL OR r."deliveryMode" IS DISTINCT FROM 'poll' OR r."userCodeHash" IS NOT NULL)) OR
		    (r.method='device_authorization' AND (a.id IS NULL OR r."deliveryMode" IS NOT NULL OR
		     r."userCodeHash" IS NULL OR r."userCodeHash" !~ '^[A-Za-z0-9_-]{43}$'))
		  )
		 ) AS incompatible`);
		if (!state || state.incompatible) throw unsupported();
		const { rows } = await client.query<{
			publicKey: string | null;
			kid: string | null;
			budget: string | null;
			metadata: string | null;
		}>(`
		 SELECT "publicKey",kid,"defaultCapabilities" AS budget,NULL::text AS metadata FROM "${schema}"."agentHost"
		 UNION ALL
		 SELECT "publicKey",kid,NULL::text AS budget,metadata FROM "${schema}"."agent"`);
		for (const { publicKey, kid, budget, metadata } of rows) {
			if (budget !== null) {
				const parsed = parseOwnedAgentStoredJSON(budget);
				const values =
					typeof parsed === "string"
						? parseOwnedAgentStoredJSON(parsed)
						: parsed;
				if (!Array.isArray(values) || values.length !== 0) throw unsupported();
			}
			if (metadata !== null) {
				const parsed = parseOwnedAgentStoredJSON(metadata);
				if (
					parsed !== null &&
					(typeof parsed !== "object" || Array.isArray(parsed))
				)
					throw unsupported();
			}
			if (!publicKey) {
				if (kid !== null) throw unsupported();
				continue;
			}
			const parsed = await readOwnedAgentPublicKey(
				parseOwnedAgentStoredJSON(publicKey),
			);
			if (parsed instanceof Response || parsed.kid !== kid) throw unsupported();
		}
		await client.query("COMMIT");
	} catch (error) {
		await client.query("ROLLBACK");
		throw error;
	} finally {
		client.release();
	}
}
