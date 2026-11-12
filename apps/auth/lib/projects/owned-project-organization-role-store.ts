import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

interface StoredOrganizationRole {
	id: string;
	organizationId: string;
	role: string;
	permission: string;
	createdAt: Date;
	updatedAt: Date | null;
}

const projection =
	'id, "organizationId", role, permission, "createdAt", "updatedAt"';
// Match JavaScript trim() used for native role references, including older spaced comma tokens.
const roleWhitespace =
	"\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff";
const actionable = `status = 'pending' AND "expiresAt" > statement_timestamp()`;

/** Operate only inside the selected project transaction and its organization scope. */
export function projectOrganizationRoleStore(client: PoolClient) {
	async function list(organizationId: string, lock: boolean) {
		const result = await client.query<StoredOrganizationRole>(
			`SELECT ${projection} FROM "organizationRole" WHERE "organizationId"=$1 ORDER BY id${lock ? " FOR SHARE" : ""}`,
			[organizationId],
		);
		return result.rows;
	}

	async function insert(
		organizationId: string,
		role: string,
		permission: string,
	) {
		const result = await client.query<StoredOrganizationRole>(
			`INSERT INTO "organizationRole" (id,"organizationId",role,permission,"createdAt")
			 VALUES ($1,$2,$3,$4,statement_timestamp()) RETURNING ${projection}`,
			[randomUUID(), organizationId, role, permission],
		);
		return result.rows[0]!;
	}

	async function update(
		current: StoredOrganizationRole,
		role: string,
		permission: string,
	) {
		const result = await client.query(
			`UPDATE "organizationRole" SET role=$3,permission=$4,"updatedAt"=statement_timestamp() WHERE id=$1 AND "organizationId"=$2`,
			[current.id, current.organizationId, role, permission],
		);
		if (result.rowCount !== 1)
			throw new Error("Organization role changed during the update.");
	}

	async function remove(current: StoredOrganizationRole) {
		const result = await client.query(
			`DELETE FROM "organizationRole" WHERE id=$1 AND "organizationId"=$2`,
			[current.id, current.organizationId],
		);
		if (result.rowCount !== 1)
			throw new Error("Organization role changed during deletion.");
	}

	async function references(organizationId: string, role: string) {
		const result = await client.query<{
			members: boolean;
			invitations: boolean;
		}>(
			`SELECT EXISTS (SELECT 1 FROM "member" m WHERE m."organizationId"=$1 AND
			 EXISTS (SELECT 1 FROM unnest(string_to_array(m.role, ',')) AS p(part) WHERE p.part=$2 OR btrim(p.part,$3)=$2)) AS members,
			 EXISTS (SELECT 1 FROM "invitation" i WHERE i."organizationId"=$1 AND ${actionable} AND
			 EXISTS (SELECT 1 FROM unnest(string_to_array(i.role, ',')) AS p(part) WHERE p.part=$2 OR btrim(p.part,$3)=$2)) AS invitations`,
			[organizationId, role, roleWhitespace],
		);
		return result.rows[0]!;
	}

	async function renameReferences(
		organizationId: string,
		oldRole: string,
		newRole: string,
	) {
		// Preserve token order and whitespace so the rename cannot change how an existing token is evaluated.
		for (const table of ["member", "invitation"] as const) {
			await client.query(
				`UPDATE "${table}" AS scoped SET role=(
				 SELECT string_agg(CASE WHEN p.part=$2 THEN $3 WHEN btrim(p.part,$4)=$2 THEN
				   left(p.part,length(p.part)-length(ltrim(p.part,$4))) || $3 || right(p.part,length(p.part)-length(rtrim(p.part,$4)))
				   ELSE p.part END, ',' ORDER BY p.ordinal)
				 FROM unnest(string_to_array(scoped.role, ',')) WITH ORDINALITY AS p(part,ordinal)
				 ) WHERE scoped."organizationId"=$1 ${table === "invitation" ? `AND ${actionable}` : ""}
				 AND EXISTS (SELECT 1 FROM unnest(string_to_array(scoped.role, ',')) AS p(part) WHERE p.part=$2 OR btrim(p.part,$4)=$2)`,
				[organizationId, oldRole, newRole, roleWhitespace],
			);
		}
	}

	return { list, insert, update, remove, references, renameReferences };
}
