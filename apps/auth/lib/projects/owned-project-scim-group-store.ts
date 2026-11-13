import { randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { OwnedProjectSCIMConnection } from "./owned-project-scim-authority";
import { ownedSCIMScopedKey } from "./owned-project-scim-authority";
import {
	lockOwnedSCIMOrganization,
	reconcileOwnedSCIMOrganizationProjection,
} from "./owned-project-scim-directory-writes";
import { ownedSCIMError } from "./owned-project-scim-discovery";
import type { OwnedSCIMGroupInput } from "./owned-project-scim-group-input";
import {
	ownedSCIMGroupMemberLimit,
	patchOwnedSCIMGroup,
} from "./owned-project-scim-group-input";
import type { parseOwnedSCIMPatch } from "./owned-project-scim-mutation";
import type { OwnedSCIMGroupRow } from "./owned-project-scim-resources";

type Client = Pick<PoolClient, "query">;
type GroupMember = { id: string; userId: string };
const domainConflict = () =>
	ownedSCIMError(
		409,
		"The connection provisioningDomainId changed after resources were created",
	);
const missing = () => ownedSCIMError(404, "SCIM Group not found");

function groupKeys(connectionId: string, group: OwnedSCIMGroupInput) {
	return {
		name: ownedSCIMScopedKey([
			"scim-group-display-name",
			connectionId,
			group.displayName.toLowerCase(),
		]),
		external: group.externalId
			? ownedSCIMScopedKey([
					"scim-group-external-id",
					connectionId,
					group.externalId,
				])
			: null,
	};
}

async function assertKeys(
	client: Client,
	connectionId: string,
	keys: ReturnType<typeof groupKeys>,
	id = "",
) {
	const { rows } = await client.query<{
		nameConflict: boolean;
		externalConflict: boolean;
	}>(
		`SELECT EXISTS (SELECT 1 FROM "scimGroup" WHERE "connectionId" = $1 AND "displayNameKey" = $2 AND id <> $4) AS "nameConflict",
		        EXISTS (SELECT 1 FROM "scimGroup" WHERE "connectionId" = $1 AND "externalIdKey" = $3 AND id <> $4) AS "externalConflict"`,
		[connectionId, keys.name, keys.external, id],
	);
	if (rows[0]?.nameConflict)
		throw ownedSCIMError(
			409,
			"SCIM Group displayName already exists",
			"uniqueness",
		);
	if (rows[0]?.externalConflict)
		throw ownedSCIMError(
			409,
			"SCIM Group externalId already exists",
			"uniqueness",
		);
}

/** Locks the same subjects used by User deletion, SSO identity resolution, and projection. */
async function lockSubjects(
	client: Client,
	connection: OwnedProjectSCIMConnection,
	targets: readonly string[],
	validate: readonly string[],
) {
	const ids = [...new Set([...targets, ...validate])];
	const lookup = () =>
		client.query<GroupMember>(
			`SELECT id, "userId" FROM "scimUser" WHERE "connectionId" = $1 AND "provisioningDomainId" = $2 AND id = ANY($3::text[])`,
			[connection.connectionId, connection.provisioningDomainId, ids],
		);
	if (ids.length === 0) return new Map<string, string>();
	const observed = (await lookup()).rows;
	const sourceIds = new Set(observed.map((member) => member.id));
	if (validate.some((id) => !sourceIds.has(id)))
		throw ownedSCIMError(
			400,
			"One or more Group members are invalid",
			"invalidValue",
		);
	const userIds = [...new Set(observed.map((member) => member.userId))];
	const locked = await client.query<{ userId: string }>(
		`SELECT "userId" FROM "scimSubject" WHERE "userId" = ANY($1::text[]) ORDER BY "userId" FOR UPDATE`,
		[userIds],
	);
	if (locked.rows.length !== userIds.length)
		throw ownedSCIMError(
			500,
			"A SCIM User selected for projection has no subject aggregate",
		);
	await client.query(
		`UPDATE "scimSubject" SET revision = revision + 1, "updatedAt" = statement_timestamp() WHERE "userId" = ANY($1::text[])`,
		[userIds],
	);
	const latest = new Map(
		(await lookup()).rows.map((member) => [member.id, member.userId]),
	);
	if (observed.some((member) => latest.get(member.id) !== member.userId))
		throw ownedSCIMError(
			409,
			"The SCIM User changed concurrently; retry the request",
		);
	return latest;
}

async function projectAffected(
	client: Client,
	connection: OwnedProjectSCIMConnection,
	organizationId: string,
	sources: ReadonlyMap<string, string>,
	affected: readonly string[],
) {
	const userIds = [
		...new Set(
			affected.flatMap((id) => {
				const userId = sources.get(id);
				return userId ? [userId] : [];
			}),
		),
	].sort();
	if (!userIds.length) return;
	const { rows } = await client.query<{ userId: string }>(
		`SELECT DISTINCT u."userId" FROM "scimUser" u
		WHERE u."userId" = ANY($1::text[]) AND u."provisioningDomainId" = $2 AND u.active
		AND NOT EXISTS (SELECT 1 FROM "scimConnectionBinding" b WHERE b."connectionId" = u."connectionId" AND b."decommissionStatus" <> 'active')`,
		[userIds, connection.provisioningDomainId],
	);
	const active = new Set(rows.map((row) => row.userId));
	for (const userId of userIds)
		await reconcileOwnedSCIMOrganizationProjection(
			client,
			userId,
			organizationId,
			connection.provisioningDomainId,
			active.has(userId),
		);
}

/** Writes connection-owned Group rows and membership deltas in the caller's fenced transaction. */
export async function ownedSCIMGroupWriter(
	client: Client,
	connection: OwnedProjectSCIMConnection,
) {
	const connectionId = connection.connectionId;
	const domain = connection.provisioningDomainId;
	const organizationId = await lockOwnedSCIMOrganization(client, domain);
	async function lock(id: string) {
		const group = (
			await client.query<OwnedSCIMGroupRow>(
				`SELECT * FROM "scimGroup" WHERE id = $1 AND "connectionId" = $2 FOR UPDATE`,
				[id, connectionId],
			)
		).rows[0];
		if (!group) throw missing();
		if (group.provisioningDomainId !== domain) throw domainConflict();
		return group;
	}
	async function members(groupId: string) {
		const { rows } = await client.query<{
			connectionId: string;
			scimUserId: string;
		}>(
			`SELECT "connectionId", "scimUserId" FROM "scimGroupMember" WHERE "groupId" = $1 ORDER BY "createdAt" ASC LIMIT $2`,
			[groupId, ownedSCIMGroupMemberLimit + 1],
		);
		if (rows.length > ownedSCIMGroupMemberLimit)
			throw ownedSCIMError(
				500,
				"Persisted SCIM Group membership exceeds the server limit",
			);
		if (rows.some((row) => row.connectionId !== connectionId))
			throw domainConflict();
		return rows.map((row) => row.scimUserId);
	}
	async function writeEdges(
		groupId: string,
		added: readonly string[],
		removed: readonly string[],
	) {
		if (removed.length)
			await client.query(
				`DELETE FROM "scimGroupMember" WHERE "connectionId" = $1 AND "groupId" = $2 AND "scimUserId" = ANY($3::text[])`,
				[connectionId, groupId, removed],
			);
		if (added.length)
			await client.query(
				`INSERT INTO "scimGroupMember" (id, "connectionId", "groupId", "scimUserId", "membershipKey", "createdAt")
			SELECT input.id, $1, $2, input."userId", input.key, statement_timestamp()
			FROM unnest($3::text[], $4::text[], $5::text[]) AS input(id, "userId", key)`,
				[
					connectionId,
					groupId,
					added.map(() => randomUUID()),
					added,
					added.map((id) =>
						ownedSCIMScopedKey([
							"scim-group-member",
							connectionId,
							groupId,
							id,
						]),
					),
				],
			);
	}

	async function create(input: OwnedSCIMGroupInput) {
		const mismatched = await client.query(
			`SELECT 1 FROM "scimGroup" WHERE "connectionId" = $1 AND "provisioningDomainId" <> $2 LIMIT 1`,
			[connectionId, domain],
		);
		if (mismatched.rowCount) throw domainConflict();
		const keys = groupKeys(connectionId, input);
		await assertKeys(client, connectionId, keys);
		const id = randomUUID();
		const order = `${Date.now().toString().padStart(15, "0")}:${randomBytes(8).toString("hex")}`;
		const group = (
			await client.query<OwnedSCIMGroupRow>(
				`INSERT INTO "scimGroup" (id, "connectionId", "provisioningDomainId", revision, "displayName", "displayNameKey", "externalId", "externalIdKey", "orderKey", "createdAt", "updatedAt")
			VALUES ($1, $2, $3, 0, $4, $5, $6, $7, $8, statement_timestamp(), statement_timestamp()) RETURNING *`,
				[
					id,
					connectionId,
					domain,
					input.displayName,
					keys.name,
					input.externalId,
					keys.external,
					order,
				],
			)
		).rows[0]!;
		const sources = await lockSubjects(
			client,
			connection,
			input.memberIds,
			input.memberIds,
		);
		await writeEdges(id, input.memberIds, []);
		await projectAffected(
			client,
			connection,
			organizationId,
			sources,
			input.memberIds,
		);
		return group;
	}

	async function update(
		id: string,
		replacement: OwnedSCIMGroupInput | undefined,
		operations: ReturnType<typeof parseOwnedSCIMPatch> | undefined,
	) {
		const group = await lock(id);
		const current = await members(id);
		const input = operations
			? patchOwnedSCIMGroup(group, current, operations)
			: {
					...replacement!,
					validateIds: replacement!.memberIds,
					targets: [...new Set([...current, ...replacement!.memberIds])],
				};
		const existing = new Set(current);
		const desired = new Set(input.memberIds);
		const added = input.memberIds.filter((member) => !existing.has(member));
		const removed = current.filter((member) => !desired.has(member));
		const keys = groupKeys(connectionId, input);
		await assertKeys(client, connectionId, keys, id);
		const sources = await lockSubjects(
			client,
			connection,
			input.targets,
			input.validateIds,
		);
		const metadataChanged =
			group.displayName !== input.displayName ||
			group.externalId !== input.externalId;
		const affected =
			operations && !metadataChanged
				? [...added, ...removed]
				: [...input.memberIds, ...removed];
		await writeEdges(id, added, removed);
		const changed =
			!operations || metadataChanged || added.length > 0 || removed.length > 0;
		const updated = (
			await client.query<OwnedSCIMGroupRow>(
				`UPDATE "scimGroup" SET revision = revision + 1,
			"displayName" = $4, "displayNameKey" = $5, "externalId" = $6, "externalIdKey" = $7,
			"updatedAt" = CASE WHEN $8 THEN statement_timestamp() ELSE "updatedAt" END
			WHERE id = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3 RETURNING *`,
				[
					id,
					connectionId,
					domain,
					input.displayName,
					keys.name,
					input.externalId,
					keys.external,
					changed,
				],
			)
		).rows[0];
		if (!updated) throw missing();
		await projectAffected(
			client,
			connection,
			organizationId,
			sources,
			affected,
		);
		return updated;
	}

	async function remove(id: string) {
		await lock(id);
		const current = await members(id);
		const sources = await lockSubjects(client, connection, current, []);
		await client.query(
			`DELETE FROM "scimGroup" WHERE id = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3`,
			[id, connectionId, domain],
		);
		await projectAffected(client, connection, organizationId, sources, current);
	}

	return { create, update, remove };
}
