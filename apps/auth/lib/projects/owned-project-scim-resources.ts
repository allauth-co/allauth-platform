import type { PoolClient } from "pg";
import type { OwnedProjectSCIMConnection } from "./owned-project-scim-authority";
import {
	createOwnedProjectSCIMReadAuthority,
	ownedSCIMScopedKey,
} from "./owned-project-scim-authority";
import {
	ownedSCIMError,
	ownedSCIMList,
	ownedSCIMResponse,
	ownedSCIMURLs,
	scimGroupSchema,
} from "./owned-project-scim-discovery";
import type {
	AttributeProjection,
	SCIMFilter,
	SCIMResource,
} from "./owned-project-scim-resources-query";
import {
	projectSCIMResource,
	readAttributeProjection,
	readSCIMCollectionQuery,
	readSCIMQuery,
} from "./owned-project-scim-resources-query";
import { readOwnedSCIMUserAttributes } from "./owned-project-scim-resources-user";

type Reader = Pick<PoolClient, "query">;
type Location = (path: string) => string;
interface ResourceRow {
	id: string;
	provisioningDomainId: string;
	externalId: string | null;
	displayName: string;
	createdAt: Date;
	updatedAt: Date;
}

interface UserRow extends ResourceRow {
	userName: string;
	active: boolean;
	serializedAttributes: string | null;
	formattedName: string;
	givenName: string | null;
	familyName: string | null;
	serializedEmails: string;
}

type ResourceRows =
	| { kind: "User"; rows: UserRow[] }
	| { kind: "Group"; rows: ResourceRow[] };

interface GroupMembership {
	groupId: string;
	id: string | null;
	displayName: string | null;
	provisioningDomainId: string | null;
}

const columns = `id, "provisioningDomainId", "externalId", "displayName", "createdAt", "updatedAt"`;
const userColumns = `${columns}, "userName", active, "serializedAttributes", "formattedName", "givenName", "familyName", "serializedEmails"`;
const groupMemberLimit = 1000;

function domainConflict() {
	return ownedSCIMError(
		409,
		"The connection provisioningDomainId changed after resources were created",
	);
}

function resourceLocation(location: Location, kind: SCIMResource, id: string) {
	return location(`/scim/v2/${kind}s/${encodeURIComponent(id)}`);
}

function resourceMeta(
	row: ResourceRow,
	kind: SCIMResource,
	location: Location,
) {
	return {
		resourceType: kind,
		created: row.createdAt,
		lastModified: row.updatedAt,
		location: resourceLocation(location, kind, row.id),
	};
}

function userResource(
	row: UserRow,
	location: Location,
	projection: AttributeProjection,
) {
	return projectSCIMResource(
		{
			...readOwnedSCIMUserAttributes(row),
			id: row.id,
			...(row.externalId ? { externalId: row.externalId } : {}),
			userName: row.userName,
			displayName: row.displayName,
			active: row.active,
			meta: resourceMeta(row, "User", location),
		},
		projection,
	);
}

function requestsMembers(projection: AttributeProjection) {
	if (projection.mode === "default") return true;
	if (projection.mode === "exclude")
		return !projection.paths.includes("members");
	return projection.paths.some(
		(path) => path === "members" || path.startsWith("members."),
	);
}

async function groupResources(
	client: Reader,
	connection: OwnedProjectSCIMConnection,
	groups: ResourceRow[],
	location: Location,
	projection: AttributeProjection,
) {
	const membersByGroup = new Map<string, GroupMembership[]>();
	if (groups.length && requestsMembers(projection)) {
		const maximum = groups.length * groupMemberLimit;
		const { rows } = await client.query<GroupMembership>(
			`SELECT m."groupId", u.id, u."displayName", u."provisioningDomainId"
			 FROM (
				SELECT "groupId", "scimUserId", "createdAt" FROM "scimGroupMember"
				WHERE "connectionId" = $1 AND "groupId" = ANY($2::text[])
				ORDER BY "createdAt" ASC LIMIT $3
			 ) m LEFT JOIN "scimUser" u ON u.id = m."scimUserId" AND u."connectionId" = $1
			 ORDER BY m."createdAt" ASC`,
			[connection.connectionId, groups.map((group) => group.id), maximum + 1],
		);
		if (rows.length > maximum)
			throw ownedSCIMError(
				500,
				"Persisted SCIM Group membership exceeds the server limit",
			);
		for (const membership of rows) {
			if (
				membership.id !== null &&
				membership.provisioningDomainId !== connection.provisioningDomainId
			)
				throw domainConflict();
			const group = membersByGroup.get(membership.groupId) ?? [];
			group.push(membership);
			if (group.length > groupMemberLimit)
				throw ownedSCIMError(
					500,
					"Persisted SCIM Group membership exceeds the server limit",
				);
			membersByGroup.set(membership.groupId, group);
		}
	}
	return groups.map((group) => {
		const members = (membersByGroup.get(group.id) ?? []).flatMap((member) =>
			member.id === null
				? []
				: [
						{
							value: member.id,
							$ref: resourceLocation(location, "User", member.id),
							display: member.displayName,
							type: "User",
						},
					],
		);
		return projectSCIMResource(
			{
				schemas: [scimGroupSchema],
				id: group.id,
				...(group.externalId ? { externalId: group.externalId } : {}),
				displayName: group.displayName,
				members,
				meta: resourceMeta(group, "Group", location),
			},
			projection,
		);
	});
}

function collectionWhere(
	connection: OwnedProjectSCIMConnection,
	kind: SCIMResource,
	filters: SCIMFilter[],
) {
	const params = [connection.connectionId, connection.provisioningDomainId];
	const predicates = [`"connectionId" = $1`, `"provisioningDomainId" = $2`];
	for (const { attribute, value } of filters) {
		const position = `$${params.length + 1}`;
		if (attribute === "emails.value" || attribute === "emails.work.value") {
			const field =
				attribute === "emails.value"
					? "emailValueIndex"
					: "workEmailValueIndex";
			predicates.push(`strpos("${field}", ${position}) > 0`);
			params.push(
				`|${ownedSCIMScopedKey(["scim-email-value", value.trim().toLowerCase()])}|`,
			);
			continue;
		}
		predicates.push(
			attribute === "id"
				? `id = ${position}`
				: `"${attribute}Key" = ${position}`,
		);
		if (attribute === "id") {
			params.push(value);
			continue;
		}
		const keyKind =
			attribute === "userName"
				? "scim-user-name"
				: attribute === "displayName"
					? "scim-group-display-name"
					: `scim-${kind.toLowerCase()}-external-id`;
		const keyValue = attribute === "externalId" ? value : value.toLowerCase();
		params.push(
			attribute === "externalId" && !value
				? ""
				: ownedSCIMScopedKey([keyKind, connection.connectionId, keyValue]),
		);
	}
	return { where: predicates.join(" AND "), params };
}

/** Serves the candidate managed SCIM Users and Groups GET routes in the selected realm. */
export function createOwnedProjectSCIMResources(
	options: Parameters<typeof createOwnedProjectSCIMReadAuthority>[0] & {
		baseURL: string;
	},
) {
	const read = createOwnedProjectSCIMReadAuthority(options);
	const { prefix, location } = ownedSCIMURLs(options.baseURL);
	return async function resources(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (request.method !== "GET" || !url.pathname.startsWith(prefix))
			return null;
		const match = /^(Users|Groups)(?:\/([^/]+))?$/.exec(
			url.pathname.slice(prefix.length),
		);
		if (!match) return null;
		const collection = match[1] === "Users" ? "Users" : "Groups";
		const kind = collection === "Users" ? "User" : "Group";
		const table = kind === "User" ? '"scimUser"' : '"scimGroup"';
		const id = match[2];

		try {
			const query = readSCIMQuery(url.searchParams, id === undefined);
			const result = await read(
				request.headers,
				collection,
				async (client, connection) => {
					const select = async (
						clause: string,
						parameters: (string | number)[],
					): Promise<ResourceRows> =>
						kind === "User"
							? {
									kind,
									rows: (
										await client.query<UserRow>(
											`SELECT ${userColumns} FROM ${table} ${clause}`,
											parameters,
										)
									).rows,
								}
							: {
									kind,
									rows: (
										await client.query<ResourceRow>(
											`SELECT ${columns} FROM ${table} ${clause}`,
											parameters,
										)
									).rows,
								};
					const render = (
						result: ResourceRows,
						projection: AttributeProjection,
					) =>
						result.kind === "User"
							? result.rows.map((row) =>
									userResource(row, location, projection),
								)
							: groupResources(
									client,
									connection,
									result.rows,
									location,
									projection,
								);

					if (id !== undefined) {
						const result = await select(
							`WHERE "connectionId" = $1 AND id = $2`,
							[connection.connectionId, id],
						);
						const row = result.rows[0];
						if (!row) return ownedSCIMError(404, `SCIM ${kind} not found`);
						if (row.provisioningDomainId !== connection.provisioningDomainId)
							return domainConflict();
						const rendered = await render(
							result,
							readAttributeProjection(kind, query),
						);
						return ownedSCIMResponse(rendered[0]!);
					}

					const scope = [
						connection.connectionId,
						connection.provisioningDomainId,
					];
					const mismatched = await client.query(
						`SELECT 1 FROM ${table} WHERE "connectionId" = $1 AND "provisioningDomainId" <> $2 LIMIT 1`,
						scope,
					);
					if (mismatched.rowCount) return domainConflict();
					const { startIndex, count, filters, projection } =
						readSCIMCollectionQuery(kind, query);
					const { where, params } = collectionWhere(connection, kind, filters);
					const total = await client.query<{ count: string }>(
						`SELECT count(*) FROM ${table} WHERE ${where}`,
						params,
					);
					const rows = count
						? await render(
								await select(
									`WHERE ${where} ORDER BY "orderKey" ASC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
									[...params, count, startIndex - 1],
								),
								projection,
							)
						: [];
					return ownedSCIMResponse(
						ownedSCIMList(rows, Number(total.rows[0]?.count ?? 0), startIndex),
					);
				},
			);
			return result.ok
				? result.value
				: ownedSCIMError(result.status, result.detail);
		} catch (error) {
			if (error instanceof Response) return error;
			return ownedSCIMError(500, "SCIM resources could not be read");
		}
	};
}
