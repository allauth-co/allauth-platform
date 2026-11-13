import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { organizationRolePermissions } from "./owned-project-organization-access";
import type { DirectoryOperation } from "./service-directory-transport";

const id = z
	.string()
	.min(1)
	.max(160)
	.refine((value) => !value.includes("\0"));
const pagination = {
	limit: z.coerce.number().int().min(1).max(100).default(25),
	offset: z.coerce.number().int().min(0).max(100000).default(0),
};
const operations = {
	users: "serviceDirectoryUsers",
	organizations: "serviceDirectoryOrganizations",
	members: "serviceDirectoryMembers",
	roles: "serviceDirectoryRoles",
} as const satisfies Record<string, DirectoryOperation>;
const querySchema = {
	serviceDirectoryUsers: z.strictObject({
		userId: id.optional(),
		...pagination,
	}),
	serviceDirectoryOrganizations: z.strictObject({
		organizationId: id.optional(),
		...pagination,
	}),
	serviceDirectoryMembers: z
		.strictObject({
			organizationId: id.optional(),
			userId: id.optional(),
			...pagination,
		})
		.refine((value) => Boolean(value.organizationId || value.userId)),
	serviceDirectoryRoles: z.strictObject({ organizationId: id, ...pagination }),
};
const builtInPermissions = organizationRolePermissions([])!;
const builtInRoles = ["admin", "owner", "member"].map((role) => ({
	id: role,
	role,
	permission: Object.fromEntries(
		[...builtInPermissions.get(role)!].map(([resource, allowed]) => [
			resource,
			[...allowed],
		]),
	),
	builtIn: true,
}));

interface Options {
	database: Pool;
	schemaName: string;
	project: string;
	projectId: string;
	environment: "development" | "production";
	authorize(headers: Headers): Promise<void>;
}

function json(value: unknown, status = 200) {
	return Response.json(value, {
		status,
		headers: { "cache-control": "no-store", pragma: "no-cache" },
	});
}

async function readPage(
	client: PoolClient,
	table: string,
	columns: string,
	filter: string,
	parameters: string[],
	limit: number,
	offset: number,
) {
	const entries = await client.query(
		`SELECT ${columns} FROM "${table}" ${filter} ORDER BY id LIMIT $${parameters.length + 1} OFFSET $${parameters.length + 2}`,
		[...parameters, limit, offset],
	);
	const count = await client.query<{ total: number }>(
		`SELECT COUNT(*)::int AS total FROM "${table}" ${filter}`,
		parameters,
	);
	return { entries: entries.rows, total: count.rows[0].total };
}

/** Keep directory authority independent of user cookies and restrict reads to the selected project. */
export function createOwnedProjectServiceDirectory(options: Options) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	const envelope = {
		project: options.project,
		projectId: options.projectId,
		environment: options.environment,
	};

	async function read(
		operation: DirectoryOperation,
		headers: Headers,
		query: Record<string, unknown>,
	) {
		try {
			await options.authorize(headers);
		} catch (error) {
			if (
				error &&
				typeof error === "object" &&
				"statusCode" in error &&
				(error.statusCode === 401 || error.statusCode === 403)
			) {
				const body =
					"body" in error && error.body && typeof error.body === "object"
						? error.body
						: null;
				const message =
					body && "message" in body && typeof body.message === "string"
						? body.message
						: "The directory request is not permitted.";
				return json({ error: message }, error.statusCode);
			}
			throw error;
		}
		const parsed = querySchema[operation].safeParse(query);
		if (!parsed.success)
			return json({ error: "Invalid directory query." }, 400);
		const { limit, offset } = parsed.data;
		const userId = "userId" in parsed.data ? parsed.data.userId : undefined;
		const orgId =
			"organizationId" in parsed.data ? parsed.data.organizationId : undefined;
		const fields = { ...envelope, limit, offset };

		return store.transaction(async (client) => {
			await client.query(
				"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
			);
			if (operation === "serviceDirectoryUsers") {
				const columns =
					'id,name,email,"emailVerified","twoFactorEnabled",image,banned,"banExpires","directoryDisabled","createdAt","updatedAt"';
				const { entries, total } = await readPage(
					client,
					"user",
					columns,
					userId ? "WHERE id = $1" : "",
					userId ? [userId] : [],
					limit,
					offset,
				);
				return json({ ...fields, users: entries, total });
			}
			if (operation === "serviceDirectoryOrganizations") {
				const { entries, total } = await readPage(
					client,
					"organization",
					'id,name,slug,logo,"createdAt"',
					orgId ? "WHERE id = $1" : "",
					orgId ? [orgId] : [],
					limit,
					offset,
				);
				return json({ ...fields, organizations: entries, total });
			}
			if (orgId) {
				const target = await client.query(
					'SELECT 1 FROM "organization" WHERE id = $1',
					[orgId],
				);
				if (!target.rowCount) return json({ error: "Not Found" }, 404);
			}
			if (operation === "serviceDirectoryMembers") {
				const filter = [
					...(orgId ? ['"organizationId" = $1'] : []),
					...(userId ? [`"userId" = $${orgId ? 2 : 1}`] : []),
				].join(" AND ");
				const { entries, total } = await readPage(
					client,
					"member",
					'id,"organizationId","userId",role,"createdAt"',
					`WHERE ${filter}`,
					[orgId, userId].filter((value): value is string => Boolean(value)),
					limit,
					offset,
				);
				return json({ ...fields, members: entries, total });
			}
			const staticRoles = builtInRoles.slice(offset, offset + limit);
			const custom = await client.query<{
				id: string;
				role: string;
				permission: string;
			}>(
				'SELECT id,role,permission FROM "organizationRole" WHERE "organizationId" = $1 ORDER BY role, id LIMIT $2 OFFSET $3',
				[
					orgId,
					limit - staticRoles.length,
					Math.max(0, offset - builtInRoles.length),
				],
			);
			const count = await client.query<{ total: number }>(
				'SELECT COUNT(*)::int AS total FROM "organizationRole" WHERE "organizationId" = $1',
				[orgId],
			);
			return json({
				...fields,
				roles: [
					...staticRoles,
					...custom.rows.map((role) => ({
						...role,
						permission: JSON.parse(role.permission),
						builtIn: false,
					})),
				],
				total: builtInRoles.length + count.rows[0].total,
			});
		});
	}

	function dispatch(path: string, request: Request) {
		if (request.method !== "GET" || !path.startsWith("/service-directory/"))
			return;
		const collection = path.slice("/service-directory/".length);
		if (!Object.hasOwn(operations, collection)) return;
		const params = new URL(request.url).searchParams;
		const query = Object.fromEntries(
			[...new Set(params.keys())].map((name) => {
				const values = params.getAll(name);
				return [name, values.length === 1 ? values[0] : values];
			}),
		);
		return read(
			operations[collection as keyof typeof operations],
			request.headers,
			query,
		);
	}

	return { read, dispatch };
}
