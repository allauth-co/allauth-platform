import { randomInt, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { issuerDigest } from "./owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import {
	hasOrganizationPermission,
	organizationRolePermissions,
} from "./owned-project-organization-access";

const defaultPrefix = "allauth_";
const secondsPerDay = 86_400;
const maximumLifetime = 90 * secondsPerDay;
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const defaultPermissions = { identity: ["read"] };
const defaultConfiguration = `coalesce(nullif("configId",''),'default')='default'`;
const columns = [
	"id",
	"configId",
	"name",
	"start",
	"referenceId",
	"prefix",
	"refillInterval",
	"refillAmount",
	"lastRefillAt",
	"enabled",
	"rateLimitEnabled",
	"rateLimitTimeWindow",
	"rateLimitMax",
	"requestCount",
	"remaining",
	"lastRequest",
	"expiresAt",
	"createdAt",
	"updatedAt",
	"permissions",
	"metadata",
] as const;
const publicColumns = columns.map((column) => `"${column}"`).join(",");
const sortColumn = z.enum(columns);
const rowId = z.string();
const pagination = z.coerce.number().int().nonnegative().optional();
const listInput = z.object({
	configId: z.string().optional(),
	organizationId: z.string().optional(),
	limit: pagination,
	offset: pagination,
	sortBy: sortColumn.optional(),
	sortDirection: z.enum(["asc", "desc"]).optional(),
});
const getInput = z.object({ id: rowId, configId: z.string().optional() });
const deleteInput = z.object({ keyId: rowId, configId: z.string().optional() });
const writeFields = {
	name: z.string().optional(),
	expiresIn: z.number().min(1).nullable().optional(),
	userId: z.coerce.string().optional(),
	metadata: z.unknown().optional(),
	refillAmount: z.number().optional(),
	refillInterval: z.number().optional(),
	rateLimitMax: z.number().optional(),
	rateLimitTimeWindow: z.number().optional(),
	rateLimitEnabled: z.boolean().optional(),
	permissions: z.record(z.string(), z.array(z.string())).optional(),
	remaining: z.number().nullable().optional(),
};
const createInput = z.object({
	...writeFields,
	configId: z.string().optional(),
	prefix: z
		.string()
		.regex(/^[a-zA-Z0-9_-]+$/)
		.optional(),
});
const updateInput = deleteInput.extend({
	...writeFields,
	enabled: z.boolean().optional(),
	permissions: writeFields.permissions.nullable(),
});
const routes = {
	"/api-key/list": "GET",
	"/api-key/get": "GET",
	"/api-key/create": "POST",
	"/api-key/update": "POST",
	"/api-key/delete": "POST",
} as const;
type KeyRoute = keyof typeof routes;

type KeyRow = Record<(typeof columns)[number], unknown> & {
	id: string;
	permissions: string | null;
	metadata: string | null;
};

type KeyAuthority = {
	userId: string;
	platformAdmin: boolean;
	headers: Headers;
};

interface PersonalKeyOptions {
	database: Pool;
	schemaName: string;
	readBody(request: Request): Promise<unknown>;
	trustedIP(request: Request): string | null;
	authorize(
		request: Request,
		client: PoolClient,
	): Promise<KeyAuthority | Response | null>;
}

function isKeyRoute(path: string): path is KeyRoute {
	return Object.hasOwn(routes, path);
}

function error(code: string | undefined, message: string, status = 400) {
	return Response.json(
		{ code, message },
		{ status, headers: { "cache-control": "no-store", pragma: "no-cache" } },
	);
}

function keyNotFound() {
	return error("KEY_NOT_FOUND", "API Key not found", 404);
}

function noAuthority() {
	return error("UNAUTHORIZED_SESSION", "Unauthorized or invalid session", 401);
}

function parseStoredJSON(value: string | null, depth: number): unknown {
	let parsed: unknown = value;
	try {
		for (let index = 0; index < depth && typeof parsed === "string"; index++)
			parsed = JSON.parse(parsed);
		return parsed;
	} catch {
		return null;
	}
}

function publicKey(row: KeyRow) {
	return {
		...row,
		permissions: parseStoredJSON(row.permissions, 1),
		metadata: parseStoredJSON(row.metadata, 2),
	};
}

function validateLifetime(expiresIn: number | null | undefined) {
	if (expiresIn == null) return;
	if (expiresIn < secondsPerDay)
		return error(
			"EXPIRES_IN_IS_TOO_SMALL",
			"The expiresIn is smaller than the predefined minimum value.",
		);
	if (expiresIn > maximumLifetime)
		return error(
			"EXPIRES_IN_IS_TOO_LARGE",
			"The expiresIn is larger than the predefined maximum value.",
		);
}

function hasServerOnlyFields(
	body: z.infer<typeof createInput> | z.infer<typeof updateInput>,
	create: boolean,
) {
	return (
		body.refillAmount !== undefined ||
		body.refillInterval !== undefined ||
		body.rateLimitMax !== undefined ||
		body.rateLimitTimeWindow !== undefined ||
		body.rateLimitEnabled !== undefined ||
		body.permissions !== undefined ||
		(create ? body.remaining != null : body.remaining !== undefined)
	);
}

function apiKeyResponse(body: object, authority: KeyAuthority) {
	const headers = new Headers(authority.headers);
	headers.set("cache-control", "no-store");
	headers.set("pragma", "no-cache");
	return Response.json(body, { headers });
}

/** HTTP lifecycle for personal keys in the selected project's native default configuration. */
export function createOwnedProjectPersonalKeys(options: PersonalKeyOptions) {
	const store = createProjectEngineStore(options.database, options.schemaName);

	async function checkOrganizationListing(
		client: PoolClient,
		userId: string,
		organizationId: string,
	) {
		const {
			rows: [member],
		} = await client.query<{ role: string }>(
			'SELECT role FROM "member" WHERE "userId"=$1 AND "organizationId"=$2',
			[userId, organizationId],
		);
		if (!member)
			return error(
				"USER_NOT_MEMBER_OF_ORGANIZATION",
				"You are not a member of the organization that owns this API key.",
				403,
			);
		if (member.role.split(",").includes("owner")) return;
		const { rows } = await client.query<{ role: string; permission: string }>(
			'SELECT role,permission FROM "organizationRole" WHERE "organizationId"=$1',
			[organizationId],
		);
		const roles = organizationRolePermissions(rows);
		if (
			!roles ||
			!hasOrganizationPermission(roles, member.role, { apiKey: ["read"] })
		)
			return error(
				"INSUFFICIENT_API_KEY_PERMISSIONS",
				"You do not have permission to perform this action on organization API keys.",
				403,
			);
	}

	async function list(
		client: PoolClient,
		authority: KeyAuthority,
		params: URLSearchParams,
	) {
		const parsed = listInput.safeParse(Object.fromEntries(params));
		if (!parsed.success)
			return error("INVALID_QUERY", "Invalid API key query.");
		const { organizationId, configId, limit, offset, sortBy, sortDirection } =
			parsed.data;
		if (organizationId !== undefined) {
			if (organizationId) {
				const denied = await checkOrganizationListing(
					client,
					authority.userId,
					organizationId,
				);
				if (denied) return denied;
			}
			// The installed default configuration is personal, so it has no organization rows.
			return apiKeyResponse(
				{ apiKeys: [], total: 0, limit, offset },
				authority,
			);
		}
		if (configId && configId !== "default")
			return apiKeyResponse(
				{ apiKeys: [], total: 0, limit, offset },
				authority,
			);
		const sort = sortBy ?? "createdAt";
		const direction = sortDirection === "desc" ? "DESC" : "ASC";
		const {
			rows: [count],
		} = await client.query<{ total: string }>(
			`SELECT count(*) AS total FROM "apikey" WHERE "referenceId"=$1 AND ${defaultConfiguration}`,
			[authority.userId],
		);
		const { rows } = await client.query<KeyRow>(
			`SELECT ${publicColumns} FROM "apikey" WHERE "referenceId"=$1 AND ${defaultConfiguration}
			 ORDER BY "${sort}" ${direction}, id LIMIT $2::bigint OFFSET $3::bigint`,
			[authority.userId, limit ?? null, offset ?? 0],
		);
		return apiKeyResponse(
			{
				apiKeys: rows.map(publicKey),
				total: Number(count!.total),
				limit,
				offset,
			},
			authority,
		);
	}

	async function get(
		client: PoolClient,
		authority: KeyAuthority,
		params: URLSearchParams,
	) {
		const parsed = getInput.safeParse(Object.fromEntries(params));
		if (!parsed.success)
			return error("INVALID_QUERY", "Invalid API key query.");
		const {
			rows: [row],
		} = await client.query<KeyRow>(
			`SELECT ${publicColumns} FROM "apikey" WHERE id=$1 AND "referenceId"=$2 AND ${defaultConfiguration}`,
			[parsed.data.id, authority.userId],
		);
		return row ? apiKeyResponse(publicKey(row), authority) : keyNotFound();
	}

	async function create(
		client: PoolClient,
		authority: KeyAuthority,
		body: unknown,
	) {
		const parsed = createInput.safeParse(body);
		if (!parsed.success) return error("INVALID_BODY", "Invalid API key input.");
		const input = parsed.data;
		if (input.permissions && !authority.platformAdmin)
			return error(
				undefined,
				"Custom API key permissions require a platform administrator.",
				403,
			);
		if (hasServerOnlyFields(input, true))
			return error(
				"SERVER_ONLY_PROPERTY",
				"The property you're trying to set can only be set from the server auth instance only.",
			);
		if (input.userId !== undefined) return noAuthority();
		if (input.metadata)
			return error("METADATA_DISABLED", "Metadata is disabled.");
		const lifetime = validateLifetime(input.expiresIn);
		if (lifetime) return lifetime;
		const prefix = input.prefix ?? defaultPrefix;
		if (prefix.length > 32)
			return error(
				"INVALID_PREFIX_LENGTH",
				"The prefix length is either too large or too small.",
			);
		if (!input.name) return error("NAME_REQUIRED", "API Key name is required.");
		if (input.name.length > 32)
			return error(
				"INVALID_NAME_LENGTH",
				"The name length is either too large or too small.",
			);
		const key =
			prefix +
			Array.from({ length: 64 }, () => letters[randomInt(letters.length)]).join(
				"",
			);
		const {
			rows: [row],
		} = await client.query<KeyRow>(
			`INSERT INTO "apikey"(id,"configId",name,start,"referenceId",prefix,key,enabled,
			 "rateLimitEnabled","rateLimitTimeWindow","rateLimitMax","requestCount","expiresAt","createdAt","updatedAt",permissions)
			 VALUES($1,'default',$2,$3,$4,$5,$6,TRUE,TRUE,60000,100,0,clock_timestamp()+$7::double precision*interval '1 second',
			 statement_timestamp(),statement_timestamp(),$8) RETURNING ${publicColumns}`,
			[
				randomUUID(),
				input.name,
				key.slice(0, 6),
				authority.userId,
				prefix,
				issuerDigest(key),
				input.expiresIn ?? maximumLifetime,
				JSON.stringify(defaultPermissions),
			],
		);
		await store.record(
			client,
			"api-key.create",
			"success",
			"/api-key/create",
			authority.userId,
			row!.id,
		);
		return apiKeyResponse({ ...publicKey(row!), key }, authority);
	}

	async function update(
		client: PoolClient,
		authority: KeyAuthority,
		body: unknown,
	) {
		const parsed = updateInput.safeParse(body);
		if (!parsed.success) return error("INVALID_BODY", "Invalid API key input.");
		const input = parsed.data;
		if (input.permissions && !authority.platformAdmin)
			return error(
				undefined,
				"Custom API key permissions require a platform administrator.",
				403,
			);
		if (input.userId && input.userId !== authority.userId) return noAuthority();
		if (hasServerOnlyFields(input, false))
			return error(
				"SERVER_ONLY_PROPERTY",
				"The property you're trying to set can only be set from the server auth instance only.",
			);
		const {
			rows: [existing],
		} = await client.query<{ id: string }>(
			`SELECT id FROM "apikey" WHERE id=$1 AND "referenceId"=$2 AND ${defaultConfiguration} FOR UPDATE`,
			[input.keyId, authority.userId],
		);
		if (!existing) return keyNotFound();
		if (
			input.name !== undefined &&
			(input.name.length < 1 || input.name.length > 32)
		)
			return error(
				"INVALID_NAME_LENGTH",
				"The name length is either too large or too small.",
			);
		const lifetime = validateLifetime(input.expiresIn);
		if (lifetime) return lifetime;
		if (
			input.name === undefined &&
			input.enabled === undefined &&
			input.expiresIn === undefined
		)
			return error("NO_VALUES_TO_UPDATE", "No values to update.");
		const {
			rows: [row],
		} = await client.query<KeyRow>(
			`UPDATE "apikey" SET name=coalesce($3,name),enabled=coalesce($4,enabled),
			 "expiresAt"=CASE WHEN $5 THEN clock_timestamp()+$6::double precision*interval '1 second' ELSE "expiresAt" END
			 WHERE id=$1 AND "referenceId"=$2 AND ${defaultConfiguration} RETURNING ${publicColumns}`,
			[
				input.keyId,
				authority.userId,
				input.name ?? null,
				input.enabled ?? null,
				input.expiresIn !== undefined,
				input.expiresIn ?? null,
			],
		);
		await store.record(
			client,
			"api-key.update",
			"success",
			"/api-key/update",
			authority.userId,
			row!.id,
		);
		return apiKeyResponse(publicKey(row!), authority);
	}

	async function revoke(
		client: PoolClient,
		authority: KeyAuthority,
		body: unknown,
	) {
		const parsed = deleteInput.safeParse(body);
		if (!parsed.success) return error("INVALID_BODY", "Invalid API key input.");
		const removed = await client.query(
			`DELETE FROM "apikey" WHERE id=$1 AND "referenceId"=$2 AND ${defaultConfiguration}`,
			[parsed.data.keyId, authority.userId],
		);
		if (removed.rowCount !== 1) return keyNotFound();
		await store.record(
			client,
			"api-key.delete",
			"success",
			"/api-key/delete",
			authority.userId,
			parsed.data.keyId,
		);
		return apiKeyResponse({ success: true }, authority);
	}

	return async function dispatch(path: string, request: Request) {
		if (!isKeyRoute(path) || request.method !== routes[path]) return;
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		const body =
			request.method === "POST" ? await options.readBody(request) : undefined;
		return store.transaction(async (client) => {
			const authority = await options.authorize(request, client);
			if (authority instanceof Response) return authority;
			if (!authority)
				return path === "/api-key/create" || path === "/api-key/update"
					? noAuthority()
					: error("UNAUTHORIZED", "Unauthorized", 401);
			const params = new URL(request.url).searchParams;
			switch (path) {
				case "/api-key/list":
					return list(client, authority, params);
				case "/api-key/get":
					return get(client, authority, params);
				case "/api-key/create":
					return create(client, authority, body);
				case "/api-key/update":
					return update(client, authority, body);
				case "/api-key/delete":
					return revoke(client, authority, body);
			}
		});
	};
}
