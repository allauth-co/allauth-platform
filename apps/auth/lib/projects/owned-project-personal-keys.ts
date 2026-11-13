import { randomInt, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { PersonalApiKeyVerification } from "../auth-engine";
import { canonicalIP } from "../control/security-policy";
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
type KeyMutation = "/api-key/create" | "/api-key/update" | "/api-key/delete";
const auditError = z.object({
	code: z.string().regex(/^[a-zA-Z0-9_-]{1,100}$/),
});

type KeyRow = Record<(typeof columns)[number], unknown> & {
	id: string;
	permissions: string | null;
	metadata: string | null;
};

type VerifiableKey = KeyRow & {
	enabled: boolean | null;
	expiresAt: Date | null;
	lastRequest: Date | null;
	rateLimitEnabled: boolean | null;
	rateLimitTimeWindow: number | null;
	rateLimitMax: number | null;
	requestCount: number;
	remaining: number | null;
	createdAt: Date;
	lastRefillAt: Date | null;
	refillAmount: number | null;
	refillInterval: number | null;
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

function permits(
	permissions: string | null,
	requested: PersonalApiKeyVerification["permissions"],
) {
	if (!requested) return true;
	const grants = writeFields.permissions.safeParse(
		parseStoredJSON(permissions, 1),
	);
	const allowed = grants.success ? grants.data : undefined;
	if (!allowed) return false;
	const resources = Object.entries(requested);
	return (
		resources.length > 0 &&
		resources.every(
			([resource, actions]) =>
				Object.hasOwn(allowed, resource) &&
				actions.length > 0 &&
				actions.every((action) => allowed[resource]!.includes(action)),
		)
	);
}

function serverKeyResponse(body: object) {
	return Response.json(body, { headers: { "cache-control": "no-store" } });
}

function invalidKey(
	code: string,
	message: string,
	details?: { tryAgainIn: number },
) {
	return serverKeyResponse({
		valid: false,
		error: { code, message, ...(details && { details }) },
		key: null,
	});
}

function calculateKeyQuota(row: VerifiableKey, now: Date) {
	let { remaining, lastRefillAt } = row;
	if (remaining === null) return { remaining, lastRefillAt };
	if (
		row.refillInterval &&
		row.refillAmount &&
		now.getTime() - (lastRefillAt ?? row.createdAt).getTime() >
			row.refillInterval
	) {
		remaining = row.refillAmount;
		lastRefillAt = now;
	}
	return { remaining: remaining - 1, lastRefillAt };
}

function calculateKeyRate(
	row: VerifiableKey,
	now: Date,
): { requestCount: number; lastRequest: Date | null } | { tryAgainIn: number } {
	const { lastRequest, rateLimitTimeWindow, rateLimitMax, requestCount } = row;
	if (row.rateLimitEnabled === false) return { requestCount, lastRequest: now };
	if (rateLimitTimeWindow === null || rateLimitMax === null)
		return { requestCount, lastRequest };
	if (
		lastRequest === null ||
		now.getTime() - lastRequest.getTime() > rateLimitTimeWindow
	)
		return { requestCount: 1, lastRequest: now };
	if (requestCount >= rateLimitMax)
		return {
			tryAgainIn: Math.ceil(
				rateLimitTimeWindow - (now.getTime() - lastRequest.getTime()),
			),
		};
	return { requestCount: requestCount + 1, lastRequest: now };
}

/** Browser lifecycle and server verification for the installed default key configuration. */
export function createOwnedProjectPersonalKeys(options: PersonalKeyOptions) {
	const store = createProjectEngineStore(options.database, options.schemaName);

	async function verifyApiKey(input: PersonalApiKeyVerification) {
		const invalid = () => invalidKey("INVALID_API_KEY", "Invalid API key.");
		if (input.configId && input.configId !== "default") return invalid();
		return store.transaction(async (client) => {
			const { rows } = await client.query<VerifiableKey>(
				`SELECT ${publicColumns} FROM "apikey" WHERE key=$1 AND ${defaultConfiguration}
				 ORDER BY id LIMIT 2 FOR UPDATE`,
				[issuerDigest(input.key)],
			);
			if (rows.length !== 1) return invalid();
			const row = rows[0]!;
			if (row.enabled === false)
				return invalidKey("KEY_DISABLED", "API Key is disabled");
			const now = new Date();
			if (row.expiresAt && row.expiresAt < now) {
				await client.query('DELETE FROM "apikey" WHERE id=$1', [row.id]);
				return invalidKey("KEY_EXPIRED", "API Key has expired");
			}
			if (!permits(row.permissions, input.permissions))
				return invalidKey("KEY_NOT_FOUND", "API Key not found");
			const quota = calculateKeyQuota(row, now);
			if (quota.remaining !== null && quota.remaining < 0) {
				if (row.remaining === 0 && row.refillAmount === null)
					await client.query('DELETE FROM "apikey" WHERE id=$1', [row.id]);
				return invalidKey(
					"USAGE_EXCEEDED",
					"API Key has reached its usage limit",
				);
			}
			const rate = calculateKeyRate(row, now);
			if ("tryAgainIn" in rate) {
				if (
					quota.remaining !== row.remaining ||
					quota.lastRefillAt !== row.lastRefillAt
				)
					await client.query(
						'UPDATE "apikey" SET remaining=$2,"lastRefillAt"=$3 WHERE id=$1',
						[row.id, quota.remaining, quota.lastRefillAt],
					);
				return invalidKey("RATE_LIMITED", "Rate limit exceeded.", {
					tryAgainIn: rate.tryAgainIn,
				});
			}
			const {
				rows: [current],
			} = await client.query<KeyRow>(
				`UPDATE "apikey" SET remaining=$2,"lastRefillAt"=$3,"requestCount"=$4,"lastRequest"=$5,"updatedAt"=$6
				 WHERE id=$1 RETURNING ${publicColumns}`,
				[
					row.id,
					quota.remaining,
					quota.lastRefillAt,
					rate.requestCount,
					rate.lastRequest,
					now,
				],
			);
			if (!current) return invalid();
			return serverKeyResponse({
				valid: true,
				error: null,
				key: publicKey(current),
			});
		});
	}

	async function deleteAllExpiredApiKeys() {
		await store.transaction((client) =>
			client.query(
				'DELETE FROM "apikey" WHERE "expiresAt" < statement_timestamp()',
			),
		);
		return serverKeyResponse({ success: true, error: null });
	}

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
		input: z.infer<typeof createInput>,
	) {
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
		return apiKeyResponse({ ...publicKey(row!), key }, authority);
	}

	async function update(
		client: PoolClient,
		authority: KeyAuthority,
		input: z.infer<typeof updateInput>,
	) {
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
		return apiKeyResponse(publicKey(row!), authority);
	}

	async function revoke(
		client: PoolClient,
		authority: KeyAuthority,
		input: z.infer<typeof deleteInput>,
	) {
		const removed = await client.query(
			`DELETE FROM "apikey" WHERE id=$1 AND "referenceId"=$2 AND ${defaultConfiguration}`,
			[input.keyId, authority.userId],
		);
		if (removed.rowCount !== 1) return keyNotFound();
		return apiKeyResponse({ success: true }, authority);
	}

	async function mutate<Input>(
		client: PoolClient,
		request: Request,
		path: KeyMutation,
		authority: KeyAuthority | null,
		body: unknown,
		schema: z.ZodType<Input>,
		change: (
			client: PoolClient,
			authority: KeyAuthority,
			input: Input,
		) => Promise<Response>,
	) {
		const parsed = schema.safeParse(body);
		const response = !parsed.success
			? error("VALIDATION_ERROR", "Invalid API key input.")
			: authority
				? await change(client, authority, parsed.data)
				: path === "/api-key/delete"
					? error("UNAUTHORIZED", "Unauthorized", 401)
					: noAuthority();
		const failed = response.status >= 400;
		const detail = failed
			? auditError.safeParse(
					await response
						.clone()
						.json()
						.catch(() => null),
				)
			: null;
		const userId = parsed.success ? authority?.userId : undefined;
		await store.recordEvent(client, {
			type: path.slice(1).replaceAll("/", "."),
			outcome: failed ? "failure" : "success",
			actorId: userId,
			userId,
			ipAddress: canonicalIP(options.trustedIP(request)) ?? undefined,
			userAgent: request.headers.get("user-agent") ?? undefined,
			metadata: {
				path,
				...(failed
					? { errorCode: detail?.data?.code ?? "AUTHENTICATION_FAILED" }
					: {}),
			},
		});
		return response;
	}

	async function dispatch(path: string, request: Request) {
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
			if (
				(path === "/api-key/create" || path === "/api-key/update") &&
				body &&
				typeof body === "object" &&
				"permissions" in body &&
				body.permissions &&
				!authority?.platformAdmin
			)
				return error(
					undefined,
					"Custom API key permissions require a platform administrator.",
					403,
				);
			const params = new URL(request.url).searchParams;
			switch (path) {
				case "/api-key/list":
					return authority
						? list(client, authority, params)
						: error("UNAUTHORIZED", "Unauthorized", 401);
				case "/api-key/get":
					return authority
						? get(client, authority, params)
						: error("UNAUTHORIZED", "Unauthorized", 401);
				case "/api-key/create":
					return mutate(
						client,
						request,
						path,
						authority,
						body,
						createInput,
						create,
					);
				case "/api-key/update":
					return mutate(
						client,
						request,
						path,
						authority,
						body,
						updateInput,
						update,
					);
				case "/api-key/delete":
					return mutate(
						client,
						request,
						path,
						authority,
						body,
						deleteInput,
						revoke,
					);
			}
		});
	}

	return { dispatch, verifyApiKey, deleteAllExpiredApiKeys };
}
