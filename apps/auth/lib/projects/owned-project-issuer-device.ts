import { randomInt, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { freshFeatureSession } from "../features/helpers";
import type { createPlatformIssuerStore } from "../platform-issuer-store";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectIssuerAuthorizationOptions } from "./owned-project-issuer-authorization";
import type {
	IssuerClientAuthenticator,
	ProjectIssuerClient,
} from "./owned-project-issuer-client";
import {
	createIssuerClientAuthenticator,
	readIssuerClient,
} from "./owned-project-issuer-client";
import {
	issuerForm,
	issuerFormParameters,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";
import { issuerResourcePolicy } from "./owned-project-issuer-resources";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import { projectOrigin, projectSlug } from "./validation";

export const projectDeviceGrantType =
	"urn:ietf:params:oauth:grant-type:device_code";
const expirySeconds = 600;
const intervalSeconds = 5;
const deviceAlphabet =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const userAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const defaultUserCode = new RegExp(`^[${userAlphabet}]+$`);
const codeInput = z.string().min(1).max(191);
const resourceInput = z.string().min(1).max(2048);
const resourcesInput = z.array(resourceInput).max(16);
const initiationInput = z.object({
	client_id: z.string().max(256).optional(),
	user_id: z.string().max(256).optional(),
	scope: z.string().max(4096).optional(),
	client_secret: z.string().max(4096).optional(),
	client_assertion: z.string().max(16384).optional(),
	client_assertion_type: z.string().max(256).optional(),
	resource: z.union([z.string().max(2048), resourcesInput.min(1)]).optional(),
});
const browserInput = z.object({ userCode: codeInput });
const standaloneTokenInput = z.object({
	grant_type: z.literal(projectDeviceGrantType),
	device_code: z.string().max(191),
	client_id: z.string().max(256),
});
const scopeToken = /^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/;
const codeColumns = `id,"deviceCode","userCode","userId","expiresAt",status,"lastPolledAt","pollingInterval","clientId",scope,resources,"oauthClientId"`;

export interface PreparedIssuerDeviceBody {
	body: unknown;
}

/** Preserve exact installed custom user codes before trying the default alphabet. */
export function deviceUserCodeCandidates(value: unknown) {
	const parsed = codeInput.safeParse(value);
	if (!parsed.success) return;
	const exact = parsed.data;
	const normalized = exact.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
	return normalized !== exact && defaultUserCode.test(normalized)
		? [exact, normalized]
		: [exact];
}

type DeviceRow = {
	id: string;
	deviceCode: string;
	userCode: string;
	userId: string | null;
	expiresAt: Date;
	status: string;
	lastPolledAt: Date | null;
	pollingInterval: number | null;
	clientId: string | null;
	scope: string | null;
	resources: unknown;
	oauthClientId: string | null;
};

export interface OwnedProjectIssuerDeviceOptions
	extends Pick<
		OwnedProjectIssuerAuthorizationOptions,
		"database" | "schemaName" | "issuer" | "readBody" | "readSession"
	> {
	platformOrigin: string;
	projectSlug?: string;
	endpointBase?: string;
	store?: Pick<
		ReturnType<typeof createPlatformIssuerStore>,
		"transaction" | "lockUser"
	>;
	trustedOrigins?: readonly string[];
	trustedIP(request: Request): string | null;
	authenticateClient?: IssuerClientAuthenticator;
}

export interface ProjectDeviceGrant {
	userId: string;
	scopes: string[];
	resources: string[];
	originalResources: string[] | null;
}

function invalidGrant(message = "Invalid device code") {
	return new ProjectOAuthError("invalid_grant", message);
}

function requireDeviceClient(client: ProjectIssuerClient) {
	if (!client.grantTypes?.includes(projectDeviceGrantType))
		throw new ProjectOAuthError(
			"unauthorized_client",
			`client is not authorized to use grant type ${projectDeviceGrantType}`,
		);
}

function deviceScopes(value: string | null, client: ProjectIssuerClient) {
	if (value && value.length > 4096)
		throw new ProjectOAuthError("invalid_scope", "Invalid device scope");
	const scopes = value?.trim().split(/\s+/).filter(Boolean) ?? [];
	if (
		scopes.length > 64 ||
		scopes.some(
			(item) =>
				!scopeToken.test(item) ||
				(client.scopes !== null && !client.scopes.includes(item)),
		)
	)
		throw new ProjectOAuthError(
			"invalid_scope",
			"The client does not allow the requested scopes",
		);
	return scopes;
}

function resourceList(input: unknown) {
	const parsed = resourcesInput.safeParse(input);
	if (
		!parsed.success ||
		parsed.data.some((value) => {
			if (
				!URL.canParse(value) ||
				value.includes("#") ||
				/[\\\u0000-\u0020\u007f]/.test(value)
			)
				return true;
			return ["javascript:", "data:", "vbscript:"].includes(
				new URL(value).protocol,
			);
		})
	)
		throw new ProjectOAuthError("invalid_target", "Invalid resource indicator");
	return [...new Set(parsed.data)];
}

function formResources(form: URLSearchParams) {
	const values = form.getAll("resource");
	return resourceList(values.length === 1 && values[0] === "" ? [] : values);
}

function randomCode(alphabet: string, length: number) {
	return Array.from(
		{ length },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
}

async function readDevice(
	database: PoolClient,
	raw: string,
	clientId: string,
	lock = false,
) {
	const { rows } = await database.query<DeviceRow>(
		`SELECT ${codeColumns} FROM "deviceCode" WHERE "deviceCode"=$1 AND "oauthClientId"=$2 AND "clientId"=$2${lock ? " FOR UPDATE" : ""}`,
		[raw, clientId],
	);
	return rows[0];
}

/** Consume an OAuth-only device code with token writes in the caller's transaction. */
export async function consumeDeviceGrant<T>(
	database: PoolClient,
	_request: Request,
	form: URLSearchParams,
	authClient: ProjectIssuerClient,
	options: {
		endpointBase: string;
		issue(grant: ProjectDeviceGrant): Promise<T>;
	},
): Promise<T> {
	const raw = form.get("device_code");
	if (!raw)
		throw new ProjectOAuthError("invalid_request", "device_code is required");
	if (!codeInput.safeParse(raw).success) throw invalidGrant();
	requireDeviceClient(authClient);
	const observed = await readDevice(database, raw, authClient.clientId);
	if (!observed) throw invalidGrant();
	const owner =
		observed.userId &&
		(
			await database.query(
				`SELECT id FROM "user" WHERE id=$1 AND "emailVerified"=TRUE AND banned IS DISTINCT FROM TRUE
		 AND "directoryDisabled" IS DISTINCT FROM TRUE AND "isAnonymous" IS DISTINCT FROM TRUE FOR SHARE`,
				[observed.userId],
			)
		).rowCount === 1;
	const row = await readDevice(database, raw, authClient.clientId, true);
	if (!row || row.id !== observed.id) throw invalidGrant();
	const scopes = deviceScopes(row.scope, authClient);
	const now = Date.now();
	if (
		row.lastPolledAt &&
		row.pollingInterval &&
		now - row.lastPolledAt.getTime() < row.pollingInterval
	)
		throw new ProjectOAuthError("slow_down", "Polling too frequently");
	await database.query(
		'UPDATE "deviceCode" SET "lastPolledAt"=clock_timestamp() WHERE id=$1',
		[row.id],
	);
	if (row.expiresAt.getTime() <= now || row.status === "denied") {
		await database.query('DELETE FROM "deviceCode" WHERE id=$1', [row.id]);
		throw row.status === "denied" && row.expiresAt.getTime() > now
			? new ProjectOAuthError("access_denied", "Access denied")
			: new ProjectOAuthError("expired_token", "Device code has expired");
	}
	// A first claim can land between the snapshot and the row lock. Let the next
	// poll acquire the now-known user lock before the code instead of reversing it.
	if (
		row.status === "pending" ||
		(row.status === "approved" && observed.userId !== row.userId)
	)
		throw new ProjectOAuthError(
			"authorization_pending",
			"Authorization pending",
		);
	if (row.status !== "approved" || !row.userId)
		throw new ProjectOAuthError(
			"server_error",
			"Invalid device code status",
			500,
		);
	if (!owner) throw invalidGrant("The account is unavailable.");
	const originalResources =
		row.resources === null ? null : resourceList(row.resources);
	const requested = formResources(form);
	if (requested.some((value) => !originalResources?.includes(value)))
		throw new ProjectOAuthError(
			"invalid_target",
			"Requested resource was not authorized by the user",
		);
	const resources = requested.length ? requested : (originalResources ?? []);
	await issuerResourcePolicy(
		database,
		authClient,
		resources,
		scopes,
		`${options.endpointBase}/oauth2/userinfo`,
	);
	const result = await options.issue({
		userId: row.userId,
		scopes,
		resources,
		originalResources,
	});
	if (result instanceof Response && !result.ok)
		throw new Error("Device token issuance did not complete.");
	const consumed = await database.query(
		'DELETE FROM "deviceCode" WHERE id=$1 AND "oauthClientId"=$2 AND "userId"=$3 AND status=\'approved\'',
		[row.id, authClient.clientId, row.userId],
	);
	if (consumed.rowCount !== 1)
		throw new Error("The locked device grant was not consumed.");
	return result;
}

/** OAuth device initiation and signed-browser review over the native realm table. */
export function createOwnedProjectIssuerDevice(
	options: OwnedProjectIssuerDeviceOptions,
) {
	const store =
		options.store ??
		createProjectEngineStore(options.database, options.schemaName);
	const platform = projectOrigin.parse(options.platformOrigin);
	const origin = new URL(options.issuer).origin;
	const endpointBase = options.endpointBase ?? options.issuer;
	const sharedIssuer =
		options.endpointBase !== undefined && options.projectSlug === undefined;
	const browserOrigins = new Set([
		origin,
		...(options.trustedOrigins?.map((value) => projectOrigin.parse(value)) ??
			[]),
	]);
	const verificationURL = new URL("/device", platform);
	if (options.projectSlug !== undefined || options.endpointBase === undefined)
		verificationURL.searchParams.set(
			"project",
			projectSlug.parse(options.projectSlug),
		);
	const authenticateClient =
		options.authenticateClient ??
		createIssuerClientAuthenticator(options.issuer, browserOrigins);

	function formEncoded(request: Request) {
		return (
			request.headers
				.get("content-type")
				?.split(";", 1)[0]
				?.trim()
				.toLowerCase() === "application/x-www-form-urlencoded"
		);
	}

	async function initiationForm(
		request: Request,
		prepared?: PreparedIssuerDeviceBody,
	) {
		if (formEncoded(request)) {
			if (!prepared) return issuerForm(request);
			if (!(prepared.body instanceof URLSearchParams))
				throw new ProjectOAuthError(
					"invalid_request",
					"Supply a form-encoded OAuth request.",
				);
			return issuerFormParameters(prepared.body);
		}
		const parsed = initiationInput.safeParse(
			prepared ? prepared.body : await options.readBody(request),
		);
		if (!parsed.success) {
			if (parsed.error.issues.every(({ path }) => path[0] === "resource"))
				throw new ProjectOAuthError(
					"invalid_target",
					"Invalid resource indicator",
				);
			throw new ProjectOAuthError(
				"invalid_request",
				"Invalid device authorization request",
			);
		}
		const { resource, ...fields } = parsed.data;
		const form = new URLSearchParams();
		for (const [key, value] of Object.entries(fields))
			if (value) form.set(key, value);
		for (const value of Array.isArray(resource)
			? resource
			: resource
				? [resource]
				: [])
			form.append("resource", value);
		return form;
	}

	async function rejectStandaloneToken(request: Request) {
		const body = formEncoded(request)
			? Object.fromEntries(await issuerForm(request))
			: await options.readBody(request);
		const parsed = standaloneTokenInput.safeParse(body);
		if (!parsed.success)
			throw new ProjectOAuthError(
				"invalid_request",
				"Invalid device token request",
			);
		const { device_code, client_id } = parsed.data;
		return store.transaction(async (database) => {
			const {
				rows: [row],
			} = await database.query<Pick<DeviceRow, "clientId" | "oauthClientId">>(
				'SELECT "clientId","oauthClientId" FROM "deviceCode" WHERE "deviceCode"=$1',
				[device_code],
			);
			if (row?.clientId && row.clientId !== client_id)
				return invalidGrant("Client ID mismatch").response();
			// Only the shared platform issuer allows standalone MCP device sessions.
			if (typeof row?.oauthClientId === "string")
				return invalidGrant(
					"This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
				).response();
			return invalidGrant().response();
		});
	}

	async function create(request: Request, prepared?: PreparedIssuerDeviceBody) {
		const form = await initiationForm(request, prepared);
		return store.transaction(async (database) => {
			const bodyId = form.get("client_id");
			const hasCredentials =
				request.headers.has("authorization") ||
				["client_secret", "client_assertion", "client_assertion_type"].some(
					(key) => form.has(key),
				);
			if (!bodyId && !hasCredentials)
				throw new ProjectOAuthError("invalid_request", "client_id is required");
			if (
				bodyId &&
				!hasCredentials &&
				!(await readIssuerClient(database, bodyId))
			)
				throw new ProjectOAuthError("invalid_client", "Invalid client ID");
			const client = await authenticateClient(database, request, form, true);
			try {
				requireDeviceClient(client);
				const scopes = deviceScopes(form.get("scope"), client);
				const resources = formResources(form);
				await issuerResourcePolicy(
					database,
					client,
					resources,
					scopes,
					`${endpointBase}/oauth2/userinfo`,
				);
				const userId = form.get("user_id") || null;
				if (userId && userId.length > 256)
					throw new ProjectOAuthError("invalid_request", "Invalid user_id");
				for (let attempt = 0; attempt < 3; attempt++) {
					const deviceCode = randomCode(deviceAlphabet, 40);
					const userCode = randomCode(userAlphabet, 8);
					const created = await database.query(
						`INSERT INTO "deviceCode"(id,"deviceCode","userCode","userId","expiresAt",status,"pollingInterval","clientId",scope,resources,"oauthClientId")
						 VALUES($1,$2,$3,$4,clock_timestamp() + $5::integer * interval '1 second','pending',$6,$7,$8,$9,$7) ON CONFLICT DO NOTHING`,
						[
							randomUUID(),
							deviceCode,
							userCode,
							userId,
							expirySeconds,
							intervalSeconds * 1000,
							client.clientId,
							form.get("scope") ? scopes.join(" ") : null,
							resources.length ? JSON.stringify(resources) : null,
						],
					);
					if (created.rowCount !== 1) continue;
					const complete = new URL(verificationURL.href);
					complete.searchParams.set("user_code", userCode);
					return issuerJSON({
						device_code: deviceCode,
						user_code: userCode,
						verification_uri: verificationURL.href,
						verification_uri_complete: complete.href,
						expires_in: expirySeconds,
						interval: intervalSeconds,
					});
				}
				throw new ProjectOAuthError(
					"server_error",
					"Failed to generate a unique device code",
					500,
				);
			} catch (error) {
				if (error instanceof ProjectOAuthError) return error.response();
				throw error;
			}
		});
	}

	async function browser(
		request: Request,
		userCode: string,
		decision?: "approve" | "deny",
	) {
		const caller = request.headers.get("origin");
		if (
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			(caller !== null && !browserOrigins.has(caller)) ||
			(decision && caller === null)
		)
			throw new ProjectOAuthError(
				"access_denied",
				"Use your signed-in browser session for this action.",
				403,
			);
		return store.transaction(async (database) => {
			const current = await options.readSession(request, database);
			const denied = () =>
				new ProjectOAuthError(
					"access_denied",
					"Sign in again with a verified account before approving access.",
					403,
				);
			if (
				!current ||
				current.session.userId !== current.user.id ||
				current.session.impersonatedBy
			)
				throw denied();
			const user = await store.lockUser(database, current.user.id);
			const { rows: sessions } = await database.query<{
				createdAt: Date;
				expiresAt: Date;
				impersonatedBy: string | null;
			}>(
				`SELECT "createdAt","expiresAt","impersonatedBy" FROM "session" WHERE id=$1 AND "userId"=$2 FOR SHARE`,
				[current.session.id, current.user.id],
			);
			const session = sessions[0];
			if (
				!user ||
				user.directoryDisabled ||
				user.isAnonymous ||
				!session ||
				!freshFeatureSession({ user, session })
			)
				throw denied();
			try {
				const candidates = deviceUserCodeCandidates(userCode);
				if (!candidates)
					throw new ProjectOAuthError("invalid_request", "Invalid user code");
				const {
					rows: [row],
				} = await database.query<DeviceRow>(
					`SELECT ${codeColumns} FROM "deviceCode" WHERE "userCode"=ANY($1::text[])
					 ORDER BY ("userCode"=$2) DESC LIMIT 1 FOR UPDATE`,
					[candidates, userCode],
				);
				if (!row || (sharedIssuer && !row.oauthClientId))
					throw new ProjectOAuthError("invalid_request", "Invalid user code");
				if (row.expiresAt.getTime() <= Date.now())
					throw new ProjectOAuthError("expired_token", "User code has expired");
				if (decision) {
					if (row.status !== "pending")
						throw new ProjectOAuthError(
							"invalid_request",
							"Device code already processed",
						);
					if (!row.userId)
						throw new ProjectOAuthError(
							"invalid_request",
							"Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying",
						);
					if (row.userId !== user.id)
						throw new ProjectOAuthError(
							"access_denied",
							`You are not authorized to ${decision} this device authorization`,
							403,
						);
					await database.query(
						'UPDATE "deviceCode" SET status=$1 WHERE id=$2',
						[decision === "approve" ? "approved" : "denied", row.id],
					);
					return issuerJSON({ success: true });
				}
				if (!row.userId && row.status === "pending") {
					await database.query(
						'UPDATE "deviceCode" SET "userId"=$1 WHERE id=$2',
						[user.id, row.id],
					);
					row.userId = user.id;
				}
				if (row.userId !== user.id)
					return issuerJSON({ user_code: userCode, status: row.status });
				const resources =
					row.oauthClientId && row.resources ? resourceList(row.resources) : [];
				return issuerJSON({
					user_code: userCode,
					status: row.status,
					client_id: row.clientId,
					scope: row.scope,
					resource: resources.length > 1 ? resources : resources[0],
				});
			} catch (error) {
				if (error instanceof ProjectOAuthError) return error.response();
				throw error;
			}
		});
	}

	return async function dispatch(
		path: string,
		request: Request,
		prepared?: PreparedIssuerDeviceBody,
	) {
		if (
			path !== "/device/code" &&
			path !== "/device/token" &&
			path !== "/device" &&
			path !== "/device/approve" &&
			path !== "/device/deny"
		)
			return;
		const url = new URL(request.url);
		if (
			url.origin + url.pathname !== `${endpointBase}${path}` ||
			request.method !== (path === "/device" ? "GET" : "POST")
		)
			return new ProjectOAuthError(
				"invalid_request",
				"Invalid device authorization endpoint.",
				404,
			).response();
		try {
			const rule =
				path === "/device"
					? { max: 5, windowMs: expirySeconds * 1000 }
					: { max: 100, windowMs: 60_000 };
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(
					client,
					options.trustedIP(request),
					path,
					rule,
				),
			);
			if (limited) return limited;
			if (path === "/device/code") return await create(request, prepared);
			if (path === "/device/token") return await rejectStandaloneToken(request);
			if (path === "/device") {
				const codes = url.searchParams.getAll("user_code");
				if (codes.length !== 1)
					throw new ProjectOAuthError(
						"invalid_request",
						"user_code is required",
					);
				return await browser(request, codes[0]!);
			}
			const parsed = browserInput.safeParse(
				prepared ? prepared.body : await options.readBody(request),
			);
			if (!parsed.success)
				throw new ProjectOAuthError("invalid_request", "Invalid user code");
			return await browser(
				request,
				parsed.data.userCode,
				path === "/device/approve" ? "approve" : "deny",
			);
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	};
}
