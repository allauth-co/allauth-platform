import { createLocalJWKSet, jwtVerify } from "jose";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type {
	IssuerClientAuthenticator,
	ProjectIssuerClient,
} from "./owned-project-issuer-client";
import {
	createIssuerClientAuthenticator,
	readIssuerClient,
} from "./owned-project-issuer-client";
import {
	issuerDigest,
	issuerForm,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import { issuerObject } from "./owned-project-issuer-resources";
import {
	revokeIssuerOpaqueAccess,
	revokeIssuerRefresh,
} from "./owned-project-issuer-revoke";

const maxTokenLength = 16 * 1024;
const maxAudiences = 64;
const nonempty = z.string().min(1).max(2048);
const claimStrings = z.array(nonempty).max(128);
const jwt = z.looseObject({
	sub: nonempty,
	azp: nonempty,
	client_id: nonempty.optional(),
	iss: nonempty,
	aud: z.union([nonempty, z.array(nonempty).min(1).max(maxAudiences)]),
	sid: nonempty.optional(),
	scope: z.string().max(8192),
	iat: z.number().int().nonnegative(),
	exp: z.number().int().nonnegative(),
	cnf: z.record(z.string(), z.unknown()).optional(),
});
const reserved = new Set([
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"jti",
	"sid",
	"azp",
	"client_id",
	"scope",
	"cnf",
	"act",
	"active",
	"token_type",
	"auth_time",
	"acr",
	"amr",
	"__proto__",
	"constructor",
	"prototype",
]);

type IssuerTokenRecord = {
	id: string;
	clientId: string;
	userId: string | null;
	sessionId: string | null;
	referenceId: string | null;
	resources: unknown;
	scopes: unknown;
	confirmation: unknown;
	requestedUserInfoClaims: unknown;
	expiresAt: Date;
	createdAt: Date;
	revoked: Date | null;
};
type IssuerResource = {
	identifier: string;
	customClaims: unknown;
	linked: boolean;
};

export type ActiveProjectIssuerAccess = {
	payload: Record<string, unknown> & {
		active: true;
		iss: string;
		client_id: string;
		azp: string;
		sub?: string;
		sid?: string;
		aud?: string | string[];
		scope: string;
		cnf?: Record<string, unknown>;
		token_type: "Bearer" | "DPoP";
	};
	userId?: string;
	requestedUserInfoClaims: string[];
};

function tokenType(confirmation: Record<string, unknown> | undefined) {
	return typeof confirmation?.jkt === "string" && confirmation.jkt
		? "DPoP"
		: "Bearer";
}

function tokenRecord(form: URLSearchParams) {
	const token = form
		.get("token")
		?.trim()
		.replace(/^(?:Bearer|DPoP)\s+/i, "");
	if (!token || token.length > maxTokenLength)
		throw new ProjectOAuthError(
			"invalid_request",
			"missing a required token for introspection",
		);
	return token;
}

function isCompactJwt(token: string) {
	return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
}

async function activeUser(database: PoolClient, userId: string) {
	return Boolean(
		(
			await database.query(
				`SELECT 1 FROM "user" WHERE id=$1 AND banned IS DISTINCT FROM TRUE AND "directoryDisabled" IS DISTINCT FROM TRUE FOR SHARE`,
				[userId],
			)
		).rowCount,
	);
}

async function activeSession(
	database: PoolClient,
	sessionId: string,
	userId: string,
) {
	return Boolean(
		(
			await database.query(
				`SELECT 1 FROM "session" WHERE id=$1 AND "userId"=$2 AND "expiresAt" > clock_timestamp() FOR SHARE`,
				[sessionId, userId],
			)
		).rowCount,
	);
}

async function organizationClaims(
	database: PoolClient,
	origin: string,
	owner: ProjectIssuerClient,
	row: IssuerTokenRecord,
	scopes: string[],
	resources: string[],
) {
	if (!row.userId || !row.referenceId || !scopes.includes("organization:read"))
		return {};
	const config = issuerObject(owner.metadata);
	if (
		!Array.isArray(config.allauthOrganizationIds) ||
		!config.allauthOrganizationIds.includes(row.referenceId) ||
		resources.length !== 1 ||
		resources[0] !== config.allauthResourceURI
	)
		return null;
	const { rows } = await database.query<{ role: string }>(
		'SELECT role FROM "member" WHERE "organizationId"=$1 AND "userId"=$2 FOR SHARE',
		[row.referenceId, row.userId],
	);
	return rows[0]
		? {
				[`${origin}/organization_id`]: row.referenceId,
				[`${origin}/organization_role`]: rows[0].role,
			}
		: null;
}

function emptyRevocation() {
	return new Response(null, {
		status: 200,
		headers: { "cache-control": "no-store", pragma: "no-cache" },
	});
}

/** Introspection and revocation over the project's existing OAuth grant rows and signing keys. */
export function createOwnedProjectIssuerIntrospection(options: {
	database: Pool;
	schemaName: string;
	issuer: string;
	keys: LegacyMfaKeys;
	authenticateClient?: IssuerClientAuthenticator;
}) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	const keyring = createOwnedProjectIssuerKeys(options);
	const origin = new URL(options.issuer).origin;
	const userinfo = `${options.issuer}/oauth2/userinfo`;
	const authenticateClient =
		options.authenticateClient ??
		createIssuerClientAuthenticator(options.issuer);

	async function existingResources(
		database: PoolClient,
		audiences: string[],
		callerId?: string,
	) {
		const targets = [
			...new Set(audiences.filter((value) => value !== userinfo)),
		];
		const { rows } = await database.query<IssuerResource>(
			`SELECT r.identifier,r."customClaims",EXISTS(SELECT 1 FROM "oauthClientResource" link
			 WHERE link."clientId"=$2 AND link."resourceId"=r.identifier) AS linked
			 FROM "oauthResource" r WHERE r.identifier=ANY($1::text[]) FOR SHARE OF r`,
			[targets, callerId ?? null],
		);
		// Disabled resources stop issuance. Deletion invalidates existing access.
		return rows.length === targets.length
			? new Map(rows.map((row) => [row.identifier, row]))
			: null;
	}

	async function accessJWT(
		database: PoolClient,
		token: string,
		callerId?: string,
	): Promise<ActiveProjectIssuerAccess | null> {
		const keys = await keyring.existingPublicKeys(database);
		if (!keys.keys.length) return null;
		let claims: z.infer<typeof jwt>;
		try {
			const { payload } = await jwtVerify(token, createLocalJWKSet(keys), {
				issuer: options.issuer,
				typ: "at+jwt",
				requiredClaims: ["sub", "iat", "exp", "aud"],
			});
			claims = jwt.parse(payload);
		} catch {
			return null;
		}
		const now = Math.floor(Date.now() / 1000);
		if (
			(claims.client_id && claims.client_id !== claims.azp) ||
			claims.iat > now + 5 ||
			claims.exp <= claims.iat
		)
			return null;
		const owner = await readIssuerClient(database, claims.azp);
		if (!owner || owner.disabled) return null;
		const resources = await existingResources(
			database,
			typeof claims.aud === "string" ? [claims.aud] : claims.aud,
			callerId,
		);
		if (
			!resources ||
			(callerId &&
				callerId !== owner.clientId &&
				![...resources.values()].some((row) => row.linked))
		)
			return null;
		const userId =
			claims.sid || claims.sub !== owner.clientId ? claims.sub : undefined;
		if (userId && !(await activeUser(database, userId))) return null;
		if (
			claims.sid &&
			(!userId || !(await activeSession(database, claims.sid, userId)))
		)
			return null;
		return {
			payload: {
				...claims,
				client_id: owner.clientId,
				active: true,
				token_type: tokenType(claims.cnf),
			},
			userId,
			requestedUserInfoClaims: [],
		};
	}

	async function readStored(
		database: PoolClient,
		kind: "oauthAccessToken" | "oauthRefreshToken",
		digest: string,
		ownerId?: string,
		lock = false,
	) {
		const { rows } = await database.query<IssuerTokenRecord>(
			`SELECT id,"clientId","userId","sessionId","referenceId",resources,scopes,confirmation,"requestedUserInfoClaims","expiresAt","createdAt",revoked
			 FROM "${kind}" WHERE token=$1 AND ($2::text IS NULL OR "clientId"=$2)${lock ? " FOR SHARE" : ""}`,
			[digest, ownerId ?? null],
		);
		const row = rows[0];
		return row && !row.revoked && row.expiresAt.getTime() > Date.now()
			? row
			: null;
	}

	async function opaqueAccess(
		database: PoolClient,
		token: string,
		callerId?: string,
	): Promise<ActiveProjectIssuerAccess | null> {
		const digest = issuerDigest(token);
		const row = await readStored(database, "oauthAccessToken", digest);
		if (!row) return null;
		const owner = await readIssuerClient(database, row.clientId);
		if (!owner || owner.disabled) return null;
		const audiences = claimStrings
			.max(maxAudiences)
			.safeParse(row.resources ?? []);
		const scopes = claimStrings.safeParse(row.scopes ?? []);
		if (!audiences.success || !scopes.success) return null;
		const resources = await existingResources(
			database,
			audiences.data,
			callerId,
		);
		if (
			!resources ||
			(callerId &&
				callerId !== owner.clientId &&
				![...resources.values()].some((value) => value.linked))
		)
			return null;
		if (row.userId && !(await activeUser(database, row.userId))) return null;
		if (
			row.sessionId &&
			(!row.userId ||
				!(await activeSession(database, row.sessionId, row.userId)))
		)
			return null;
		// Session/user authority is locked before the token to match revocation.
		const current = await readStored(
			database,
			"oauthAccessToken",
			digest,
			row.clientId,
			true,
		);
		if (
			current?.id !== row.id ||
			current.sessionId !== row.sessionId ||
			current.userId !== row.userId
		)
			return null;
		const profile = await organizationClaims(
			database,
			origin,
			owner,
			row,
			scopes.data,
			audiences.data,
		);
		if (!profile) return null;
		const extra: Record<string, unknown> = Object.create(null);
		for (const resource of audiences.data) {
			for (const [key, value] of Object.entries(
				issuerObject(resources.get(resource)?.customClaims),
			)) {
				if (!reserved.has(key)) extra[key] = value;
			}
		}
		const audience = [...new Set(audiences.data)];
		if (
			audience.length &&
			scopes.data.includes("openid") &&
			!audience.includes(userinfo)
		)
			audience.push(userinfo);
		const confirmation = row.confirmation
			? issuerObject(row.confirmation)
			: undefined;
		return {
			payload: {
				...extra,
				...profile,
				active: true,
				iss: options.issuer,
				aud: audience.length > 1 ? audience : audience[0],
				client_id: row.clientId,
				azp: row.clientId,
				sub: row.userId ?? undefined,
				sid: row.sessionId ?? undefined,
				exp: Math.floor(row.expiresAt.getTime() / 1000),
				iat: Math.floor(row.createdAt.getTime() / 1000),
				scope: scopes.data.join(" "),
				token_type: tokenType(confirmation),
				cnf: confirmation,
			},
			userId: row.userId ?? undefined,
			requestedUserInfoClaims:
				claimStrings.safeParse(row.requestedUserInfoClaims).data ?? [],
		};
	}

	/** Resolve access validity inside an existing realm transaction. UserInfo can additionally enforce DPoP and its own audience. */
	async function activeAccess(
		database: PoolClient,
		token: string,
		callerId?: string,
	) {
		if (!token || token.length > maxTokenLength) return null;
		return isCompactJwt(token)
			? accessJWT(database, token, callerId)
			: opaqueAccess(database, token, callerId);
	}

	async function activeRefresh(
		database: PoolClient,
		digest: string,
		ownerId: string,
	) {
		const row = await readStored(
			database,
			"oauthRefreshToken",
			digest,
			ownerId,
		);
		if (!row?.userId || !(await activeUser(database, row.userId))) return null;
		const scopes = claimStrings.safeParse(row.scopes ?? []);
		if (!scopes.success) return null;
		const sid =
			row.sessionId &&
			(await activeSession(database, row.sessionId, row.userId))
				? row.sessionId
				: undefined;
		const current = await readStored(
			database,
			"oauthRefreshToken",
			digest,
			ownerId,
			true,
		);
		if (
			current?.id !== row.id ||
			current.userId !== row.userId ||
			current.sessionId !== row.sessionId
		)
			return null;
		const confirmation = row.confirmation
			? issuerObject(row.confirmation)
			: undefined;
		return {
			active: true,
			client_id: row.clientId,
			iss: options.issuer,
			sub: row.userId,
			sid,
			exp: Math.floor(row.expiresAt.getTime() / 1000),
			iat: Math.floor(row.createdAt.getTime() / 1000),
			scope: scopes.data.join(" "),
			token_type: tokenType(confirmation),
			cnf: confirmation,
		};
	}

	async function revokeToken(
		database: PoolClient,
		token: string,
		callerId: string,
	) {
		if (isCompactJwt(token)) {
			const active = await accessJWT(database, token, callerId);
			if (active?.payload.client_id === callerId)
				return new ProjectOAuthError(
					"unsupported_token_type",
					"JWT access tokens are self-contained and cannot be revoked server-side",
				).response();
		} else {
			const digest = issuerDigest(token);
			if (!(await revokeIssuerOpaqueAccess(database, digest, callerId)))
				await revokeIssuerRefresh(database, digest, callerId);
		}
		return emptyRevocation();
	}

	async function dispatch(
		request: Request,
		operation: "introspect" | "revoke",
	) {
		const url = new URL(request.url);
		if (
			request.method !== "POST" ||
			url.origin + url.pathname !== `${options.issuer}/oauth2/${operation}`
		)
			return new ProjectOAuthError(
				"invalid_request",
				"Invalid OAuth endpoint.",
				404,
			).response();
		try {
			const form = await issuerForm(request);
			return await store.transaction(async (database) => {
				const caller = await authenticateClient(
					database,
					request,
					form,
					operation === "revoke",
				);
				try {
					const token = tokenRecord(form);
					if (operation === "revoke")
						return await revokeToken(database, token, caller.clientId);
					// The issuer can identify its compact JWTs and look up both opaque kinds
					// without relying on the client's optional type hint.
					const access = await activeAccess(database, token, caller.clientId);
					const refresh =
						!access &&
						!isCompactJwt(token) &&
						(await activeRefresh(
							database,
							issuerDigest(token),
							caller.clientId,
						));
					return issuerJSON(access?.payload || refresh || { active: false });
				} catch (error) {
					if (error instanceof ProjectOAuthError) return error.response();
					throw error;
				}
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	}

	return {
		activeAccess,
		introspect: (request: Request) => dispatch(request, "introspect"),
		revoke: (request: Request) => dispatch(request, "revoke"),
	};
}
