import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { isPlatformAdmin } from "../configuration";
import type {
	createProjectEngineStore,
	ProjectUser,
} from "./owned-project-engine-store";
import { readSignedProjectIssuerQuery } from "./owned-project-issuer-authorization-query";
import {
	createProjectIssuerClient,
	projectIssuerClientCredential,
	projectIssuerClientUpdate,
	updateProjectIssuerClient,
} from "./owned-project-issuer-client-writes";
import {
	issuerDigest,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";

const clientInput = z.object({ client_id: z.string().min(1).max(2048) });
const publicInput = clientInput.extend({
	oauth_query: z.string().min(1).max(16384),
});
const publicFields = {
	clientId: "client_id",
	name: "client_name",
	uri: "client_uri",
	icon: "logo_uri",
	contacts: "contacts",
	tos: "tos_uri",
	policy: "policy_uri",
};
const clientFields = {
	...publicFields,
	userId: "user_id",
	softwareId: "software_id",
	softwareVersion: "software_version",
	softwareStatement: "software_statement",
	redirectUris: "redirect_uris",
	postLogoutRedirectUris: "post_logout_redirect_uris",
	backchannelLogoutUri: "backchannel_logout_uri",
	backchannelLogoutSessionRequired: "backchannel_logout_session_required",
	tokenEndpointAuthMethod: "token_endpoint_auth_method",
	grantTypes: "grant_types",
	responseTypes: "response_types",
	applicationType: "application_type",
	jwksUri: "jwks_uri",
	disabled: "disabled",
	skipConsent: "skip_consent",
	enableEndSession: "enable_end_session",
	requirePKCE: "require_pkce",
	dpopBoundAccessTokens: "dpop_bound_access_tokens",
	subjectType: "subject_type",
	referenceId: "reference_id",
};
const reservedFields = new Set([
	...Object.keys(clientFields),
	...Object.values(clientFields),
	"id",
	"clientSecret",
	"client_secret",
	"clientDiscoveryId",
	"client_discovery_id",
	"clientCredentialsScopes",
	"client_credentials_scopes",
	"jwks",
	"metadata",
	"scopes",
	"scope",
	"createdAt",
	"updatedAt",
	"expiresAt",
	"client_id_issued_at",
	"client_secret_expires_at",
]);
const publicSelect = Object.keys(publicFields)
	.map((key) => `"${key}"`)
	.join(",");
const clientSelect = Object.keys(clientFields)
	.map((key) => `"${key}"`)
	.join(",");
const reference = "allauth:platform";
const privateSelect = `${clientSelect},scopes,"createdAt",jwks,metadata,"clientSecret" IS NOT NULL AS "hasSecret"`;
const unauthorized = () =>
	Response.json(
		{ code: "UNAUTHORIZED", message: "Unauthorized" },
		{
			status: 401,
			headers: { "cache-control": "no-store", pragma: "no-cache" },
		},
	);
const missing = () =>
	new ProjectOAuthError("not_found", "client not found", 404).response();
const invalid = () =>
	new ProjectOAuthError(
		"invalid_request",
		"Invalid client request.",
	).response();

function mapped(row: Record<string, unknown>, fields: Record<string, string>) {
	return Object.fromEntries(
		Object.entries(fields)
			.filter(([name]) => row[name] !== null && row[name] !== undefined)
			.map(([name, key]) => [key, row[name]]),
	);
}

function clientResult(row: Record<string, unknown>) {
	const metadata =
		row.metadata &&
		typeof row.metadata === "object" &&
		!Array.isArray(row.metadata)
			? Object.fromEntries(
					Object.entries(row.metadata).filter(
						([name]) => !reservedFields.has(name),
					),
				)
			: {};
	const issued =
		row.createdAt instanceof Date
			? Math.round(row.createdAt.getTime() / 1000)
			: undefined;
	const scopes = Array.isArray(row.scopes) ? row.scopes.join(" ") : undefined;
	return {
		...metadata,
		redirect_uris: [],
		...mapped(row, clientFields),
		client_id_issued_at: issued,
		client_secret_expires_at: row.hasSecret ? 0 : undefined,
		scope: scopes,
		jwks: typeof row.jwks === "string" ? JSON.parse(row.jwks) : undefined,
	};
}

async function readClient(client: PoolClient, clientId: string, lock = false) {
	const {
		rows: [row],
	} = await client.query(
		`SELECT ${privateSelect} FROM "oauthClient" WHERE "clientId"=$1 AND "clientDiscoveryId" IS NULL${lock ? " FOR UPDATE" : ""}`,
		[clientId],
	);
	return row;
}

async function auditClient(
	client: PoolClient,
	path: string,
	userId: string,
	clientId: string,
) {
	await client.query(
		`INSERT INTO "allauthAudit" (id,"actorId",action,"targetId","createdAt")
		 VALUES ($1,$2,$3,$4,statement_timestamp())`,
		[randomUUID(), userId, path, clientId],
	);
}

/** Keep project client details scoped to the authenticated realm and redact stored client secrets. */
export function createOwnedProjectIssuerClients(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	signingSecret: string;
	trustedOrigins: ReadonlySet<string>;
	readBody(request: Request): Promise<unknown>;
	readManagementUser(
		client: PoolClient,
		request: Request,
		write: boolean,
	): Promise<ProjectUser | null>;
}) {
	return async (path: string, request: Request) => {
		const get = request.method === "GET";
		const post = request.method === "POST";
		const list = get && path === "/oauth2/get-clients";
		const privateRead = get && path === "/oauth2/get-client";
		const publicRead = get && path === "/oauth2/public-client";
		const prelogin = post && path === "/oauth2/public-client-prelogin";
		const remove = post && path === "/oauth2/delete-client";
		const rotate = post && path === "/oauth2/client/rotate-secret";
		const create = post && path === "/oauth2/create-client";
		const update = post && path === "/oauth2/update-client";
		const write = remove || rotate || create || update;
		if (!list && !privateRead && !publicRead && !prelogin && !write) return;
		const input = post
			? await options.readBody(request)
			: {
					client_id: new URL(request.url).searchParams.get("client_id"),
				};
		if (prelogin) {
			const parsed = publicInput.safeParse(input);
			const signed =
				parsed.success &&
				readSignedProjectIssuerQuery(
					parsed.data.oauth_query,
					options.signingSecret,
				);
			if (
				!parsed.success ||
				!signed ||
				signed.params.get("client_id") !== parsed.data.client_id
			)
				return new ProjectOAuthError(
					"invalid_signature",
					"The authorization request is unavailable.",
					401,
				).response();
		}
		const changes = update ? projectIssuerClientUpdate.safeParse(input) : null;
		const parsed =
			list || create ? null : (changes ?? clientInput.safeParse(input));
		if (parsed && !parsed.success) return invalid();
		try {
			return await options.store.transaction(async (client) => {
				const user = prelogin
					? null
					: await options.readManagementUser(client, request, write);
				if (!prelogin && (!user || (!publicRead && !isPlatformAdmin(user))))
					return unauthorized();
				if (list) {
					const { rows } = await client.query(
						`SELECT ${privateSelect} FROM "oauthClient" WHERE "referenceId"=$1`,
						[reference],
					);
					return issuerJSON(rows.map(clientResult));
				}
				if (create && user) {
					const created = await createProjectIssuerClient(
						client,
						input,
						options.trustedOrigins,
						reference,
					);
					const row = await readClient(client, created.clientId);
					if (!row) throw new Error("The project client was not registered.");
					await auditClient(client, path, user.id, created.clientId);
					return issuerJSON(
						{ ...clientResult(row), client_secret: created.secret },
						201,
					);
				}
				const id = parsed?.data?.client_id;
				if (!id) return invalid();
				if (publicRead || prelogin) {
					const {
						rows: [row],
					} = await client.query(
						`SELECT ${publicSelect} FROM "oauthClient" WHERE "clientId"=$1 AND "clientDiscoveryId" IS NULL AND disabled IS DISTINCT FROM TRUE`,
						[id],
					);
					return row
						? issuerJSON({ ...mapped(row, publicFields), redirect_uris: [] })
						: missing();
				}
				const row = await readClient(client, id, write);
				if (!row) return missing();
				if (
					row.userId ? row.userId !== user?.id : row.referenceId !== reference
				)
					return unauthorized();
				if (remove) {
					await client.query('DELETE FROM "oauthClient" WHERE "clientId"=$1', [
						id,
					]);
					return new Response(null, {
						headers: { "cache-control": "no-store", pragma: "no-cache" },
					});
				}
				if (rotate) {
					if (
						!row.hasSecret ||
						!["client_secret_basic", "client_secret_post"].some(
							(method) => method === row.tokenEndpointAuthMethod,
						)
					)
						return new ProjectOAuthError(
							"invalid_client",
							"secret rotation is only available for clients using client_secret authentication",
						).response();
					const secret = projectIssuerClientCredential();
					await client.query(
						`UPDATE "oauthClient" SET "clientSecret"=$2,"updatedAt"=date_trunc('second',statement_timestamp()) WHERE "clientId"=$1`,
						[id, issuerDigest(secret)],
					);
					return issuerJSON({ ...clientResult(row), client_secret: secret });
				}
				if (update && changes?.success && user) {
					await updateProjectIssuerClient(
						client,
						id,
						changes.data.update,
						clientResult(row),
						options.trustedOrigins,
					);
					const saved = await readClient(client, id);
					if (!saved) throw new Error("The project client was not updated.");
					await auditClient(client, path, user.id, id);
					return issuerJSON(clientResult(saved));
				}
				return issuerJSON(clientResult(row));
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	};
}
