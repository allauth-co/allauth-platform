import type { PoolClient } from "pg";
import * as z from "zod";
import { isPlatformAdmin } from "../configuration";
import type {
	createProjectEngineStore,
	ProjectUser,
} from "./owned-project-engine-store";
import { readSignedProjectIssuerQuery } from "./owned-project-issuer-authorization-query";
import { issuerJSON, ProjectOAuthError } from "./owned-project-issuer-http";

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

/** Keep project client details scoped to the authenticated realm and redact stored client secrets. */
export function createOwnedProjectIssuerClients(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	signingSecret: string;
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
		if (!list && !privateRead && !publicRead && !prelogin && !remove) return;
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
		const parsed = list ? null : clientInput.safeParse(input);
		if (parsed && !parsed.success) return invalid();
		return options.store.transaction(async (client) => {
			const user = prelogin
				? null
				: await options.readManagementUser(client, request, remove);
			if (!prelogin && (!user || (!publicRead && !isPlatformAdmin(user))))
				return unauthorized();
			if (list) {
				const { rows } = await client.query(
					`SELECT ${clientSelect},scopes,"createdAt",jwks,metadata,"clientSecret" IS NOT NULL AS "hasSecret"
					 FROM "oauthClient" WHERE "referenceId"=$1`,
					[reference],
				);
				return issuerJSON(rows.map(clientResult));
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
			const {
				rows: [row],
			} = await client.query(
				`SELECT ${clientSelect},scopes,"createdAt",jwks,metadata,"clientSecret" IS NOT NULL AS "hasSecret"
				 FROM "oauthClient" WHERE "clientId"=$1 AND "clientDiscoveryId" IS NULL${remove ? " FOR UPDATE" : ""}`,
				[id],
			);
			if (!row) return missing();
			if (row.userId ? row.userId !== user?.id : row.referenceId !== reference)
				return unauthorized();
			if (remove) {
				await client.query('DELETE FROM "oauthClient" WHERE "clientId"=$1', [
					id,
				]);
				return new Response(null, {
					headers: { "cache-control": "no-store", pragma: "no-cache" },
				});
			}
			return issuerJSON(clientResult(row));
		});
	};
}
