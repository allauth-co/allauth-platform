import { randomInt, randomUUID } from "node:crypto";
import { type JWK, importJWK } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { validateRedirectUris } from "../configuration";
import { publicProjectHttpsURL } from "./owned-project-https";
import { issuerAssertionAlgorithms } from "./owned-project-issuer-client";
import { issuerDigest, ProjectOAuthError } from "./owned-project-issuer-http";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const grantType = z.enum(["authorization_code", "refresh_token", deviceGrant]);
const authentication = z.enum([
	"none",
	"client_secret_basic",
	"client_secret_post",
	"private_key_jwt",
]);
const text = z.string().max(2048);
const urls = z.array(text).min(1).max(20);
const publicKey = z.looseObject({ kty: z.enum(["RSA", "EC", "OKP"]) });
const client = z.object({
	redirect_uris: urls.optional(),
	scope: z.string().max(2048).optional(),
	client_name: text.optional(),
	client_uri: text.optional(),
	logo_uri: text.optional(),
	contacts: z.array(z.string().min(1).max(320)).min(1).max(20).optional(),
	tos_uri: text.optional(),
	policy_uri: text.optional(),
	software_id: text.optional(),
	software_version: text.optional(),
	software_statement: z.string().max(8192).optional(),
	post_logout_redirect_uris: urls.optional(),
	backchannel_logout_uri: text.optional(),
	backchannel_logout_session_required: z.boolean().optional(),
	token_endpoint_auth_method: authentication.optional(),
	application_type: z.enum(["web", "native"]).optional(),
	jwks: z.object({ keys: z.array(publicKey).min(1).max(30) }).optional(),
	jwks_uri: text.optional(),
	grant_types: z.array(grantType).min(1).max(3).optional(),
	response_types: z.array(z.literal("code")).optional(),
	dpop_bound_access_tokens: z.boolean().optional(),
	require_pkce: z.literal(true).optional(),
});

export const projectIssuerClientUpdate = z.object({
	client_id: z.string().min(1).max(256),
	update: client.omit({
		token_endpoint_auth_method: true,
		jwks: true,
		jwks_uri: true,
		dpop_bound_access_tokens: true,
	}),
});
type Client = z.infer<typeof client>;

const fields = {
	redirect_uris: "redirectUris",
	scope: "scopes",
	client_name: "name",
	client_uri: "uri",
	logo_uri: "icon",
	contacts: "contacts",
	tos_uri: "tos",
	policy_uri: "policy",
	software_id: "softwareId",
	software_version: "softwareVersion",
	software_statement: "softwareStatement",
	post_logout_redirect_uris: "postLogoutRedirectUris",
	backchannel_logout_uri: "backchannelLogoutUri",
	backchannel_logout_session_required: "backchannelLogoutSessionRequired",
	token_endpoint_auth_method: "tokenEndpointAuthMethod",
	application_type: "applicationType",
	jwks: "jwks",
	jwks_uri: "jwksUri",
	grant_types: "grantTypes",
	response_types: "responseTypes",
	dpop_bound_access_tokens: "dpopBoundAccessTokens",
	require_pkce: "requirePKCE",
} satisfies Record<keyof Client, string>;
const serialized = new Set([
	"redirectUris",
	"scopes",
	"contacts",
	"postLogoutRedirectUris",
	"jwks",
	"grantTypes",
	"responseTypes",
]);
const privateKeyFields = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const invalid = (message: string) =>
	new ProjectOAuthError("invalid_client_metadata", message);

export function projectIssuerClientCredential() {
	return Array.from(
		{ length: 32 },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
}

function values(input: Client) {
	return Object.entries(fields).flatMap(([key, column]) => {
		const value = input[key as keyof Client];
		if (value === undefined) return [];
		const stored =
			key === "scope" && typeof value === "string" ? value.split(" ") : value;
		return [
			[
				column,
				serialized.has(column) ? JSON.stringify(stored) : stored,
			] as const,
		];
	});
}

async function validate(input: Client, trustedOrigins: ReadonlySet<string>) {
	const grantTypes = input.grant_types ?? ["authorization_code"];
	const auth = input.token_endpoint_auth_method ?? "client_secret_basic";
	const kind = input.application_type ?? "web";
	const authorization = grantTypes.includes("authorization_code");
	const responseTypes =
		input.response_types ?? (authorization ? ["code"] : undefined);
	if (Boolean(responseTypes?.includes("code")) !== authorization)
		throw invalid(
			"The code response type must match the authorization_code grant.",
		);
	if (authorization && !input.redirect_uris?.length)
		throw new ProjectOAuthError(
			"invalid_redirect_uri",
			"Redirect URIs are required for authorization_code.",
		);
	if (input.redirect_uris) {
		try {
			validateRedirectUris(input.redirect_uris);
			if (
				kind === "web" &&
				input.redirect_uris.some((uri) => new URL(uri).protocol !== "https:")
			)
				throw new Error("Web callbacks require HTTPS.");
		} catch {
			throw new ProjectOAuthError(
				"invalid_redirect_uri",
				"The registered redirect URI is invalid.",
			);
		}
	}
	if (input.post_logout_redirect_uris)
		for (const uri of input.post_logout_redirect_uris) {
			const url = URL.canParse(uri) ? new URL(uri) : null;
			if (
				!url ||
				!["https:", "http:"].includes(url.protocol) ||
				url.username ||
				url.password ||
				uri.includes("#") ||
				uri.includes("*")
			)
				throw invalid("The registered logout redirect URI is invalid.");
		}
	if (input.jwks && input.jwks_uri)
		throw invalid("jwks and jwks_uri are mutually exclusive.");
	if (auth === "private_key_jwt" && !input.jwks && !input.jwks_uri)
		throw invalid("private_key_jwt requires either jwks or jwks_uri.");
	try {
		if (input.backchannel_logout_uri)
			publicProjectHttpsURL(input.backchannel_logout_uri, true);
		if (
			input.jwks_uri &&
			!trustedOrigins.has(publicProjectHttpsURL(input.jwks_uri, true).origin)
		)
			throw new Error("The key document origin is not registered.");
	} catch {
		throw invalid(
			"The registered back-channel or key document URL is invalid.",
		);
	}
	for (const key of input.jwks?.keys ?? []) {
		if (privateKeyFields.some((field) => field in key))
			throw invalid("Registered key sets must contain only public keys.");
		const algorithm =
			typeof key.alg === "string" && issuerAssertionAlgorithms.includes(key.alg)
				? key.alg
				: key.kty === "RSA"
					? "RS256"
					: key.kty === "EC"
						? "ES256"
						: "EdDSA";
		try {
			const imported = await importJWK(key as JWK, algorithm);
			if (imported instanceof Uint8Array || imported.type !== "public")
				throw new Error("The key is not a public key.");
		} catch {
			throw invalid("The registered public key is invalid.");
		}
	}
	return {
		...input,
		grant_types: grantTypes,
		response_types: responseTypes,
		application_type: kind,
		token_endpoint_auth_method: auth,
	} satisfies Client;
}

/** Register a project client using the persisted managed-registration and secret formats. */
export async function createProjectIssuerClient(
	database: PoolClient,
	input: unknown,
	trustedOrigins: ReadonlySet<string>,
	reference: string,
) {
	const parsed = client.safeParse(input);
	if (!parsed.success) throw invalid("The client registration is invalid.");
	const data = await validate(parsed.data, trustedOrigins);
	const clientId = projectIssuerClientCredential();
	const secret =
		data.token_endpoint_auth_method === "client_secret_basic" ||
		data.token_endpoint_auth_method === "client_secret_post"
			? projectIssuerClientCredential()
			: undefined;
	const entries = values({ ...data, redirect_uris: data.redirect_uris ?? [] });
	const columns = [
		"id",
		"clientId",
		"clientSecret",
		"referenceId",
		"clientCredentialsScopes",
		...entries.map(([column]) => column),
	];
	const record = [
		randomUUID(),
		clientId,
		secret ? issuerDigest(secret) : null,
		reference,
		"[]",
		...entries.map(([, value]) => value),
	];
	await database.query(
		`INSERT INTO "oauthClient" (${columns.map((column) => `"${column}"`).join(",")},"createdAt","updatedAt")
		 VALUES (${record.map((_, index) => `$${index + 1}`).join(",")},date_trunc('second',statement_timestamp()),date_trunc('second',statement_timestamp()))`,
		record,
	);
	return { clientId, secret };
}

/** Revalidate the merged registration while changing only the submitted fields. */
export async function updateProjectIssuerClient(
	database: PoolClient,
	clientId: string,
	updates: z.infer<typeof projectIssuerClientUpdate>["update"],
	prior: Record<string, unknown>,
	trustedOrigins: ReadonlySet<string>,
) {
	const entries = values(updates);
	if (entries.length === 0) return;
	const merged = client.safeParse({ ...prior, ...updates });
	if (!merged.success)
		throw invalid("The stored client registration is invalid.");
	await validate(merged.data, trustedOrigins);
	await database.query(
		`UPDATE "oauthClient" SET ${entries.map(([column], index) => `"${column}"=$${index + 2}`).join(",")},
		 "clientCredentialsScopes"='[]',"updatedAt"=date_trunc('second',statement_timestamp()) WHERE "clientId"=$1`,
		[clientId, ...entries.map(([, value]) => value)],
	);
}
