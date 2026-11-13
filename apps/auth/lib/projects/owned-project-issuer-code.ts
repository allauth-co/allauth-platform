import type { PoolClient } from "pg";
import * as z from "zod";
import type { ProjectIssuerClient } from "./owned-project-issuer-client";
import { issuerDigest, ProjectOAuthError } from "./owned-project-issuer-http";
import { issuerObject } from "./owned-project-issuer-resources";

const resources = z.union([z.string(), z.array(z.string()).max(20)]);
const storedCode = z.object({
	type: z.literal("authorization_code"),
	query: z.object({
		client_id: z.string(),
		scope: z.string(),
		redirect_uri: z.string().optional(),
		code_challenge: z.string().optional(),
		code_challenge_method: z.string().optional(),
		nonce: z.string().optional(),
		dpop_jkt: z.string().optional(),
		resource: resources.optional(),
		claims: z.unknown().optional(),
	}),
	userId: z.string(),
	sessionId: z.string(),
	referenceId: z.string().optional(),
	authTime: z.number().optional(),
	resource: resources.optional(),
});
const supportedUserInfo = new Set(["sub", "name", "email", "email_verified"]);

export function readRequestedUserInfoClaims(value: unknown) {
	return Object.keys(issuerObject(issuerObject(value).userinfo)).filter(
		(claim) => supportedUserInfo.has(claim),
	);
}

function invalidCode(message = "invalid code") {
	return new ProjectOAuthError("invalid_grant", message);
}

function list(value?: string | string[]) {
	return typeof value === "string" ? [value] : value?.length ? value : null;
}

export async function readAuthorizationCode(
	database: PoolClient,
	form: URLSearchParams,
	client: ProjectIssuerClient,
) {
	if (
		!(
			client.grantTypes?.length ? client.grantTypes : ["authorization_code"]
		).includes("authorization_code")
	)
		throw new ProjectOAuthError(
			"unauthorized_client",
			"The client cannot exchange authorization codes.",
		);
	const code = form.get("code");
	if (!code || code.length > 4096)
		throw new ProjectOAuthError("invalid_request", "code is required");
	const digest = issuerDigest(code);
	// Serialize consumption and replay cleanup across project replicas.
	// cspell:ignore xact
	await database.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
		`allauth-oauth-code:${digest}`,
	]);
	const { rows } = await database.query<{ value: string; live: boolean }>(
		`SELECT value, "expiresAt" > clock_timestamp() AS live FROM "verification"
		 WHERE identifier=$1 ORDER BY "createdAt" DESC, id LIMIT 1 FOR UPDATE`,
		[digest],
	);
	if (!rows[0]?.live) {
		await database.query(
			'DELETE FROM "oauthAccessToken" WHERE "authorizationCodeId"=$1 AND "clientId"=$2',
			[digest, client.clientId],
		);
		await database.query(
			'DELETE FROM "oauthRefreshToken" WHERE "authorizationCodeId"=$1 AND "clientId"=$2',
			[digest, client.clientId],
		);
		throw invalidCode();
	}
	let value: unknown;
	try {
		value = JSON.parse(rows[0].value);
	} catch {
		throw invalidCode();
	}
	const parsed = storedCode.safeParse(value);
	if (!parsed.success || parsed.data.query.client_id !== client.clientId)
		throw invalidCode();
	const record = parsed.data;
	const { query } = record;
	const redirect = form.get("redirect_uri") ?? undefined;
	if (query.redirect_uri && !redirect)
		throw new ProjectOAuthError("invalid_request", "redirect_uri is required");
	if (query.redirect_uri !== redirect)
		throw invalidCode("redirect_uri mismatch");
	const scopes = query.scope.split(" ");
	if (
		!scopes.length ||
		scopes.some(
			(scope) => !scope || (client.scopes && !client.scopes.includes(scope)),
		)
	)
		throw new ProjectOAuthError(
			"invalid_scope",
			"The requested scopes exceed the grant.",
		);

	const verifier = form.get("code_verifier");
	const pkceRequired =
		client.tokenEndpointAuthMethod === "none" ||
		client.requirePKCE !== false ||
		(scopes.includes("offline_access") &&
			!(scopes.includes("openid") && query.nonce));
	if (pkceRequired && !verifier)
		throw new ProjectOAuthError(
			"invalid_request",
			"PKCE is required for this client",
		);
	if (verifier !== null || query.code_challenge !== undefined) {
		if (
			!verifier ||
			!/^[A-Za-z\d._~-]{43,128}$/.test(verifier) ||
			query.code_challenge_method !== "S256" ||
			issuerDigest(verifier) !== query.code_challenge
		)
			throw new ProjectOAuthError(
				"invalid_request",
				"code verification failed",
				401,
			);
	}
	const originalResources = list(record.resource) ?? list(query.resource);
	const supplied = form.getAll("resource");
	if (
		supplied.length &&
		originalResources &&
		!supplied.every((resource) => originalResources.includes(resource))
	)
		throw new ProjectOAuthError(
			"invalid_target",
			"The requested resource exceeds the grant.",
		);
	return {
		digest,
		record,
		scopes,
		originalResources,
		requestedResources: supplied.length ? supplied : (originalResources ?? []),
		requestedUserInfoClaims: readRequestedUserInfoClaims(query.claims),
	};
}
