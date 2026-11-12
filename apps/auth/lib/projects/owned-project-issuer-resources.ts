import type { PoolClient } from "pg";
import type { ProjectIssuerClient } from "./owned-project-issuer-client";
import { ProjectOAuthError } from "./owned-project-issuer-http";
import type { IssuerSigningPin } from "./owned-project-issuer-keys";

interface IssuerResource {
	identifier: string;
	disabled: boolean | null;
	linked: boolean;
	allowedScopes: string[] | null;
	accessTokenTtl: number | null;
	refreshTokenTtl: number | null;
	signingAlgorithm: string | null;
	signingKeyId: string | null;
	customClaims: unknown;
	dpopBoundAccessTokensRequired: boolean | null;
}

const reservedClaims = new Set([
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
	"auth_time",
	"acr",
	"amr",
	"cnf",
	"act",
	"active",
	"token_type",
]);

export function issuerObject(value: unknown): Record<string, unknown> {
	if (typeof value === "string") {
		try {
			value = JSON.parse(value);
		} catch {
			return {};
		}
	}
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: {};
}

export async function issuerResourcePolicy(
	database: PoolClient,
	client: ProjectIssuerClient,
	requestedResources: string[],
	requestedScopes: string[],
	userinfo: string,
) {
	const resources = [...new Set(requestedResources)];
	const targets = resources.filter((resource) => resource !== userinfo);
	const { rows } = await database.query<IssuerResource>(
		`SELECT r.identifier,r.disabled,r."allowedScopes",r."accessTokenTtl",r."refreshTokenTtl",
			 r."signingAlgorithm",r."signingKeyId",r."customClaims",r."dpopBoundAccessTokensRequired",
			 EXISTS(SELECT 1 FROM "oauthClientResource" c WHERE c."clientId"=$1 AND c."resourceId"=r.identifier) AS linked
		 FROM "oauthResource" r WHERE r.identifier = ANY($2::text[]) FOR SHARE OF r`,
		[client.clientId, targets],
	);
	const byIdentifier = new Map(rows.map((row) => [row.identifier, row]));
	let scopes = requestedScopes;
	let accessTtl = 300;
	let refreshTtl = 30 * 86400;
	let dpopRequired =
		client.dpopBoundAccessTokens === true ||
		issuerObject(client.metadata).dpop_bound_access_tokens === true;
	const pin: IssuerSigningPin = {};
	const claims: Record<string, unknown> = Object.create(null);
	for (const target of targets) {
		const row = byIdentifier.get(target);
		if (!row || row.disabled || !row.linked)
			throw new ProjectOAuthError(
				"invalid_target",
				"The requested resource is unavailable to this client.",
			);
		if (row.allowedScopes) {
			scopes = scopes.filter((scope) => row.allowedScopes!.includes(scope));
			if (!scopes.length)
				throw new ProjectOAuthError(
					"invalid_scope",
					"The requested scopes are unavailable for this resource.",
				);
		}
		if (row.accessTokenTtl !== null)
			accessTtl = Math.min(accessTtl, row.accessTokenTtl);
		if (row.refreshTokenTtl !== null)
			refreshTtl = Math.min(refreshTtl, row.refreshTokenTtl);
		if (
			(row.signingAlgorithm && pin.alg && row.signingAlgorithm !== pin.alg) ||
			(row.signingKeyId && pin.kid && row.signingKeyId !== pin.kid)
		)
			throw new ProjectOAuthError(
				"invalid_request",
				"The requested resources require different signing keys.",
			);
		pin.alg = row.signingAlgorithm ?? pin.alg;
		pin.kid = row.signingKeyId ?? pin.kid;
		dpopRequired ||= row.dpopBoundAccessTokensRequired === true;
		for (const [key, value] of Object.entries(issuerObject(row.customClaims))) {
			if (
				!reservedClaims.has(key) &&
				!["__proto__", "constructor", "prototype"].includes(key)
			)
				claims[key] = value;
		}
	}
	const audience =
		resources.length && requestedScopes.includes("openid")
			? [...new Set([...resources, userinfo])]
			: resources;
	return { scopes, audience, accessTtl, refreshTtl, pin, claims, dpopRequired };
}
