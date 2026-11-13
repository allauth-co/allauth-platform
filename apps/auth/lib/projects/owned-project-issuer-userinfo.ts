import type { PoolClient } from "pg";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { requireIssuerDpop } from "./owned-project-issuer-dpop";
import {
	issuerForm,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";
import type {
	ActiveProjectIssuerAccess,
	IssuerTransactionOptions,
} from "./owned-project-issuer-introspection";

interface UserInfoUser {
	id: string;
	name: string;
	image: string | null;
	email: string;
	emailVerified: boolean;
}

function profileClaims(
	user: UserInfoUser,
	scopes: string[],
	requestedClaims: string[],
) {
	const include = (scope: string, claim: string) =>
		scopes.includes(scope) || requestedClaims.includes(claim);
	const claims: Record<string, unknown> = { sub: user.id };
	const parts = user.name.split(" ").filter(Boolean);
	if (include("profile", "name")) claims.name = user.name;
	if (include("profile", "picture") && user.image != null)
		claims.picture = user.image;
	if (parts.length > 1) {
		if (include("profile", "given_name"))
			claims.given_name = parts.slice(0, -1).join(" ");
		if (include("profile", "family_name")) claims.family_name = parts.at(-1);
	}
	if (include("email", "email")) claims.email = user.email;
	if (include("email", "email_verified"))
		claims.email_verified = user.emailVerified;
	return claims;
}

function invalidAccessToken() {
	return new ProjectOAuthError(
		"invalid_token",
		"Invalid or expired access token",
		401,
		'Bearer error="invalid_token"',
	);
}

async function authorization(request: Request) {
	const header = request.headers.get("authorization");
	const body =
		request.method === "POST" &&
		request.headers
			.get("content-type")
			?.toLowerCase()
			.startsWith("application/x-www-form-urlencoded")
			? (await issuerForm(request)).get("access_token")
			: null;
	if (header && body)
		throw new ProjectOAuthError(
			"invalid_request",
			"Multiple access token transport methods are not allowed",
		);
	if (body) return { scheme: "bearer", token: body };
	const match = /^(Bearer|DPoP) ([^\s,]+)$/i.exec(header ?? "");
	if (!match)
		throw new ProjectOAuthError(
			"invalid_request",
			"access token not found",
			401,
		);
	return { scheme: match[1]!.toLowerCase(), token: match[2]! };
}

export function createOwnedProjectIssuerUserInfo(
	options: IssuerTransactionOptions & {
		issuer: string;
		endpointBase?: string;
		activeAccess(
			client: PoolClient,
			token: string,
		): Promise<ActiveProjectIssuerAccess | null>;
	},
) {
	const store =
		"store" in options
			? options.store
			: createProjectEngineStore(options.database, options.schemaName);
	const endpoint = `${options.endpointBase ?? options.issuer}/oauth2/userinfo`;
	return async function userinfo(request: Request) {
		const url = new URL(request.url);
		if (
			url.origin + url.pathname !== endpoint ||
			!["GET", "POST"].includes(request.method)
		)
			return new ProjectOAuthError(
				"invalid_request",
				"Invalid UserInfo endpoint.",
				404,
			).response();
		try {
			const { scheme, token } = await authorization(request);
			return await store.transaction(async (client) => {
				const active = await options.activeAccess(client, token);
				if (!active) throw invalidAccessToken();
				const { aud, cnf, scope } = active.payload;
				if (aud && !(Array.isArray(aud) ? aud : [aud]).includes(endpoint))
					throw invalidAccessToken();
				const jkt = cnf?.jkt;
				if (cnf) {
					if (scheme !== "dpop" || typeof jkt !== "string" || !jkt)
						throw invalidAccessToken();
					try {
						await requireIssuerDpop(client, request, endpoint, {
							required: true,
							expectedJkt: jkt,
							accessToken: token,
						});
					} catch (error) {
						if (error instanceof ProjectOAuthError)
							throw new ProjectOAuthError(error.code, error.message, 401);
						throw error;
					}
				} else if (scheme !== "bearer") {
					throw invalidAccessToken();
				}
				const scopes = scope.split(" ");
				if (!scopes.includes("openid"))
					return new ProjectOAuthError(
						"invalid_scope",
						"Missing required scope",
					).response();
				if (!active.userId)
					return new ProjectOAuthError(
						"invalid_request",
						"user not found",
					).response();
				const { rows } = await client.query<UserInfoUser>(
					'SELECT id,name,image,email,"emailVerified" FROM "user" WHERE id=$1',
					[active.userId],
				);
				if (!rows[0])
					return new ProjectOAuthError(
						"invalid_request",
						"user not found",
					).response();
				return issuerJSON(
					profileClaims(rows[0], scopes, active.requestedUserInfoClaims),
				);
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	};
}
