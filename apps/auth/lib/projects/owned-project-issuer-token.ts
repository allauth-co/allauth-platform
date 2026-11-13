import { createHash, randomInt, randomUUID } from "node:crypto";
import type { JWTHeaderParameters, JWTPayload } from "jose";
import { SignJWT } from "jose";
import type { Pool, PoolClient } from "pg";
import type { createPlatformIssuerStore } from "../platform-issuer-store";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type {
	IssuerClientAuthenticator,
	ProjectIssuerClient,
} from "./owned-project-issuer-client";
import { createIssuerClientAuthenticator } from "./owned-project-issuer-client";
import { readAuthorizationCode } from "./owned-project-issuer-code";
import {
	consumeDeviceGrant,
	projectDeviceGrantType,
} from "./owned-project-issuer-device";
import { requireIssuerDpop } from "./owned-project-issuer-dpop";
import {
	issuerDigest,
	issuerForm,
	issuerJSON,
	ProjectOAuthError,
} from "./owned-project-issuer-http";
import type { IssuerSigningPin } from "./owned-project-issuer-keys";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import {
	issuerObject,
	issuerResourcePolicy,
} from "./owned-project-issuer-resources";

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

interface Grant {
	id: string;
	clientId: string;
	userId: string;
	sessionId: string | null;
	referenceId: string | null;
	authorizationCodeId: string | null;
	expiresAt: Date;
	createdAt: Date;
	revoked: Date | null;
	authTime: Date | null;
	confirmation: unknown;
	resources: string[] | null;
	requestedUserInfoClaims: string[] | null;
	scopes: string[];
}

type IssuerGrant = Pick<
	Grant,
	| "clientId"
	| "userId"
	| "sessionId"
	| "referenceId"
	| "authorizationCodeId"
	| "authTime"
	| "confirmation"
	| "resources"
	| "requestedUserInfoClaims"
>;

interface RefreshOptions {
	database: Pool;
	schemaName: string;
	issuer: string;
	endpointBase?: string;
	keys: LegacyMfaKeys;
	store?: Pick<
		ReturnType<typeof createPlatformIssuerStore>,
		"transaction" | "lockUser"
	>;
	keyring?: IssuerTokenKeyring;
	authenticateClient?: IssuerClientAuthenticator;
}

interface IssuerTokenKeyring {
	signingKey(
		client: PoolClient,
		pin?: IssuerSigningPin,
	): Promise<{
		alg: string;
		sign(
			payload: JWTPayload,
			header?: Pick<JWTHeaderParameters, "typ">,
		): Promise<string>;
	}>;
}

function projectTokenKeyring(options: RefreshOptions): IssuerTokenKeyring {
	const keyring = createOwnedProjectIssuerKeys(options);
	return {
		async signingKey(client, pin) {
			const signing = await keyring.signingKey(client, pin);
			return {
				alg: signing.alg,
				sign(payload, header) {
					return new SignJWT(payload)
						.setProtectedHeader({
							alg: signing.alg,
							kid: signing.id,
							...header,
						})
						.sign(signing.key);
				},
			};
		},
	};
}

function tokenValue() {
	return Array.from(
		{ length: 32 },
		() => tokenAlphabet[randomInt(tokenAlphabet.length)],
	).join("");
}

function invalidGrant() {
	return new ProjectOAuthError("invalid_grant", "invalid refresh token");
}

function refreshAllowed(client: ProjectIssuerClient) {
	const grants = client.grantTypes?.length
		? client.grantTypes
		: ["authorization_code"];
	return (
		grants.includes("refresh_token") || grants.includes("authorization_code")
	);
}

async function selectRefresh(
	database: PoolClient,
	digest: string,
	clientId: string,
	lock = false,
) {
	const { rows } = await database.query<Grant>(
		`SELECT id, "clientId","userId","sessionId","referenceId","authorizationCodeId",
			"expiresAt","createdAt",revoked,"authTime",confirmation,resources,"requestedUserInfoClaims",scopes
		 FROM "oauthRefreshToken" WHERE token = $1 AND "clientId" = $2${lock ? " FOR UPDATE" : ""}`,
		[digest, clientId],
	);
	return rows[0];
}

function scopesFor(
	form: URLSearchParams,
	grant: Grant,
	client: ProjectIssuerClient,
) {
	const requested = form.get("scope");
	const scopes = requested === null ? grant.scopes : requested.split(" ");
	if (
		!scopes.every(
			(scope) =>
				grant.scopes.includes(scope) &&
				(!client.scopes || client.scopes.includes(scope)),
		)
	)
		throw new ProjectOAuthError(
			"invalid_scope",
			"The requested scopes exceed the grant.",
		);
	return scopes;
}

function resourcesFor(form: URLSearchParams, grant: Grant) {
	const requested = form.getAll("resource");
	if (
		requested.length &&
		grant.resources &&
		!requested.every((resource) => grant.resources!.includes(resource))
	)
		throw new ProjectOAuthError(
			"invalid_target",
			"The requested resource exceeds the grant.",
		);
	return requested.length ? requested : (grant.resources ?? []);
}

function hashForIdToken(accessToken: string, algorithm: string) {
	const hash = algorithm.endsWith("384")
		? "sha384"
		: algorithm === "EdDSA" ||
				algorithm === "Ed25519" ||
				algorithm.endsWith("512")
			? "sha512"
			: "sha256";
	const digest = createHash(hash).update(accessToken).digest();
	return digest.subarray(0, digest.length / 2).toString("base64url");
}

async function organizationClaims(
	database: PoolClient,
	origin: string,
	client: ProjectIssuerClient,
	grant: IssuerGrant,
	scopes: string[],
	resources: string[],
) {
	if (!grant.referenceId || !scopes.includes("organization:read")) return {};
	const metadata = issuerObject(client.metadata);
	if (
		!Array.isArray(metadata.allauthOrganizationIds) ||
		!metadata.allauthOrganizationIds.includes(grant.referenceId) ||
		resources.length !== 1 ||
		resources[0] !== metadata.allauthResourceURI
	)
		throw new ProjectOAuthError(
			"invalid_target",
			"This client has no organization binding for the resource.",
		);
	const { rows } = await database.query<{ role: string }>(
		`SELECT role FROM "member" WHERE "organizationId"=$1 AND "userId"=$2 FOR SHARE`,
		[grant.referenceId, grant.userId],
	);
	if (!rows[0])
		throw new ProjectOAuthError(
			"access_denied",
			"The organization membership is unavailable.",
			403,
		);
	return {
		[`${origin}/organization_id`]: grant.referenceId,
		[`${origin}/organization_role`]: rows[0].role,
	};
}

async function saveRefresh(
	database: PoolClient,
	grant: IssuerGrant,
	values: {
		id: string;
		token: string;
		scopes: string[];
		resources: string[] | null;
		confirmation: { jkt: string } | undefined;
		iat: number;
		exp: number;
	},
) {
	await database.query(
		`INSERT INTO "oauthRefreshToken"(id,token,"clientId","userId","sessionId","referenceId","authorizationCodeId",
			"expiresAt","createdAt","authTime",confirmation,resources,"requestedUserInfoClaims",scopes)
		 VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),to_timestamp($9),$10,$11,$12,$13,$14)`,
		[
			values.id,
			issuerDigest(values.token),
			grant.clientId,
			grant.userId,
			grant.sessionId,
			grant.referenceId,
			grant.authorizationCodeId,
			values.exp,
			values.iat,
			grant.authTime,
			values.confirmation ?? null,
			values.resources && JSON.stringify(values.resources),
			grant.requestedUserInfoClaims &&
				JSON.stringify(grant.requestedUserInfoClaims),
			JSON.stringify(values.scopes),
		],
	);
}

export function createOwnedProjectIssuerToken(options: RefreshOptions) {
	const store =
		options.store ??
		createProjectEngineStore(options.database, options.schemaName);
	const keyring = options.keyring ?? projectTokenKeyring(options);
	const origin = new URL(options.issuer).origin;
	const endpointBase = options.endpointBase ?? options.issuer;
	const tokenEndpoint = `${endpointBase}/oauth2/token`;
	const userInfoEndpoint = `${endpointBase}/oauth2/userinfo`;
	const authenticateClient =
		options.authenticateClient ??
		createIssuerClientAuthenticator(options.issuer);

	async function rotate(
		database: PoolClient,
		request: Request,
		form: URLSearchParams,
		client: ProjectIssuerClient,
	) {
		if (!refreshAllowed(client))
			throw new ProjectOAuthError(
				"unauthorized_client",
				"The client cannot use refresh tokens.",
			);
		const raw = form.get("refresh_token");
		if (!raw || raw.length > 4096)
			throw new ProjectOAuthError(
				"invalid_request",
				"Missing a required refresh_token for refresh_token grant",
			);
		const digest = issuerDigest(raw);
		const observed = await selectRefresh(database, digest, client.clientId);
		if (!observed || observed.expiresAt.getTime() <= Date.now())
			throw invalidGrant();

		// Session revocation and directory changes use the same user → session
		// → grant lock order, so a refresh cannot resurrect revoked authority.
		const user = await store.lockUser(database, observed.userId);
		if (!user || user.directoryDisabled || user.banned) throw invalidGrant();
		const linked = observed.sessionId
			? await database.query<{ impersonatedBy: string | null }>(
					`SELECT "impersonatedBy" FROM "session" WHERE id=$1 AND "userId"=$2 FOR SHARE`,
					[observed.sessionId, observed.userId],
				)
			: undefined;
		const grant = await selectRefresh(database, digest, client.clientId, true);
		if (!grant || grant.expiresAt.getTime() <= Date.now()) throw invalidGrant();
		if (grant.revoked) {
			const previous = issuerObject(grant.confirmation);
			if (grant.confirmation) {
				if (typeof previous.jkt !== "string") throw invalidGrant();
				await requireIssuerDpop(database, request, tokenEndpoint, {
					required: true,
					expectedJkt: previous.jkt,
				});
			}
			// The foreign key deletes opaque access tokens minted in this family.
			await database.query(
				'DELETE FROM "oauthRefreshToken" WHERE "clientId"=$1 AND "userId"=$2',
				[client.clientId, grant.userId],
			);
			return invalidGrant().response();
		}
		if (
			grant.sessionId &&
			(grant.sessionId !== observed.sessionId || !linked?.rows[0])
		)
			throw invalidGrant();
		return issue(database, request, client, grant, {
			scopes: scopesFor(form, grant, client),
			resources: resourcesFor(form, grant),
			actor: linked?.rows[0]?.impersonatedBy,
			rotation: grant,
		});
	}

	async function exchangeCode(
		database: PoolClient,
		request: Request,
		form: URLSearchParams,
		client: ProjectIssuerClient,
	) {
		const {
			digest,
			record,
			scopes,
			originalResources,
			requestedResources,
			requestedUserInfoClaims,
		} = await readAuthorizationCode(database, form, client);
		const user = await store.lockUser(database, record.userId);
		if (!user || user.directoryDisabled || user.banned)
			throw new ProjectOAuthError(
				"invalid_grant",
				"The account is unavailable.",
			);
		const { rows } = await database.query<{
			createdAt: Date;
			impersonatedBy: string | null;
		}>(
			`SELECT "createdAt","impersonatedBy" FROM "session"
			 WHERE id=$1 AND "userId"=$2 AND "expiresAt">statement_timestamp() FOR SHARE`,
			[record.sessionId, record.userId],
		);
		const session = rows[0];
		if (!session)
			throw new ProjectOAuthError(
				"invalid_request",
				"session no longer exists",
			);

		const authTime =
			record.authTime === undefined
				? session.createdAt
				: new Date(
						record.authTime < 1e12 ? record.authTime * 1000 : record.authTime,
					);
		return issue(
			database,
			request,
			client,
			{
				clientId: client.clientId,
				userId: record.userId,
				sessionId: record.sessionId,
				referenceId: record.referenceId ?? null,
				authorizationCodeId: digest,
				authTime,
				confirmation: record.query.dpop_jkt
					? { jkt: record.query.dpop_jkt }
					: null,
				resources: originalResources,
				requestedUserInfoClaims,
			},
			{
				scopes,
				resources: requestedResources,
				actor: session.impersonatedBy,
				nonce: record.query.nonce,
			},
		);
	}

	async function issue(
		database: PoolClient,
		request: Request,
		client: ProjectIssuerClient,
		grant: IssuerGrant,
		input: {
			scopes: string[];
			resources: string[];
			actor?: string | null;
			nonce?: string;
			rotation?: Pick<Grant, "id" | "scopes">;
		},
	) {
		const {
			scopes: requestedScopes,
			resources: requestedResources,
			actor,
		} = input;
		const policy = await issuerResourcePolicy(
			database,
			client,
			requestedResources,
			requestedScopes,
			userInfoEndpoint,
		);
		if (actor && requestedScopes.includes("offline_access"))
			throw new ProjectOAuthError(
				"access_denied",
				"Offline access is unavailable during impersonation.",
				403,
			);
		const actorClaims = actor
			? { act: { sub: actor }, [`${origin}/impersonated_by`]: actor }
			: {};
		const previous = issuerObject(grant.confirmation);
		if (grant.confirmation && typeof previous.jkt !== "string")
			throw new ProjectOAuthError(
				"invalid_grant",
				"The sender constraint is unavailable.",
			);
		const confirmation = await requireIssuerDpop(
			database,
			request,
			tokenEndpoint,
			{
				required: policy.dpopRequired,
				expectedJkt:
					typeof previous.jkt === "string" ? previous.jkt : undefined,
			},
		);
		const organization = await organizationClaims(
			database,
			origin,
			client,
			grant,
			policy.scopes,
			requestedResources,
		);

		const iat = Math.floor(Date.now() / 1000);
		const exp = iat + policy.accessTtl;
		// A narrowed legacy refresh grant without offline access can issue an access
		// token until its existing expiry, but it cannot extend that expiry.
		const mintRefresh =
			refreshAllowed(client) &&
			(requestedScopes.includes("offline_access") ||
				input.rotation?.scopes.includes("offline_access"));
		const refreshed = mintRefresh ? tokenValue() : undefined;
		const refreshId = mintRefresh ? randomUUID() : null;
		const accessClaims = {
			...policy.claims,
			...organization,
			...actorClaims,
			sub: grant.userId,
			azp: client.clientId,
			client_id: client.clientId,
			iss: options.issuer,
			iat,
			exp,
			jti: tokenValue(),
			scope: policy.scopes.join(" "),
			sid: grant.sessionId ?? undefined,
			cnf: confirmation,
		};
		let accessToken: string;
		if (policy.audience.length) {
			const signing = await keyring.signingKey(database, policy.pin);
			accessToken = await signing.sign(
				{
					...accessClaims,
					aud:
						policy.audience.length === 1 ? policy.audience[0] : policy.audience,
				},
				{ typ: "at+jwt" },
			);
		} else {
			accessToken = tokenValue();
		}
		let idToken: string | undefined;
		if (policy.scopes.includes("openid")) {
			const signing = await keyring.signingKey(database);
			idToken = await signing.sign({
				...actorClaims,
				acr: "0",
				nonce: input.nonce,
				sub: grant.userId,
				aud: client.clientId,
				iss: options.issuer,
				iat,
				exp: iat + 300,
				at_hash: hashForIdToken(accessToken, signing.alg),
				auth_time: grant.authTime
					? Math.floor(grant.authTime.getTime() / 1000)
					: undefined,
				sid:
					client.enableEndSession || client.backchannelLogoutUri
						? (grant.sessionId ?? undefined)
						: undefined,
			});
		}

		if (!input.rotation && grant.authorizationCodeId) {
			const consumed = await database.query(
				`DELETE FROM "verification" WHERE identifier=$1 AND "expiresAt">clock_timestamp()`,
				[grant.authorizationCodeId],
			);
			if (!consumed.rowCount)
				throw new ProjectOAuthError("invalid_grant", "invalid code");
		}
		if (input.rotation && mintRefresh)
			await database.query(
				'UPDATE "oauthRefreshToken" SET revoked=to_timestamp($2),"rotatedAt"=to_timestamp($2) WHERE id=$1',
				[input.rotation.id, iat],
			);
		if (refreshId && refreshed)
			await saveRefresh(database, grant, {
				id: refreshId,
				token: refreshed,
				scopes: policy.scopes,
				confirmation,
				iat,
				exp: iat + policy.refreshTtl,
				resources:
					grant.resources ??
					(requestedResources.length ? requestedResources : null),
			});
		if (!policy.audience.length) {
			await database.query(
				`INSERT INTO "oauthAccessToken"(id,token,"clientId","userId","sessionId","referenceId","authorizationCodeId",
					"refreshId","expiresAt","createdAt",confirmation,"requestedUserInfoClaims",scopes)
				 VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9),to_timestamp($10),$11,$12,$13)`,
				[
					randomUUID(),
					issuerDigest(accessToken),
					grant.clientId,
					grant.userId,
					grant.sessionId,
					grant.referenceId,
					grant.authorizationCodeId,
					refreshId,
					exp,
					iat,
					confirmation ?? null,
					grant.requestedUserInfoClaims &&
						JSON.stringify(grant.requestedUserInfoClaims),
					JSON.stringify(policy.scopes),
				],
			);
		}
		return issuerJSON({
			access_token: accessToken,
			expires_in: policy.accessTtl,
			expires_at: exp,
			token_type: confirmation ? "DPoP" : "Bearer",
			refresh_token: refreshed,
			scope: policy.scopes.join(" "),
			id_token: idToken,
		});
	}

	return async function token(request: Request) {
		const url = new URL(request.url);
		if (
			request.method !== "POST" ||
			url.origin + url.pathname !== tokenEndpoint
		)
			return new ProjectOAuthError(
				"invalid_request",
				"Invalid OAuth token endpoint.",
				404,
			).response();
		try {
			const form = await issuerForm(request);
			const grantType = form.get("grant_type");
			if (
				grantType !== "refresh_token" &&
				grantType !== "authorization_code" &&
				grantType !== projectDeviceGrantType
			)
				throw new ProjectOAuthError(
					"unsupported_grant_type",
					"This token grant is unavailable.",
				);
			return await store.transaction(async (database) => {
				const client = await authenticateClient(database, request, form, true);
				// Protocol failures may consume a verified client assertion or a
				// replayed grant. Their response must commit with that decision.
				try {
					if (grantType === "refresh_token")
						return await rotate(database, request, form, client);
					if (grantType === "authorization_code")
						return await exchangeCode(database, request, form, client);
					return await consumeDeviceGrant(database, request, form, client, {
						endpointBase,
						issue: (grant) =>
							issue(
								database,
								request,
								client,
								{
									clientId: client.clientId,
									userId: grant.userId,
									sessionId: null,
									referenceId: null,
									authorizationCodeId: null,
									authTime: null,
									confirmation: null,
									resources: grant.originalResources ?? null,
									requestedUserInfoClaims: null,
								},
								{ scopes: grant.scopes, resources: grant.resources },
							),
					});
				} catch (error) {
					if (error instanceof ProjectOAuthError) return error.response();
					throw error;
				}
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	};
}
