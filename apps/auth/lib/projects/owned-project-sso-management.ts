import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { rolesInclude } from "../configuration";
import { createProjectEngineStore } from "./owned-project-engine-store";
import {
	organizationFailure as failure,
	organizationJson as json,
} from "./owned-project-organization-response";
import {
	checkProjectSsoDomainDns,
	projectSsoDnsIdentifier,
	readProjectSsoDomainProof,
	requestProjectSsoDomainProof,
	verifyProjectSsoDomainProof,
} from "./owned-project-sso-domain";
import type { SsoFetch } from "./owned-project-sso-network";
import type { StoredProjectSsoProvider } from "./owned-project-sso-projection";
import {
	projectSsoProviderResponse,
	readStoredSsoConfiguration,
} from "./owned-project-sso-projection";
import {
	authorizeProjectSsoRegistration,
	prepareProjectSsoRegistration,
	projectSsoRegistrationInput,
	registerProjectSsoProvider,
} from "./owned-project-sso-register";
import {
	projectSamlAcs,
	publicSamlRegistration,
} from "./owned-project-sso-saml-management";
import { projectSamlServiceMetadata } from "./owned-project-sso-saml-protocol";
import { ssoProviderId } from "./owned-project-sso-store";
import {
	projectSsoUpdateInput,
	updateProjectSsoProvider,
} from "./owned-project-sso-update";

const paths = {
	"/sso/providers": "GET",
	"/sso/register": "POST",
	"/sso/get-provider": "GET",
	"/sso/saml2/sp/metadata": "GET",
	"/sso/delete-provider": "POST",
	"/sso/update-provider": "POST",
	"/sso/request-domain-verification": "POST",
	"/sso/verify-domain": "POST",
} as const;
type Path = keyof typeof paths;
const providerInput = z.object({
	providerId: z
		.string()
		.max(2048)
		.refine((value) => !value.includes("\0")),
});
const columns =
	'id, "providerId", issuer, domain, "domainVerified", "organizationId", "userId", "oidcConfig", "samlConfig"';
const noProvider = () => failure(404, "NOT_FOUND", "Provider not found");
const accessDenied = () =>
	failure(403, "FORBIDDEN", "You don't have access to this provider");

export interface OwnedProjectSsoManagementOptions {
	database: Pool;
	schemaName: string;
	/** Fully bound auth origin and prefix for the metadata URL returned to this transport. */
	baseURL: string;
	trustedOrigins: ReadonlySet<string>;
	fetch?: SsoFetch;
	saml?: boolean;
	trustedRequest(headers: Headers, mutation: boolean): boolean;
	readBody(request: Request): Promise<unknown>;
	readSession(
		request: Request,
		client: PoolClient,
	): Promise<{ token: string; user: { id: string } } | null>;
}

function isAdminRole(role: string) {
	return rolesInclude(role, "owner") || rolesInclude(role, "admin");
}

async function readProvider(
	client: PoolClient,
	providerId: string,
	lock: boolean,
) {
	const result = await client.query<StoredProjectSsoProvider>(
		`SELECT ${columns} FROM "ssoProvider" WHERE "providerId"=$1${lock ? " FOR UPDATE" : ""}`,
		[providerId],
	);
	return result.rows[0];
}

async function canManageProvider(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
	userId: string,
) {
	if (!provider.organizationId) return provider.userId === userId;
	const member = await client.query<{ role: string }>(
		`SELECT role FROM "member" WHERE "organizationId"=$1 AND "userId"=$2 ORDER BY "createdAt",id LIMIT 1 FOR SHARE`,
		[provider.organizationId, userId],
	);
	return Boolean(member.rows[0] && isAdminRole(member.rows[0].role));
}

/** The same guarded provider row serializes account linking and SCIM directory binding. */
async function deleteProvider(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
) {
	if (!ssoProviderId.safeParse(provider.providerId).success)
		return failure(
			409,
			"SSO_PROVIDER_MUTATION_REJECTED",
			"SSO provider mutation is not allowed",
		);
	const binding = await client.query(
		'SELECT 1 FROM "allauthDirectory" WHERE "providerId"=$1 LIMIT 1',
		[provider.providerId],
	);
	if (binding.rowCount)
		return failure(
			409,
			"SSO_PROVIDER_MUTATION_REJECTED",
			"SSO provider mutation is not allowed",
		);
	await client.query('DELETE FROM "account" WHERE "providerId"=$1', [
		provider.providerId,
	]);
	await client.query('DELETE FROM "verification" WHERE identifier=$1', [
		projectSsoDnsIdentifier(provider.providerId),
	]);
	await client.query(
		'DELETE FROM "ssoProvider" WHERE id=$1 AND "providerId"=$2',
		[provider.id, provider.providerId],
	);
}

async function auditProviderChange(
	client: PoolClient,
	path:
		| "/sso/delete-provider"
		| "/sso/verify-domain"
		| "/sso/update-provider"
		| "/sso/register",
	provider: StoredProjectSsoProvider,
	actorId: string,
) {
	const type = `sso.${path.slice("/sso/".length)}`;
	await client.query(
		`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","userId","organizationId","targetId","createdAt",metadata)
		VALUES ($1,$2,'success',$3,$3,$4,$5,statement_timestamp(),jsonb_build_object('path',$6::text))`,
		[
			randomUUID(),
			type,
			actorId,
			provider.organizationId,
			provider.providerId,
			path,
		],
	);
	await client.query(
		`INSERT INTO "allauthAudit" (id,"actorId",action,"targetId","organizationId","createdAt")
		VALUES ($1,$2,$3,$4,$5,statement_timestamp())`,
		[randomUUID(), actorId, path, provider.providerId, provider.organizationId],
	);
}

/** Project provider management uses live signed project sessions and scoped PostgreSQL authority. */
export function createOwnedProjectSsoManagement(
	options: OwnedProjectSsoManagementOptions,
) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	const origin = new URL(options.baseURL).origin;

	async function lockActor(
		client: PoolClient,
		request: Request,
		session: NonNullable<Awaited<ReturnType<typeof options.readSession>>>,
	) {
		const user = await store.lockUser(client, session.user.id);
		return user &&
			(await store.lockSession(client, session.token, user.id, false)) &&
			(await options.readSession(request, client))
			? user
			: null;
	}

	async function forProvider<T>(
		request: Request,
		providerId: string,
		mutation: boolean,
		run: (
			client: PoolClient,
			provider: StoredProjectSsoProvider,
			actorId: string,
		) => Promise<T>,
	) {
		return store.transaction(async (client) => {
			const session = await options.readSession(request, client);
			if (!session) return failure(401, "UNAUTHORIZED", "Unauthorized");
			const userId = session.user.id;
			// Match the SSO callback's provider → user → membership lock order.
			const provider = await readProvider(client, providerId, mutation);
			if (!provider) return noProvider();
			if (mutation && !(await lockActor(client, request, session)))
				return failure(401, "UNAUTHORIZED", "Unauthorized");
			if (!(await canManageProvider(client, provider, userId)))
				return accessDenied();
			return run(client, provider, userId);
		});
	}

	async function register(request: Request) {
		const parsed = projectSsoRegistrationInput.safeParse(
			await options.readBody(request),
		);
		if (!parsed.success)
			return failure(400, "BAD_REQUEST", "Invalid SSO provider request.");
		const input = parsed.data;
		async function registerWithAuthority<T>(
			run: (client: PoolClient, actorId: string) => Promise<T>,
		) {
			return store.transaction(async (client) => {
				const session = await options.readSession(request, client);
				const user = session && (await lockActor(client, request, session));
				if (!user) return failure(401, "UNAUTHORIZED", "Unauthorized");
				const authorization = await authorizeProjectSsoRegistration(
					client,
					input,
					user,
				);
				if (authorization) return authorization;
				return run(client, user.id);
			});
		}

		// Release database locks during bounded discovery and recheck authority before inserting.
		const authorization = await registerWithAuthority(async () => undefined);
		if (authorization instanceof Response) return authorization;
		const configuration = await prepareProjectSsoRegistration(
			input,
			options.trustedOrigins,
			options.fetch,
			options.saml ? options.baseURL : undefined,
		);
		if (configuration instanceof Response) return configuration;
		return registerWithAuthority(async (client, actorId) => {
			const provider = await registerProjectSsoProvider(
				client,
				actorId,
				input,
				configuration,
			);
			if (provider instanceof Response) return provider;
			await auditProviderChange(client, "/sso/register", provider, actorId);
			const { oidcConfig: _oidc, samlConfig: _saml, ...rest } = provider;
			const sameOrigin = request.headers.get("origin") === origin;
			const { type, config } = configuration;
			if (type === "saml") {
				return json({
					...rest,
					oidcConfig: null,
					samlConfig: sameOrigin ? config : publicSamlRegistration(config),
					redirectURI: `${options.baseURL}/sso/callback/${encodeURIComponent(provider.providerId)}`,
				});
			}
			const { clientSecret, ...publicConfig } = config;
			return json({
				...rest,
				oidcConfig: sameOrigin ? config : publicConfig,
				samlConfig: null,
				redirectURI: `${options.baseURL}/sso/callback/${encodeURIComponent(provider.providerId)}`,
			});
		});
	}

	async function metadata(request: Request) {
		const id = ssoProviderId.safeParse(
			new URL(request.url).searchParams.get("providerId"),
		);
		if (!id.success)
			return failure(400, "BAD_REQUEST", "Invalid SSO provider request.");
		const provider = await store.transaction((client) =>
			readProvider(client, id.data, false),
		);
		if (!provider)
			return failure(
				404,
				"NOT_FOUND",
				"No provider found for the given providerId",
			);
		const config = readStoredSsoConfiguration(provider.samlConfig);
		try {
			const acs = projectSamlAcs(options.baseURL, id.data);
			return new Response(projectSamlServiceMetadata(config, acs), {
				headers: {
					"Content-Type": "application/xml",
					"Cache-Control": "no-store",
					"Content-Security-Policy": "default-src 'none'; sandbox",
					"X-Content-Type-Options": "nosniff",
				},
			});
		} catch {
			return failure(400, "BAD_REQUEST", "Invalid SAML configuration");
		}
	}

	return async (
		path: string,
		request: Request,
	): Promise<Response | undefined> => {
		if (!Object.hasOwn(paths, path) || request.method !== paths[path as Path])
			return;
		if (path === "/sso/saml2/sp/metadata") {
			if (!options.saml) return;
			try {
				return await metadata(request);
			} catch {
				return failure(
					503,
					"SSO_MANAGEMENT_UNAVAILABLE",
					"SSO provider management is temporarily unavailable.",
				);
			}
		}
		const mutation = request.method === "POST";
		if (!options.trustedRequest(request.headers, mutation))
			return failure(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		try {
			if (path === "/sso/register") return await register(request);
			if (path === "/sso/update-provider") {
				const input = projectSsoUpdateInput.safeParse(
					await options.readBody(request),
				);
				if (!input.success)
					return failure(400, "BAD_REQUEST", "Invalid SSO provider request.");
				return await forProvider(
					request,
					input.data.providerId,
					true,
					async (client, provider, actorId) => {
						const updated = await updateProjectSsoProvider(
							client,
							provider,
							input.data,
							options.saml ? options.baseURL : undefined,
						);
						if (updated instanceof Response) return updated;
						await auditProviderChange(client, path, updated, actorId);
						return json(projectSsoProviderResponse(updated, options.baseURL));
					},
				);
			}
			if (path !== "/sso/providers") {
				const input = providerInput.safeParse(
					mutation
						? await options.readBody(request)
						: {
								providerId: new URL(request.url).searchParams.get("providerId"),
							},
				);
				if (!input.success)
					return failure(400, "BAD_REQUEST", "Invalid SSO provider request.");
				const { providerId } = input.data;
				if (path === "/sso/request-domain-verification")
					return await forProvider(
						request,
						providerId,
						true,
						requestProjectSsoDomainProof,
					);
				if (path === "/sso/verify-domain") {
					const snapshot = await forProvider(
						request,
						providerId,
						true,
						readProjectSsoDomainProof,
					);
					if (snapshot instanceof Response) return snapshot;
					const dnsError = await checkProjectSsoDomainDns(snapshot);
					if (dnsError) return dnsError;
					return await forProvider(
						request,
						providerId,
						true,
						async (client, provider, actorId) => {
							const proofError = await verifyProjectSsoDomainProof(
								client,
								provider,
								snapshot,
							);
							if (proofError) return proofError;
							await auditProviderChange(client, path, provider, actorId);
							return new Response(null, {
								status: 204,
								headers: { "Cache-Control": "no-store" },
							});
						},
					);
				}
				if (path === "/sso/delete-provider")
					return await forProvider(
						request,
						providerId,
						true,
						async (client, provider, actorId) => {
							const deleteError = await deleteProvider(client, provider);
							if (deleteError) return deleteError;
							await auditProviderChange(client, path, provider, actorId);
							return json({ success: true });
						},
					);
				return await forProvider(
					request,
					providerId,
					false,
					async (_client, provider) =>
						json(projectSsoProviderResponse(provider, options.baseURL)),
				);
			}
			return await store.transaction(async (client) => {
				const session = await options.readSession(request, client);
				if (!session) return failure(401, "UNAUTHORIZED", "Unauthorized");
				const userId = session.user.id;
				const memberships = await client.query<{
					role: string;
					organizationId: string;
				}>(
					`SELECT role,"organizationId" FROM "member" WHERE "userId"=$1 ORDER BY id FOR SHARE`,
					[userId],
				);
				const organizationIds = [
					...new Set(
						memberships.rows
							.filter((row) => isAdminRole(row.role))
							.map((row) => row.organizationId),
					),
				];
				const providers = await client.query<StoredProjectSsoProvider>(
					`SELECT ${columns} FROM "ssoProvider" WHERE (NULLIF("organizationId",'') IS NULL AND "userId"=$1)
					 OR "organizationId"=ANY($2::text[]) ORDER BY (NULLIF("organizationId",'') IS NULL) DESC,id`,
					[userId, organizationIds],
				);
				return json({
					providers: providers.rows.map((provider) =>
						projectSsoProviderResponse(provider, options.baseURL),
					),
				});
			});
		} catch {
			return failure(
				503,
				"SSO_MANAGEMENT_UNAVAILABLE",
				"SSO provider management is temporarily unavailable.",
			);
		}
	};
}
