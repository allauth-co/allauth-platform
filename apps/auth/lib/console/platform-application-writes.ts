import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { apiResponse, json, requireSameOrigin } from "../api";
import type { ApplicationSettings } from "../applications";
import {
	applicationGrants,
	applicationMetadata,
	applicationScopes,
	applicationSettingsSchema,
} from "../applications";
import { getAuthEnvironment } from "../auth";
import { authPolicyRepository } from "../auth-policy/storage";
import {
	authOrigin,
	rolesInclude,
	trustedOrigins,
	validateRedirectUris,
} from "../configuration";
import { createPlatformIssuerStore } from "../platform-issuer-store";
import { createProjectIssuerClient } from "../projects/owned-project-issuer-client-writes";
import { ProjectOAuthError } from "../projects/owned-project-issuer-http";
import { projectRegistryPool } from "../projects/registry";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import type { ProjectApplicationRecord } from "./application-contract";
import { publicProjectApplication } from "./application-contract";
import { consoleBody } from "./database";
import { ConsoleRequestError } from "./request-error";

const createInput = applicationSettingsSchema
	.extend({ kind: z.enum(["confidential", "public"]) })
	.strict();

async function validate(client: PoolClient, settings: ApplicationSettings) {
	try {
		validateRedirectUris(settings.redirectUris, {
			allowLocalhost: settings.allowLocalhost,
		});
	} catch {
		throw new ConsoleRequestError(
			400,
			"Callbacks must use exact HTTPS URLs, or explicitly approved literal HTTP loopback URLs.",
		);
	}
	if (
		new Set(settings.organizationIds).size !== settings.organizationIds.length
	)
		throw new ConsoleRequestError(400, "Organization IDs must be distinct.");
	if (settings.organizationIds.length && !settings.resourceURI)
		throw new ConsoleRequestError(
			400,
			"Organization claims require an approved resource URI.",
		);
	if (settings.resourceURI) {
		const url = URL.canParse(settings.resourceURI)
			? new URL(settings.resourceURI)
			: null;
		if (
			!url ||
			url.protocol !== "https:" ||
			url.username ||
			url.password ||
			settings.resourceURI.includes("#") ||
			settings.resourceURI.includes("*")
		)
			throw new ConsoleRequestError(
				400,
				"Resource URIs must use exact HTTPS URLs without fragments, credentials, or wildcards.",
			);
	}
	const organizations = await client.query(
		'SELECT id FROM public."organization" WHERE id=ANY($1::text[])',
		[settings.organizationIds],
	);
	if (organizations.rowCount !== settings.organizationIds.length)
		throw new ConsoleRequestError(400, "An organization ID does not exist.");
}

async function linkResource(
	client: PoolClient,
	clientId: string,
	resource: string | undefined,
) {
	if (!resource) return;
	await client.query(
		`INSERT INTO public."oauthResource" (id,identifier,name,"accessTokenTtl","allowedScopes","policyVersion",disabled,"dpopBoundAccessTokensRequired","createdAt","updatedAt")
		VALUES ($1,$2,$2,300,'["openid","profile","email","offline_access","organization:read"]',1,false,false,now(),now())
		ON CONFLICT (identifier) DO NOTHING`,
		[randomUUID(), resource],
	);
	await client.query(
		`INSERT INTO public."oauthClientResource" (id,"clientId","resourceId","createdAt")
		VALUES ($1,$2,$3,now()) ON CONFLICT ("clientId","resourceId") DO NOTHING`,
		[randomUUID(), clientId, resource],
	);
}

async function readApplication(client: PoolClient, clientId: string) {
	const { rows } = await client.query<
		ProjectApplicationRecord & {
			userId: string | null;
			referenceId: string | null;
		}
	>(
		`SELECT "clientId",name,"redirectUris","tokenEndpointAuthMethod","grantTypes",scopes,disabled,metadata,"userId","referenceId"
		 FROM public."oauthClient" WHERE "clientId"=$1 FOR UPDATE`,
		[clientId],
	);
	return rows[0];
}

export function writePlatformConsoleApplication(
	request: Request,
	operation: "create" | "update" | "delete",
	clientId?: string,
) {
	return apiResponse(async () => {
		const env = await getAuthEnvironment();
		requireSameOrigin(request, env);
		const actor = await requireWorkspacePrincipal(request.headers, env);
		if (!rolesInclude(actor.user.role, "admin"))
			throw new ConsoleRequestError(403);
		const database = projectRegistryPool(env);
		const store = createPlatformIssuerStore(database);
		const { policy } = await authPolicyRepository(database).read("platform");
		const input =
			operation === "delete" ? undefined : await consoleBody(request);
		try {
			return await store.transaction(async (client) => {
				const user = await store.lockUser(client, actor.user.id);
				const {
					rows: [authority],
				} = await client.query<{ role: string }>(
					`SELECT u.role FROM public."session" s JOIN public."user" u ON u.id=s."userId"
					 WHERE s.id=$1 AND s."userId"=$2 AND s."expiresAt">statement_timestamp()
					 AND s."impersonatedBy" IS NULL FOR SHARE OF s`,
					[actor.session.id, actor.user.id],
				);
				if (
					!user?.emailVerified ||
					user.banned ||
					user.directoryDisabled ||
					user.isAnonymous ||
					!rolesInclude(authority?.role, "admin") ||
					(policy.mfaMode === "required" && !user.twoFactorEnabled)
				)
					throw new ConsoleRequestError(403);

				let id = clientId;
				let secret: string | undefined;
				if (operation === "create") {
					const settings = createInput.parse(input);
					await validate(client, settings);
					const origins = new Set([authOrigin(env), ...trustedOrigins(env)]);
					const created = await createProjectIssuerClient(
						client,
						{
							client_name: settings.name,
							redirect_uris: settings.redirectUris,
							application_type: settings.redirectUris.some((uri) =>
								uri.startsWith("http:"),
							)
								? "native"
								: "web",
							token_endpoint_auth_method:
								settings.kind === "public" ? "none" : "client_secret_basic",
							grant_types: applicationGrants(settings),
							response_types: ["code"],
							scope: applicationScopes(settings),
							require_pkce: true,
						},
						origins,
						"allauth:platform",
						settings.allowLocalhost,
					);
					id = created.clientId;
					secret = created.secret;
					await client.query(
						`UPDATE public."oauthClient" SET "skipConsent"=false,"enableEndSession"=true,metadata=$2 WHERE "clientId"=$1`,
						[id, JSON.stringify(applicationMetadata(settings))],
					);
					await linkResource(client, id, settings.resourceURI);
				} else {
					if (!id) throw new ConsoleRequestError(404);
					const row = await readApplication(client, id);
					if (!row) throw new ConsoleRequestError(404, "client not found");
					if (
						row.userId
							? row.userId !== user.id
							: row.referenceId !== "allauth:platform"
					)
						throw new ConsoleRequestError(401);
					if (operation === "delete") {
						await client.query(
							'DELETE FROM public."oauthClient" WHERE "clientId"=$1',
							[id],
						);
					} else {
						const settings = applicationSettingsSchema.parse(input);
						await validate(client, settings);
						await linkResource(client, id, settings.resourceURI);
						await client.query(
							`UPDATE public."oauthClient" SET name=$2,"redirectUris"=$3,"applicationType"=$4,
							 "grantTypes"=$5,scopes=$6,metadata=$7,"clientCredentialsScopes"='[]',"updatedAt"=now() WHERE "clientId"=$1`,
							[
								id,
								settings.name,
								JSON.stringify(settings.redirectUris),
								settings.redirectUris.some((uri) => uri.startsWith("http:"))
									? "native"
									: "web",
								JSON.stringify(applicationGrants(settings)),
								JSON.stringify(applicationScopes(settings).split(" ")),
								JSON.stringify({
									...row.metadata,
									...applicationMetadata(settings),
								}),
							],
						);
						const priorResource = row.metadata?.allauthResourceURI;
						if (
							typeof priorResource === "string" &&
							priorResource !== settings.resourceURI
						)
							await client.query(
								'DELETE FROM public."oauthClientResource" WHERE "clientId"=$1 AND "resourceId"=$2',
								[id, priorResource],
							);
						await client.query(
							'DELETE FROM public."oauthAccessToken" WHERE "clientId"=$1',
							[id],
						);
						await client.query(
							'DELETE FROM public."oauthRefreshToken" WHERE "clientId"=$1',
							[id],
						);
						await client.query(
							'DELETE FROM public."oauthConsent" WHERE "clientId"=$1',
							[id],
						);
					}
				}
				const action =
					operation === "create"
						? "application.created"
						: operation === "delete"
							? "application.deleted"
							: "application.updated";
				await client.query(
					'INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,$3,$4,now())',
					[randomUUID(), user.id, action, id],
				);
				if (operation === "delete") return json({ success: true });
				const saved = await readApplication(client, id!);
				if (!saved)
					throw new Error("The application could not be read after writing.");
				return json(
					{
						application: publicProjectApplication(saved),
						...(secret ? { clientSecret: secret } : {}),
					},
					operation === "create" ? 201 : 200,
				);
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError)
				throw new ConsoleRequestError(400, error.message);
			throw error;
		}
	});
}
