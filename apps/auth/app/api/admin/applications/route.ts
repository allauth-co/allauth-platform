import * as z from "zod";
import { apiResponse, json, requireAdmin, requireSameOrigin } from "@/lib/api";
import type { ProjectApplicationRecord } from "@/lib/applications";
import {
	applicationGrants,
	applicationMetadata,
	applicationScopes,
	applicationSettingsSchema,
	linkApplicationResource,
	publicApplication,
	publicProjectApplication,
	rejectProjectConsoleApplicationWrite,
	validateApplicationSettings,
} from "@/lib/applications";
import { getAuthEnvironment } from "@/lib/auth";
import { consoleApplicationRoute } from "@/lib/console/application-route";
import { recordAudit } from "@/lib/enterprise";
import { projectRegistryPool } from "@/lib/projects/registry";
import { projectInstance } from "@/lib/projects/runtime";
import { requirePlatformDirectoryAdmin } from "@/lib/workspaces/authorization";

const createSchema = applicationSettingsSchema
	.extend({ kind: z.enum(["confidential", "public"]) })
	.strict();

export const GET = (request: Request) => {
	if (!new URL(request.url).searchParams.get("project")) {
		return apiResponse(async () => {
			const env = await getAuthEnvironment();
			await requirePlatformDirectoryAdmin(request.headers, env);
			const { rows } = await projectRegistryPool(
				env,
			).query<ProjectApplicationRecord>(
				`SELECT "clientId", name, "redirectUris", "tokenEndpointAuthMethod",
				 "grantTypes", scopes, disabled, metadata
				 FROM public."oauthClient" WHERE "referenceId" = 'allauth:platform'`,
			);
			return json({
				applications: rows.map((client) =>
					publicApplication({
						client_id: client.clientId,
						scope: client.scopes?.join(" "),
						client_name: client.name ?? undefined,
						redirect_uris: client.redirectUris ?? [],
						token_endpoint_auth_method:
							client.tokenEndpointAuthMethod ?? undefined,
						grant_types: client.grantTypes ?? undefined,
						disabled: client.disabled ?? undefined,
						metadata: client.metadata,
					}),
				),
			});
		});
	}
	return consoleApplicationRoute(request, async (instance, env) => {
		await requireAdmin(instance, request.headers, env);
		const clients = await (
			await instance.$context
		).adapter.findMany<ProjectApplicationRecord>({ model: "oauthClient" });
		return json({ applications: clients.map(publicProjectApplication) });
	});
};

export const POST = (request: Request) =>
	consoleApplicationRoute(request, async (instance, env) => {
		requireSameOrigin(request, env);
		const session = await requireAdmin(instance, request.headers, env);
		if (projectInstance(instance)) rejectProjectConsoleApplicationWrite(true);
		const input = createSchema.parse(await request.json());
		await validateApplicationSettings(instance, input);
		const client = await instance.api.adminCreateOAuthClient({
			headers: request.headers,
			body: {
				client_name: input.name,
				redirect_uris: input.redirectUris,
				application_type: input.redirectUris.some((uri) =>
					uri.startsWith("http:"),
				)
					? "native"
					: "web",
				token_endpoint_auth_method:
					input.kind === "public" ? "none" : "client_secret_basic",
				grant_types: applicationGrants(input),
				response_types: ["code"],
				scope: applicationScopes(input),
				require_pkce: true,
				skip_consent: false,
				enable_end_session: true,
				metadata: applicationMetadata(input),
			},
		});
		try {
			await linkApplicationResource(
				instance,
				request.headers,
				client.client_id,
				input.resourceURI,
			);
		} catch (error) {
			await instance.api.deleteOAuthClient({
				headers: request.headers,
				body: { client_id: client.client_id },
			});
			throw error;
		}
		await recordAudit((await instance.$context).adapter, {
			actorId: session.user.id,
			action: "application.created",
			targetId: client.client_id,
		});
		return json(
			{
				application: publicApplication(client),
				...(client.client_secret ? { clientSecret: client.client_secret } : {}),
			},
			201,
		);
	});
