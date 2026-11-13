import { apiResponse, json, requireAdmin, requireSameOrigin } from "@/lib/api";
import type { ProjectApplicationRecord } from "@/lib/applications";
import {
	publicApplication,
	publicProjectApplication,
	rejectProjectConsoleApplicationWrite,
} from "@/lib/applications";
import { getAuthEnvironment } from "@/lib/auth";
import { consoleApplicationRoute } from "@/lib/console/application-route";
import { writePlatformConsoleApplication } from "@/lib/console/platform-application-writes";
import { projectRegistryPool } from "@/lib/projects/registry";
import { requirePlatformDirectoryAdmin } from "@/lib/workspaces/authorization";

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
	new URL(request.url).searchParams.get("project")
		? consoleApplicationRoute(request, async (instance, env) => {
				requireSameOrigin(request, env);
				await requireAdmin(instance, request.headers, env);
				return rejectProjectConsoleApplicationWrite(true);
			})
		: writePlatformConsoleApplication(request, "create");
