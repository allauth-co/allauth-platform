import * as z from "zod";
import { apiRoute, json, requireAdmin, requireSameOrigin } from "@/lib/api";
import { applicationGrants, applicationMetadata, applicationScopes, applicationSettingsSchema, linkApplicationResource, publicApplication, validateApplicationSettings } from "@/lib/applications";
import { recordAudit } from "@/lib/enterprise";
import { projectInstance } from "@/lib/projects/runtime";
import { APIError } from "better-auth";

const createSchema = applicationSettingsSchema.extend({ kind: z.enum(["confidential", "public"]) }).strict();

export const GET = (request: Request) => apiRoute(request, async (instance) => {
	await requireAdmin(instance, request.headers);
	if (projectInstance(instance)) {
		const clients = await (await instance.$context).adapter.findMany<{ clientId: string; name?: string; redirectUris?: string[]; tokenEndpointAuthMethod?: string; grantTypes?: string[]; scopes?: string[]; disabled?: boolean; metadata?: Record<string, unknown> }>({ model: "oauthClient" });
		return json({ applications: clients.map((client) => publicApplication({ client_id: client.clientId, client_name: client.name, redirect_uris: client.redirectUris, token_endpoint_auth_method: client.tokenEndpointAuthMethod, grant_types: client.grantTypes, scope: client.scopes?.join(" "), disabled: client.disabled, metadata: client.metadata })) });
	}
	const clients = await instance.api.getOAuthClients({ headers: request.headers });
	return json({ applications: (clients || []).map(publicApplication) });
});

export const POST = (request: Request) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env);
	const session = await requireAdmin(instance, request.headers);
	if (projectInstance(instance)) throw new APIError("BAD_REQUEST", { message: "Use the project's own verified administrator session to register native OAuth clients. App integration settings are managed in Projects." });
	const input = createSchema.parse(await request.json());
	await validateApplicationSettings(instance, input);
	const client = await instance.api.adminCreateOAuthClient({ headers: request.headers, body: { client_name: input.name, redirect_uris: input.redirectUris, application_type: input.redirectUris.some((uri) => uri.startsWith("http:")) ? "native" : "web", token_endpoint_auth_method: input.kind === "public" ? "none" : "client_secret_basic", grant_types: applicationGrants(input), response_types: ["code"], scope: applicationScopes(input), require_pkce: true, skip_consent: false, enable_end_session: true, metadata: applicationMetadata(input) } });
	try { await linkApplicationResource(instance, request.headers, client.client_id, input.resourceURI); }
	catch (error) { await instance.api.deleteOAuthClient({ headers: request.headers, body: { client_id: client.client_id } }); throw error; }
	await recordAudit((await instance.$context).adapter, { actorId: session.user.id, action: "application.created", targetId: client.client_id });
	return json({ application: publicApplication(client), ...(client.client_secret ? { clientSecret: client.client_secret } : {}) }, 201);
});
