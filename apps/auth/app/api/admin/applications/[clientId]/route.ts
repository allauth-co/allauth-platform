import { json, requireAdmin, requireSameOrigin } from "@/lib/api";
import {
	applicationGrants,
	applicationMetadata,
	applicationScopes,
	applicationSettingsSchema,
	linkApplicationResource,
	publicApplication,
	rejectProjectConsoleApplicationWrite,
	validateApplicationSettings,
} from "@/lib/applications";
import { consoleApplicationRoute } from "@/lib/console/application-route";
import { recordAudit } from "@/lib/enterprise";
import { projectInstance } from "@/lib/projects/runtime";

export const DELETE = async (
	request: Request,
	context: { params: Promise<{ clientId: string }> },
) =>
	consoleApplicationRoute(request, async (instance, env) => {
		requireSameOrigin(request, env);
		const session = await requireAdmin(instance, request.headers, env);
		if (projectInstance(instance)) rejectProjectConsoleApplicationWrite(false);
		const { clientId } = await context.params;
		await instance.api.deleteOAuthClient({
			headers: request.headers,
			body: { client_id: clientId },
		});
		await recordAudit((await instance.$context).adapter, {
			actorId: session.user.id,
			action: "application.deleted",
			targetId: clientId,
		});
		return json({ success: true });
	});

export const PATCH = async (
	request: Request,
	context: { params: Promise<{ clientId: string }> },
) =>
	consoleApplicationRoute(request, async (instance, env) => {
		requireSameOrigin(request, env);
		const actor = await requireAdmin(instance, request.headers, env);
		if (projectInstance(instance)) rejectProjectConsoleApplicationWrite(false);
		const { clientId } = await context.params;
		const input = applicationSettingsSchema.parse(await request.json());
		await validateApplicationSettings(instance, input);
		const previous = publicApplication(
			await instance.api.getOAuthClient({
				headers: request.headers,
				query: { client_id: clientId },
			}),
		);
		await linkApplicationResource(
			instance,
			request.headers,
			clientId,
			input.resourceURI,
		);
		const client = await instance.api.adminUpdateOAuthClient({
			headers: request.headers,
			body: {
				client_id: clientId,
				update: {
					client_name: input.name,
					redirect_uris: input.redirectUris,
					application_type: input.redirectUris.some((uri) =>
						uri.startsWith("http:"),
					)
						? "native"
						: "web",
					grant_types: applicationGrants(input),
					scope: applicationScopes(input),
					metadata: applicationMetadata(input),
				},
			},
		});
		if (previous.resourceURI && previous.resourceURI !== input.resourceURI)
			await instance.api.adminUnlinkClientResource({
				headers: request.headers,
				params: { identifier: previous.resourceURI, client_id: clientId },
			});
		const database = (await instance.$context).adapter;
		// Authorization policy changes require fresh consent and token issuance.
		await database.deleteMany({
			model: "oauthAccessToken",
			where: [{ field: "clientId", value: clientId }],
		});
		await database.deleteMany({
			model: "oauthRefreshToken",
			where: [{ field: "clientId", value: clientId }],
		});
		await database.deleteMany({
			model: "oauthConsent",
			where: [{ field: "clientId", value: clientId }],
		});
		await recordAudit(database, {
			actorId: actor.user.id,
			action: "application.updated",
			targetId: clientId,
		});
		return json({ application: publicApplication(client) });
	});
