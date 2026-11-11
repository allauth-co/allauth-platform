import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { consoleBody } from "@/lib/console/database";
import { listNotifications, markNotificationsRead, notificationPreferenceInput, notificationReadAction, setNotificationPreferences } from "@/lib/notifications/repository";
import { requireWorkspacePrincipal } from "@/lib/workspaces/authorization";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) => apiRoute(request, async (instance, env) => {
	const principal = await requireWorkspacePrincipal(instance, request.headers), query = new URL(request.url).searchParams;
	return json(await listNotifications(principal, env, { limit: query.get("limit") ?? undefined, offset: query.get("offset") ?? undefined }));
}, { platformOnly: true });

export const POST = (request: Request) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env);
	const principal = await requireWorkspacePrincipal(instance, request.headers);
	await markNotificationsRead(principal, notificationReadAction.parse(await consoleBody(request)), env);
	return json({ ok: true });
}, { platformOnly: true });

export const PATCH = (request: Request) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env);
	const principal = await requireWorkspacePrincipal(instance, request.headers), input = notificationPreferenceInput.parse(await consoleBody(request));
	await setNotificationPreferences(principal, input.releaseEmails, env);
	return json({ ok: true });
}, { platformOnly: true });
