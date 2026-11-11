import { APIError } from "better-auth";
import { apiRoute, json, requireSameOrigin } from "../api";
import { consoleBody } from "../console/database";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { updateProjectBrokerRedirects } from "../workspaces/broker";
import { readProjectOrigins, updateProjectOrigins } from "./origin-settings";

/** Named platform control; neither tenant sessions nor caller-selected schemas are accepted. */
export function projectOriginsRoute(request: Request, slug: string): Promise<Response> {
	return apiRoute(request, async (instance, env) => {
		if (request.method !== "GET" && request.method !== "PATCH") return json({ error: "Method not allowed." }, 405);
		if (request.method === "PATCH") {
			requireSameOrigin(request, env);
			if (request.headers.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN");
		}
		const principal = await requireWorkspacePrincipal(instance, request.headers);
		if (request.method === "GET") return json(await readProjectOrigins(principal, slug, env));
		const result = await updateProjectOrigins(principal, slug, await consoleBody(request), env, {
			reconcileBroker: (project, database) => updateProjectBrokerRedirects(instance, request.headers, principal, project, [], env, database),
		});
		return json(result, result.broker.status === "pending" ? 202 : 200);
	}, { platformOnly: true });
}
