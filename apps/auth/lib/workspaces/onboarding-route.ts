import { APIError } from "better-auth";
import type { AuthInstance } from "../api";
import { json, requireSameOrigin } from "../api";
import type { AuthEnvironment } from "../configuration";
import { requireWorkspacePrincipal } from "./authorization";
import { provisionDefaultWorkspace } from "./onboarding";

/** An explicit same-origin console action, separate from authentication and read-only workspace APIs. */
export async function defaultWorkspaceRoute(
	request: Request,
	instance: AuthInstance,
	env: AuthEnvironment,
) {
	if (new URL(request.url).searchParams.has("project"))
		throw new APIError("BAD_REQUEST", {
			message: "This endpoint manages the AllAuth platform.",
		});
	requireSameOrigin(request, env);
	return json(
		await provisionDefaultWorkspace(
			await requireWorkspacePrincipal(request.headers, env),
			env,
		),
	);
}
