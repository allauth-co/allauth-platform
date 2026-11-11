import { APIError } from "better-auth";
import * as z from "zod";
import type { createAuth } from "./auth";
import { withAuth } from "./auth";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, isPlatformAdmin, rolesInclude } from "./configuration";
import { selectedProjectAdministrator, projectInstance, withProjectAuth } from "./projects/runtime";
import { commercialLimitError } from "./billing/entitlements";

export type AuthInstance = ReturnType<typeof createAuth>;

export function json(value: unknown, status = 200): Response {
	return Response.json(value, { status, headers: { "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff" } });
}

export function requireSameOrigin(request: Request, env: AuthEnvironment) {
	if (request.headers.get("origin") !== authOrigin(env)) throw new APIError("FORBIDDEN", { message: "A same-origin request is required." });
}

export async function requireAdmin(instance: AuthInstance, headers: Headers) {
	const selected = projectInstance(instance);
	if (selected) {
		const principal = await selectedProjectAdministrator(selected.project, headers, selected.env);
		if (!principal) throw new APIError("FORBIDDEN");
		return principal;
	}
	const session = await instance.api.getSession({ headers, query: { disableCookieCache: true } });
	if (!session) throw new APIError("UNAUTHORIZED");
	if (!session.user.emailVerified || !isPlatformAdmin(session.user, session.session)) throw new APIError("FORBIDDEN");
	return session;
}

export async function requireDirectoryAdministrator(instance: AuthInstance, headers: Headers, organizationId: string) {
	const selected = projectInstance(instance);
	if (selected) {
		const principal = await selectedProjectAdministrator(selected.project, headers, selected.env);
		if (principal) return principal;
	}
	const session = await instance.api.getSession({ headers, query: { disableCookieCache: true } });
	if (!session) throw new APIError("UNAUTHORIZED");
	if (session.session.impersonatedBy || !session.user.emailVerified) throw new APIError("FORBIDDEN");
	if (isPlatformAdmin(session.user, session.session)) return session;
	const role = await instance.api.getActiveMemberRole({ headers, query: { organizationId } });
	if (!rolesInclude(role.role, "owner") && !rolesInclude(role.role, "admin")) throw new APIError("FORBIDDEN");
	return session;
}

export async function apiRoute(request: Request, callback: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>, options?: { platformOnly?: boolean }) {
	let upgradeWorkspace: string | undefined;
	try {
		const project = new URL(request.url).searchParams.get("project");
		if (project) {
			if (options?.platformOnly) throw new APIError("BAD_REQUEST", { message: "This endpoint manages the AllAuth platform." });
			return await withProjectAuth(project, (instance, env, selected) => { upgradeWorkspace = selected.workspaceId; return callback(instance, env); });
		}
		return await withAuth((instance, env) => callback(instance, env));
	}
	catch (error) {
		const limit = commercialLimitError(error);
		if (limit) return json({ error: limit.body?.message, code: limit.body?.code, ...(upgradeWorkspace ? { upgradeUrl: `/admin/workspaces?${new URLSearchParams({ workspace: upgradeWorkspace, tab: "billing" })}` } : {}) }, limit.statusCode);
		if (error instanceof APIError) return json({ error: error.body?.message || "The request is not permitted." }, error.statusCode);
		if (error instanceof z.ZodError) return json({ error: "The request contains invalid fields." }, 400);
		if (error && typeof error === "object" && "code" in error && error.code === "23505") return json({ error: "A record with this identifier already exists." }, 409);
		// Do not log exception bodies: provider errors can include credentials or tokens.
		console.error("AllAuth API request failed", error instanceof Error ? error.name : "UnknownError");
		return json({ error: "The request could not be completed." }, 500);
	}
}
