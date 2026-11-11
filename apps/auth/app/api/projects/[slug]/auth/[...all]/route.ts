import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { after } from "next/server";
import * as z from "zod";
import { json } from "@/lib/api";
import { getAuthEnvironment } from "@/lib/auth";
import { recordSdkVersionObservation } from "@/lib/notifications/repository";
import { backendCredentialRepository } from "@/lib/projects/backend-credentials";
import { projectRegistryPool } from "@/lib/projects/registry";
import {
	projectInstance,
	projectSecret,
	withProjectAuth,
} from "@/lib/projects/runtime";
import { handleServiceDirectoryRequest } from "@/lib/projects/service-directory-transport";
import {
	consumeProxySessionCheck,
	handleProjectAuthentication,
} from "@/lib/projects/session-introspection";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
async function handle(
	request: Request,
	context: { params: Promise<{ slug: string }> },
) {
	try {
		const { slug } = await context.params;
		const environment = await getAuthEnvironment();
		const response = await withProjectAuth(
			slug,
			async (instance, _env, project) => {
				const entry = projectInstance(instance);
				if (!entry) throw new Error("Project instance is unavailable.");
				const directory = await handleServiceDirectoryRequest(
					request,
					project,
					{
						authorize: (headers) =>
							backendCredentialRepository(
								projectRegistryPool(environment),
							).authorize(project.id, headers),
						consume: (key) => consumeProxySessionCheck(entry.pool, key),
						read: async (operation, headers, query) =>
							runWithAdapter((await instance.$context).adapter, async () => {
								const endpoint: unknown = Reflect.get(instance.api, operation);
								if (typeof endpoint !== "function")
									throw new Error("Directory endpoint is unavailable.");
								return Reflect.apply(endpoint, instance.api, [
									{ headers, query, asResponse: true },
								]) as Promise<Response>;
							}),
					},
				);
				if (directory) return directory;
				const result = await handleProjectAuthentication(
					request,
					project,
					environment,
					projectSecret(environment, project.id),
					{
						scope: instance,
						consume: (key) => consumeProxySessionCheck(entry.pool, key),
						session: async (headers, verified) =>
							runWithAdapter((await instance.$context).adapter, () =>
								instance.api.getSession({
									headers,
									request: verified,
									query: { disableCookieCache: true },
									asResponse: true,
								}),
							),
						fallback: (verified) => instance.handler(verified),
					},
				);
				const version = request.headers.get("x-allauth-sdk-version");
				if (request.headers.get("allauth-proxy-signature") && version) {
					// Authentication has already verified the app proxy. Optional version
					// reporting never changes its result or adds database latency to it.
					after(async () => {
						try {
							await recordSdkVersionObservation(project, version, environment);
						} catch {
							console.warn("AllAuth SDK version observation will retry.");
						}
					});
				}
				return result;
			},
			environment,
		);
		response.headers.set("Cache-Control", "no-store");
		response.headers.set("Pragma", "no-cache");
		return response;
	} catch (error) {
		if (error instanceof APIError)
			return json(
				{ error: error.body?.message || "Request not permitted." },
				error.statusCode,
			);
		if (error instanceof z.ZodError)
			return json({ error: "Invalid project." }, 400);
		console.error(
			"AllAuth project request failed",
			error instanceof Error ? error.name : "UnknownError",
		);
		return json({ error: "Authentication is temporarily unavailable." }, 503);
	}
}
export const GET = handle;
export const POST = handle;
