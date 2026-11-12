import { APIError } from "better-auth";
import { after } from "next/server";
import * as z from "zod";
import { json } from "@/lib/api";
import { getAuthEnvironment } from "@/lib/auth";
import { recordSdkVersionObservation } from "@/lib/notifications/repository";
import { backendCredentialRepository } from "@/lib/projects/backend-credentials";
import { ownedSCIMError } from "@/lib/projects/owned-project-scim-discovery";
import { internalProjectEngineSelected } from "@/lib/projects/project-engine-internal-selection";
import type { ProjectProtocolBody } from "@/lib/projects/project-protocol-body";
import {
	prepareProjectProtocolBody,
	projectProtocolBody,
} from "@/lib/projects/project-protocol-body";
import { getProject, projectRegistryPool } from "@/lib/projects/registry";
import {
	projectSecret,
	withResolvedProjectAuthEngine,
} from "@/lib/projects/runtime";
import {
	handleServiceDirectoryRequest,
	hasServiceDirectoryCredentials,
} from "@/lib/projects/service-directory-transport";
import { prepareProjectAuthentication } from "@/lib/projects/session-introspection";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function protocolBodyTimeout(protocol: ProjectProtocolBody) {
	return protocol === "scim"
		? ownedSCIMError(408, "The SCIM request body timed out")
		: json(
				{
					code: "INVALID_SAML_RESPONSE",
					message: "The SAML request body timed out.",
				},
				408,
			);
}

async function handle(
	request: Request,
	context: { params: Promise<{ slug: string }> },
) {
	let timedOut: (() => boolean) | undefined;
	let protocol: ProjectProtocolBody | null = null;
	try {
		const { slug } = await context.params;
		const environment = await getAuthEnvironment();
		const project = await getProject(slug, environment);
		if (
			!request.headers.get("allauth-proxy-signature") &&
			internalProjectEngineSelected(environment, project)
		)
			protocol = projectProtocolBody(
				request,
				`/api/projects/${project.slug}/auth`,
			);
		const protocolBody = protocol
			? await prepareProjectProtocolBody(request, protocol)
			: null;
		timedOut = protocolBody?.timedOut;
		if (protocol && timedOut?.()) return protocolBodyTimeout(protocol);
		const transport = protocolBody?.request ?? request;
		const prepare = () =>
			prepareProjectAuthentication(transport, project, environment, {
				consumeBody: true,
			});
		const directoryRequest = hasServiceDirectoryCredentials(request, project);
		// The dedicated directory credential path is GET-only and has no body.
		// Other signed requests must finish verification before holding a writer lease.
		const prepared = directoryRequest ? undefined : await prepare();
		const response = await withResolvedProjectAuthEngine(
			project,
			async ({ engine, consumeAdmission }) => {
				if (directoryRequest) {
					const directory = await handleServiceDirectoryRequest(
						request,
						project,
						{
							authorize: (headers) =>
								backendCredentialRepository(
									projectRegistryPool(environment),
								).authorize(project.id, headers),
							consume: consumeAdmission,
							read: (operation, headers, query) =>
								engine.readDirectory(operation, headers, query),
						},
					);
					if (directory) return directory;
				}
				const authentication = prepared ?? (await prepare());
				const result = await authentication.dispatch(
					projectSecret(environment, project.id),
					{
						scope: engine,
						consume: consumeAdmission,
						session: (_headers, verified) => engine.readSession(verified),
						fallback: (verified) => engine.dispatch(verified),
					},
				);
				const version = request.headers.get("x-allauth-sdk-version");
				if (authentication.signed && version) {
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
		if (protocol && timedOut?.()) return protocolBodyTimeout(protocol);
		response.headers.set("Cache-Control", "no-store");
		response.headers.set("Pragma", "no-cache");
		return response;
	} catch (error) {
		if (protocol && timedOut?.()) return protocolBodyTimeout(protocol);
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

/** Other project endpoints keep their current method surface. */
async function scimMutation(
	request: Request,
	context: { params: Promise<{ slug: string }> },
) {
	const { slug } = await context.params;
	const path = new URL(request.url).pathname;
	const basePath = `/api/projects/${slug}/auth/scim/v2/`;
	if (
		!path.startsWith(basePath) ||
		!/^(?:Users|Groups)\/[^/]+$/.test(path.slice(basePath.length))
	)
		return new Response(null, {
			status: 405,
			headers: { Allow: "GET, POST", "Cache-Control": "no-store" },
		});
	return handle(request, context);
}

export const PUT = scimMutation;
export const PATCH = scimMutation;
export const DELETE = scimMutation;
