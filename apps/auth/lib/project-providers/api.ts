import { APIError } from "better-auth";
import type { ControlPrincipal } from "../control/types";
import type { Project } from "../projects/registry";
import { googleProviderPatch, selectGoogleProvider } from "./google";
import type { GoogleProviderPatch, StoredGoogleProvider } from "./google";

export interface GoogleProviderDependencies {
	origin: string;
	brokerGoogleEnabled: boolean;
	project: (slug: string) => Promise<Project>;
	authorize: (headers: Headers, project: Project) => Promise<ControlPrincipal | null>;
	read: (projectId: string) => Promise<StoredGoogleProvider>;
	update: (project: Project, input: GoogleProviderPatch, actorId: string) => Promise<StoredGoogleProvider>;
	callbackUrls: (project: Project) => Promise<string[]>;
	canDisableGoogle: (project: Project) => Promise<boolean>;
	serializeWrite?: (project: Project, actor: ControlPrincipal, work: (locked: GoogleProviderDependencies) => Promise<Response>) => Promise<Response>;
}
async function boundedJSON(request: Request): Promise<unknown> {
	if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new APIError("UNSUPPORTED_MEDIA_TYPE");
	const declared = request.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > 8192)) throw new APIError("PAYLOAD_TOO_LARGE");
	const reader = request.body?.getReader();
	if (!reader) throw new APIError("BAD_REQUEST");
	const chunks: Uint8Array[] = []; let length = 0;
	try {
		for (;;) {
			const result = await reader.read();
			if (result.done) break;
			length += result.value.byteLength;
			if (length > 8192) { void reader.cancel().catch(() => {}); throw new APIError("PAYLOAD_TOO_LARGE"); }
			chunks.push(result.value);
		}
	} finally { reader.releaseLock(); }
	const bytes = new Uint8Array(length); let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	try { return JSON.parse(new TextDecoder().decode(bytes)) as unknown; }
	catch { throw new APIError("BAD_REQUEST", { message: "Provide a valid Google settings document." }); }
}
async function googleProviderResponse(request: Request, project: Project, actor: ControlPrincipal, dependencies: GoogleProviderDependencies): Promise<Response> {
		let stored: StoredGoogleProvider;
		if (request.method === "PATCH") {
			if (request.headers.get("origin") !== dependencies.origin || request.headers.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN");
			const input = googleProviderPatch.parse(await boundedJSON(request));
			if (!input.google.enabled && !await dependencies.canDisableGoogle(project)) throw new APIError("BAD_REQUEST", { message: "Enable another sign-in method before disabling direct Google." });
			stored = await dependencies.update(project, input, actor.user.id);
		} else if (request.method === "GET") stored = await dependencies.read(project.id);
		else throw new APIError("METHOD_NOT_ALLOWED");
		const { id, name, workspaceId, applicationId, environment } = project;
		return Response.json({
			project: { id, name, slug: project.slug, workspaceId, applicationId, environment },
			version: stored.version, updatedAt: stored.updatedAt,
			google: { enabled: stored.enabled, clientId: stored.clientId, clientSecretConfigured: Boolean(stored.encryptedClientSecret) },
			effectiveProvider: selectGoogleProvider(stored.enabled && Boolean(stored.clientId && stored.encryptedClientSecret), dependencies.brokerGoogleEnabled),
			callbackUrls: await dependencies.callbackUrls(project),
		}, { headers: { "cache-control": "no-store", pragma: "no-cache" } });
}
/** Root workspace authority, exact environment selection and a version are required for provider settings. */
export function googleProviderHandler(dependencies: GoogleProviderDependencies) {
	return async (request: Request, slug: string): Promise<Response> => {
		if (request.headers.has("authorization")) throw new APIError("FORBIDDEN");
		const project = await dependencies.project(slug);
		const actor = await dependencies.authorize(request.headers, project);
		if (!actor) throw new APIError("UNAUTHORIZED");
		if (!actor.user.emailVerified || actor.user.banned || actor.session.impersonatedBy) throw new APIError("FORBIDDEN");
		if (request.method === "PATCH" && dependencies.serializeWrite) return dependencies.serializeWrite(project, actor, (locked) => googleProviderResponse(request, project, actor, locked));
		return googleProviderResponse(request, project, actor, dependencies);
	};
}
