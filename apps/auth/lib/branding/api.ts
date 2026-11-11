import { APIError } from "better-auth";
import type { AuthEnvironment } from "../configuration";
import { apiRoute, json, requireSameOrigin } from "../api";
import { getProject } from "../projects/registry";
import { projectSlug } from "../projects/validation";
import { requireWorkspacePrincipal } from "../workspaces/authorization";
import { maxAssetBody } from "./asset-signature";
import { readApplicationSettings, settingsConflict, writeApplicationSettings } from "./repository";
import { storeBrandingAsset } from "./storage-client";
import { applicationSettingsPatch, brandingAssetKind, settingsVersion, validateBrandingAsset } from "./validation";

/** Read only a bounded stream before JSON/multipart parsers allocate the whole request. */
export async function boundedBrandingBody(request: Request, limit: number): Promise<Uint8Array<ArrayBuffer>> {
	const declared = request.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > limit)) throw new APIError("PAYLOAD_TOO_LARGE", { message: "The branding request is too large." });
	const reader = request.body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = []; let length = 0;
	try {
		for (;;) {
			const part = await reader.read(); if (part.done) break;
			length += part.value.length;
			if (length > limit) { void reader.cancel().catch(() => {}); throw new APIError("PAYLOAD_TOO_LARGE", { message: "The branding request is too large." }); }
			chunks.push(part.value);
		}
	} finally { reader.releaseLock(); }
	const bytes = new Uint8Array(length); let offset = 0;
	for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
	return bytes;
}
function projectQuery(request: Request) {
	const params = new URL(request.url).searchParams;
	if (params.getAll("project").length !== 1 || [...params.keys()].some((key) => key !== "project")) throw new APIError("BAD_REQUEST", { message: "Select one project for application settings." });
	return projectSlug.parse(params.get("project"));
}
function rootRoute(request: Request, callback: Parameters<typeof apiRoute>[1]) {
	const url = new URL(request.url); url.search = "";
	// The query selects a registry row, not the authentication database for this request.
	return apiRoute(new Request(url, { headers: request.headers }), callback, { platformOnly: true });
}
function requireBrandingOrigin(request: Request, env: AuthEnvironment) {
	requireSameOrigin(request, env);
	if (request.headers.get("sec-fetch-site") === "cross-site") throw new APIError("FORBIDDEN", { message: "A same-origin request is required." });
}
export async function applicationSettingsRequest(request: Request): Promise<Response> {
	return rootRoute(request, async (instance, env) => {
		const slug = projectQuery(request);
		if (request.method !== "GET" && request.method !== "PATCH") throw new APIError("METHOD_NOT_ALLOWED");
		if (request.method === "PATCH") requireBrandingOrigin(request, env);
		const principal = await requireWorkspacePrincipal(instance, request.headers);
		const project = await getProject(slug, env);
		if (request.method === "GET") return json(await readApplicationSettings(project.id, principal, env));
		if (request.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/json") throw new APIError("BAD_REQUEST", { message: "Application settings require JSON." });
		let body: unknown;
		try { body = JSON.parse(new TextDecoder().decode(await boundedBrandingBody(request, 16384))); } catch (error) { if (error instanceof APIError) throw error; throw new APIError("BAD_REQUEST", { message: "Application settings require valid JSON." }); }
		const value = applicationSettingsPatch.parse(body);
		return json(await writeApplicationSettings(project.id, principal, value.version, { branding: value.branding }, env));
	});
}

/** Upload only the chosen field; other saved settings remain untouched even while a form has unsaved edits. */
export async function applicationAssetRequest(request: Request): Promise<Response> {
	return rootRoute(request, async (instance, env: AuthEnvironment) => {
		const slug = projectQuery(request);
		if (request.method !== "POST") throw new APIError("METHOD_NOT_ALLOWED");
		requireBrandingOrigin(request, env);
		const principal = await requireWorkspacePrincipal(instance, request.headers);
		const project = await getProject(slug, env);
		const before = await readApplicationSettings(project.id, principal, env);
		if (!request.headers.get("content-type")?.toLowerCase().startsWith("multipart/form-data;")) throw new APIError("BAD_REQUEST", { message: "Upload a multipart image file." });
		const bytes = await boundedBrandingBody(request, maxAssetBody + 16384);
		let form: FormData;
		try { form = await new Request(request.url, { method: "POST", headers: { "content-type": request.headers.get("content-type")! }, body: bytes }).formData(); }
		catch { throw new APIError("BAD_REQUEST", { message: "The image upload is invalid." }); }
		if ([...form.keys()].some((key) => !["kind", "file", "version"].includes(key)) || ["kind", "file"].some((key) => form.getAll(key).length !== 1) || form.getAll("version").length > 1) throw new APIError("BAD_REQUEST", { message: "Provide one image file and branding field." });
		const kind = brandingAssetKind.parse(form.get("kind"));
		const suppliedVersion = form.get("version");
		if (suppliedVersion !== null && (typeof suppliedVersion !== "string" || !/^(0|[1-9][0-9]*)$/.test(suppliedVersion))) throw new APIError("BAD_REQUEST", { message: "The settings version is invalid." });
		const version = suppliedVersion === null ? before.version : settingsVersion.parse(Number(suppliedVersion));
		if (version !== before.version) throw new APIError("CONFLICT", { message: settingsConflict });
		const file = form.get("file");
		if (!(file instanceof Blob) || !file.size || file.size > maxAssetBody) throw new APIError("BAD_REQUEST", { message: "Upload an image no larger than 2 MB." });
		const asset = validateBrandingAsset(kind, new Uint8Array(await file.arrayBuffer()), file.type);
		const url = await storeBrandingAsset(asset, before, env);
		const settings = await writeApplicationSettings(project.id, principal, version, { asset: { kind, url } }, env);
		return json({ url, settings }, 201);
	});
}
