import { APIError } from "better-auth";
import type { AuthInstance } from "../api";
import { isPlatformAdmin } from "../configuration";
import type { ControlDatabase } from "../control/types";
import { selectedProjectAdministrator, projectInstance } from "../projects/runtime";

/** Management authority always comes from the platform's current database session. */
export async function requireConsoleAdministrator(instance: AuthInstance, headers: Headers) {
	const selected = projectInstance(instance);
	const principal = selected ? await selectedProjectAdministrator(selected.project, headers, selected.env) : await instance.api.getSession({ headers, query: { disableCookieCache: true } });
	if (!principal) throw new APIError("UNAUTHORIZED");
	if (!principal.user.emailVerified || principal.user.banned || principal.session.impersonatedBy || (!selected && !isPlatformAdmin(principal.user, principal.session))) throw new APIError("FORBIDDEN");
	return principal;
}

/** The selected native instance supplies the connection and search_path; callers cannot choose a schema. */
export async function consoleDatabase(instance: AuthInstance): Promise<ControlDatabase> {
	const configured = (await instance.$context).options.database;
	if (!configured || typeof configured !== "object" || !("db" in configured)) throw new APIError("SERVICE_UNAVAILABLE");
	return configured.db as ControlDatabase;
}

/** Small management forms have bounded JSON bodies; malformed/oversized inputs never reach a mutation. */
export async function consoleBody(request: Request): Promise<unknown> {
	if (!request.headers.get("content-type")?.split(";")[0]?.trim().endsWith("/json")) throw new APIError("BAD_REQUEST", { message: "Send a JSON object." });
	const reader = request.body?.getReader();
	if (!reader) throw new APIError("BAD_REQUEST");
	const chunks: Uint8Array[] = []; let bytes = 0;
	try { for (;;) { const next = await reader.read(); if (next.done) break; bytes += next.value.length; if (bytes > 16_384) { await reader.cancel(); throw new APIError("PAYLOAD_TOO_LARGE"); } chunks.push(next.value); } }
	finally { reader.releaseLock(); }
	const buffer = new Uint8Array(bytes); let offset = 0;
	for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.length; }
	try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer)) as unknown; }
	catch { throw new APIError("BAD_REQUEST", { message: "Invalid JSON." }); }
}
