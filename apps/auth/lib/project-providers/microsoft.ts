import { createHash } from "node:crypto";
import * as z from "zod";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";

const guid = z.string().trim().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i).toLowerCase();
const credentialsSchema = z.object({
	clientId: guid,
	clientSecret: z.string().min(1).max(4096).refine(value => !/[\x00-\x20\x7f]/.test(value)),
	tenantId: z.union([z.enum(["common", "organizations", "consumers"]), guid]).default("common"),
}).strict();
export type ProjectMicrosoftProvider = z.infer<typeof credentialsSchema>;

/** Read confidential Microsoft credentials for one exact environment, without a platform fallback. */
export function readProjectMicrosoftProvider(env: AuthEnvironment, slug: string): ProjectMicrosoftProvider | undefined {
	const raw = setting(env, "ALLAUTH_PROJECT_MICROSOFT_PROVIDERS").trim();
	if (!raw) return undefined;
	try {
		if (raw.length > 131072 || !/^[a-z][a-z0-9-]{1,47}$/.test(slug)) throw new Error();
		const map: unknown = JSON.parse(raw);
		if (!map || typeof map !== "object" || Array.isArray(map)) throw new Error();
		if (!Object.hasOwn(map, slug)) return undefined;
		return credentialsSchema.parse((map as Record<string, unknown>)[slug]);
	} catch { throw new Error("Microsoft provider configuration is invalid."); }
}

/** Internal cache fingerprint changes only for the selected environment's credentials and account restriction. */
export function microsoftConfigurationVersion(provider: ProjectMicrosoftProvider | undefined): string {
	return provider ? createHash("sha256").update(JSON.stringify(provider)).digest("hex") : "disabled";
}

/** Keep Microsoft's registered Web callback on the selected proxy or verified hosted account origin. */
export function microsoftCallbackURL(realm: { primaryOrigin: string; publicOrigin?: string; basePath: string }): string {
	const origin = realm.publicOrigin || realm.primaryOrigin;
	const parsed = new URL(origin);
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
	if (parsed.origin !== origin || parsed.username || parsed.password || (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:" && !realm.publicOrigin))) throw new Error("Microsoft sign-in requires an exact HTTPS application origin or local development origin.");
	return `${origin}${realm.publicOrigin ? realm.basePath : "/api/allauth"}/callback/microsoft`;
}
