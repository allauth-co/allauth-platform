import { createHash } from "node:crypto";
import * as z from "zod";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
export { generateAppleClientSecret } from "./apple-client-secret";

const identifier = z.string().trim().min(3).max(255).regex(/^[A-Za-z0-9][A-Za-z0-9.-]+$/);
const credentialsSchema = z.object({
	clientId: identifier,
	teamId: z.string().regex(/^[A-Z0-9]{10}$/),
	keyId: z.string().regex(/^[A-Z0-9]{10}$/),
	privateKey: z.string().min(80).max(8192).refine(value => /^-----BEGIN PRIVATE KEY-----\r?\n[\s\S]+\r?\n-----END PRIVATE KEY-----\s*$/.test(value)),
	appBundleIdentifier: identifier.optional(),
}).strict();
export type ProjectAppleProvider = z.infer<typeof credentialsSchema>;

/** Read credentials for one exact environment; never borrow platform or another tenant's key. */
export function readProjectAppleProvider(env: AuthEnvironment, slug: string): ProjectAppleProvider | undefined {
	const raw = setting(env, "ALLAUTH_PROJECT_APPLE_PROVIDERS").trim();
	if (!raw) return undefined;
	try {
		if (raw.length > 131072 || !/^[a-z][a-z0-9-]{1,47}$/.test(slug)) throw new Error();
		const map: unknown = JSON.parse(raw);
		if (!map || typeof map !== "object" || Array.isArray(map)) throw new Error();
		if (!Object.hasOwn(map, slug)) return undefined;
		return credentialsSchema.parse((map as Record<string, unknown>)[slug]);
	} catch { throw new Error("Apple provider configuration is invalid."); }
}

/** Internal cache fingerprint; never serialize the underlying credential map. */
export function appleConfigurationVersion(provider: ProjectAppleProvider | undefined): string {
	return provider ? createHash("sha256").update(JSON.stringify(provider)).digest("hex") : "disabled";
}

/** Apple's browser OAuth return URL must be an exact HTTPS callback. */
export function appleCallbackURL(realm: { primaryOrigin: string; publicOrigin?: string; basePath: string }): string {
	const origin = realm.publicOrigin || realm.primaryOrigin;
	const parsed = new URL(origin);
	if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.username || parsed.password) throw new Error("Apple sign-in requires an exact HTTPS application origin.");
	return `${origin}${realm.publicOrigin ? realm.basePath : "/api/allauth"}/callback/apple`;
}
