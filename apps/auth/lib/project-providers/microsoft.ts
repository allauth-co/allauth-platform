import { createHash } from "node:crypto";
import { verifyProviderIdToken } from "@better-auth/core/oauth2";
import { APIError } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
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

/** Verify the native Microsoft's token contract and state-bound nonce before parsing its profile. */
export function microsoftIntegrity(): BetterAuthPlugin {
	return { id: "allauth-microsoft-integrity", init(ctx) {
		const provider = ctx.socialProviders.find(value => value.id === "microsoft");
		if (!provider) return;
		provider.requiresIdTokenNonce = true;
		const nativeAuthorization = provider.createAuthorizationURL;
		provider.createAuthorizationURL = async input => {
			if (!input.idTokenNonce) throw new APIError("BAD_REQUEST", { message: "Microsoft sign-in requires a fresh authorization attempt." });
			const url = await nativeAuthorization(input);
			url.searchParams.set("nonce", input.idTokenNonce);
			return url;
		};
		const nativeUserInfo = provider.getUserInfo;
		provider.getUserInfo = async tokens => {
			if (!tokens.idToken || !await verifyProviderIdToken(provider, tokens.idToken, tokens.expectedIdTokenNonce)) return null;
			return nativeUserInfo(tokens);
		};
	} };
}
