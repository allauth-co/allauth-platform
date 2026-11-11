import { createHash } from "node:crypto";
import * as z from "zod";
import { setting } from "./configuration";
import type { AuthEnvironment } from "./configuration";
import type { PasskeyOptions } from "@better-auth/passkey";

const applicationId = z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){1,10}$/);
const exactHttpsOrigin = z.string().url().refine((value) => {
	const url = new URL(value);
	return value === url.origin && url.protocol === "https:" && !url.username && !url.password && !url.port && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$/.test(url.hostname) && !url.hostname.endsWith(".localhost") && !url.hostname.endsWith(".internal") && !url.hostname.endsWith(".local");
});
const policySchema = z.object({
	enabled: z.literal(true), projectId: z.uuid(), environment: z.enum(["development", "production"]), rpOrigin: exactHttpsOrigin,
	ios: z.object({ teamId: z.string().regex(/^[A-Z0-9]{10}$/), bundleId: applicationId }).strict().optional(),
	android: z.array(z.object({ packageName: applicationId, certificateSha256: z.string().regex(/^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/) }).strict()).max(10).default([]),
}).strict().refine((value) => Boolean(value.ios || value.android.length), "Declare an approved native application.");

export interface NativePasskeyCapability { enabled: boolean; ios: boolean; android: boolean; rpId?: string }
export interface SelectedNativePasskeys extends NativePasskeyCapability { version: string; rpOrigin?: string; expectedOrigins: string[] }
const disabled = (): SelectedNativePasskeys => ({ enabled: false, ios: false, android: false, version: "disabled", expectedOrigins: [] });

/** Only server-owned signing identities for this immutable project/environment can extend WebAuthn origins. */
export function selectedNativePasskeys(env: AuthEnvironment, project: { id: string; slug: string; environment: "development" | "production"; primaryOrigin: string }, publicOrigin?: string): SelectedNativePasskeys {
	try {
		const source = setting(env, "ALLAUTH_PROJECT_NATIVE_PASSKEYS");
		if (!source || source.length > 65536) return disabled();
		const entries: unknown = JSON.parse(source);
		if (!entries || typeof entries !== "object" || Array.isArray(entries) || !Object.hasOwn(entries, project.slug)) return disabled();
		const parsed = policySchema.safeParse((entries as Record<string, unknown>)[project.slug]);
		if (!parsed.success) return disabled();
		const policy = parsed.data;
		if (policy.projectId !== project.id || policy.environment !== project.environment || policy.rpOrigin !== (publicOrigin || project.primaryOrigin)) return disabled();
		const androidOrigins = policy.android.map((app) => {
			const bytes = Uint8Array.from(app.certificateSha256.split(":"), (value) => Number.parseInt(value, 16));
			return `android:apk-key-hash:${btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "")}`;
		});
		const expectedOrigins = [...new Set([policy.rpOrigin, ...androidOrigins])];
		return { enabled: true, ios: Boolean(policy.ios), android: androidOrigins.length > 0, rpId: new URL(policy.rpOrigin).hostname, rpOrigin: policy.rpOrigin, expectedOrigins, version: createHash("sha256").update(JSON.stringify(policy)).digest("hex") };
	} catch { return disabled(); }
}

/** Public capability excludes policy records, application identities and configuration digests. */
export function nativePasskeyCapability(selected?: SelectedNativePasskeys): NativePasskeyCapability {
	return selected?.enabled ? { enabled: true, ios: selected.ios, android: selected.android, rpId: selected.rpId } : { enabled: false, ios: false, android: false };
}

/** Keep the RP fixed to this realm, and opt only an exactly matching policy into native verification. */
export function realmPasskeyOptions(origin: string, rpName: string, selected?: SelectedNativePasskeys): PasskeyOptions {
	const configured = selected?.enabled && selected.rpOrigin === origin && selected.rpId === new URL(origin).hostname;
	return { rpID: new URL(origin).hostname, rpName, origin: configured ? selected.expectedOrigins : origin,
		...(configured ? { requireUserVerification: true, authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" } } : {}),
	};
}
