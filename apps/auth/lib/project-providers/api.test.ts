import { beforeEach, describe, expect, it, vi } from "vitest";
import { APIError } from "better-auth";
import type { Project } from "../projects/registry";
import type { ControlPrincipal } from "../control/types";
import { googleProviderHandler } from "./api";
import { defaultGoogleProvider } from "./google";

const project = { id: "fixture-project", name: "NativeApp", slug: "nativeapp-development", workspaceId: "fixture-workspace", applicationId: "fixture-app", environment: "development", primaryOrigin: "http://localhost:5100", origins: ["http://localhost:5100"] } as Project;
const actor = { user: { id: "fixture-admin", email: "admin@example.com", emailVerified: true }, session: { id: "fixture-session", userId: "fixture-admin" } } as ControlPrincipal;
const origin = "https://allauth.co";
function setup() {
	const authorize = vi.fn(async () => actor as ControlPrincipal | null);
	const read = vi.fn(async () => ({ ...defaultGoogleProvider(), version: 4, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "fixture-encrypted-not-public" }));
	const update = vi.fn(async () => ({ ...defaultGoogleProvider(), version: 5, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "fixture-encrypted-not-public" }));
	const selected = vi.fn(async () => project);
	const canDisableGoogle = vi.fn(async () => true);
	const handler = googleProviderHandler({ origin, brokerGoogleEnabled: true, project: selected, authorize, read, update, callbackUrls: async () => ["http://localhost:5100/api/allauth/callback/google"], canDisableGoogle });
	const request = (method = "GET", body?: unknown, extra: Record<string, string> = {}) => handler(new Request(`${origin}/api/admin/projects/${project.slug}/providers/google`, { method, headers: { cookie: "fixture-platform-cookie", origin, "content-type": "application/json", ...extra }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }), project.slug);
	return { authorize, read, update, selected, canDisableGoogle, request };
}

describe("Google provider environment administration", () => {
	let state: ReturnType<typeof setup>;
	beforeEach(() => { state = setup(); });
	it("projects safe metadata and exact environment/callback URLs without returning ciphertext", async () => {
		const response = await state.request();
		const result = await response.json() as { project: Record<string, unknown>; [key: string]: unknown };
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(result).toMatchObject({ project: { id: project.id, slug: project.slug, environment: "development" }, version: 4, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com", clientSecretConfigured: true }, effectiveProvider: "google", callbackUrls: ["http://localhost:5100/api/allauth/callback/google"] });
		expect(JSON.stringify(result)).not.toContain("fixture-encrypted");
		expect(result).not.toHaveProperty("encryptedClientSecret");
		expect(result.project).not.toHaveProperty("schemaName");
	});
	it("rejects absent, unverified, banned, impersonated and bearer-only authority before reading secrets", async () => {
		state.authorize.mockResolvedValueOnce(null);
		await expect(state.request()).rejects.toMatchObject({ statusCode: 401 });
		for (const invalid of [{ ...actor, user: { ...actor.user, emailVerified: false } }, { ...actor, user: { ...actor.user, banned: true } }, { ...actor, session: { ...actor.session, impersonatedBy: "other-admin" } }]) {
			state.authorize.mockResolvedValueOnce(invalid);
			await expect(state.request()).rejects.toMatchObject({ statusCode: 403 });
		}
		await expect(state.request("GET", undefined, { authorization: "Bearer tenant-token" })).rejects.toMatchObject({ statusCode: 403 });
		expect(state.read).not.toHaveBeenCalled(); expect(state.update).not.toHaveBeenCalled();
	});
	it("requires an exact-origin bounded versioned write and preserves blank secret input", async () => {
		const body = { version: 4, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com", clientSecret: "" } };
		const rejectedHeaders: Record<string, string>[] = [{ origin: "https://attacker.example" }, { origin: "" }, { "sec-fetch-site": "cross-site" }];
		for (const headers of rejectedHeaders) await expect(state.request("PATCH", body, headers)).rejects.toMatchObject({ statusCode: 403 });
		expect((await state.request("PATCH", body)).status).toBe(200);
		expect(state.update).toHaveBeenCalledWith(project, body, actor.user.id);
		await expect(state.request("PATCH", { ...body, project: "another-production" })).rejects.toThrow();
		await expect(state.request("PATCH", body, { "content-length": "8193" })).rejects.toMatchObject({ statusCode: 413 });
	});
	it("preserves stale-version conflicts and rejects losing the last configured login method", async () => {
		state.update.mockRejectedValueOnce(new APIError("CONFLICT", { message: "Settings changed. Reload them before saving again." }));
		await expect(state.request("PATCH", { version: 3, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com" } })).rejects.toMatchObject({ statusCode: 409 });
		state.canDisableGoogle.mockResolvedValue(false);
		await expect(state.request("PATCH", { version: 4, google: { enabled: false, clientId: "" } })).rejects.toMatchObject({ statusCode: 400 });
	});
	it("requires a real selected environment and never falls back to platform settings", async () => {
		state.selected.mockRejectedValueOnce(new APIError("NOT_FOUND"));
		await expect(state.request()).rejects.toMatchObject({ statusCode: 404 });
		expect(state.authorize).not.toHaveBeenCalled(); expect(state.read).not.toHaveBeenCalled();
	});
});
