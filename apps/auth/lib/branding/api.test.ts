import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";
import type { ApplicationSettings } from "./types";
import { defaultApplicationBranding } from "./validation";
import { applicationAssetRequest, applicationSettingsRequest, boundedBrandingBody } from "./api";

const origin = "http://localhost:3000";
const environment: AuthEnvironment = { BETTER_AUTH_URL: origin, ALLAUTH_ASSET_ORIGIN: "https://assets.allauth.co", ALLAUTH_ASSET_SECRET: "fixture-branding-storage-secret-longer-than-thirty-two" };
const mocks = vi.hoisted(() => ({ instance: undefined as unknown as AuthInstance, env: {} as AuthEnvironment, getProject: vi.fn(), read: vi.fn(), write: vi.fn(), store: vi.fn(), tenant: vi.fn() }));
vi.mock("../auth", () => ({ withAuth: (callback: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>) => callback(mocks.instance, mocks.env) }));
vi.mock("../projects/runtime", () => ({ projectInstance: () => undefined, selectedProjectAdministrator: vi.fn(), withProjectAuth: mocks.tenant }));
vi.mock("../projects/registry", () => ({ getProject: mocks.getProject }));
vi.mock("./repository", () => ({ readApplicationSettings: mocks.read, writeApplicationSettings: mocks.write, settingsConflict: "Application settings changed. Reload before saving." }));
vi.mock("./storage-client", () => ({ storeBrandingAsset: mocks.store }));

const applicationId = "0da0e1b9-bb92-4182-8bfb-cbed290b0c19";
const workspaceId = "75458045-7c45-49cc-83de-a56a7b5d19c3";
const assetUrl = `https://assets.allauth.co/branding/${workspaceId}/${applicationId}/00000000-0000-4000-8000-000000000005.png`;
async function setup() {
	const fixture = await getTestInstance({ plugins: [admin()], session: { cookieCache: { enabled: true } }, logger: { disabled: true } }, { disableTestUser: true });
	const context = await fixture.auth.$context;
	const result = await fixture.auth.api.signUpEmail({ body: { email: "owner@fixture.example", password: "fixture-branding-password", name: "Workspace Owner" } });
	await context.adapter.update({ model: "user", where: [{ field: "id", value: result.user.id }], update: { emailVerified: true } });
	const login = await fixture.auth.api.signInEmail({ body: { email: "owner@fixture.example", password: "fixture-branding-password" }, asResponse: true });
	const cookie = login.headers.getSetCookie().map((entry) => entry.split(";", 1)[0]).join("; ");
	const settings: ApplicationSettings = { applicationId, workspaceId, version: 0, branding: defaultApplicationBranding("Application"), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), storage: { available: true, maxFileSize: 2097152, formats: ["image/png"] } };
	mocks.instance = fixture.auth as unknown as AuthInstance; mocks.env = environment; mocks.getProject.mockResolvedValue({ id: "fixture-selected-project" }); mocks.read.mockResolvedValue(settings); mocks.write.mockResolvedValue({ ...settings, version: 1 }); mocks.store.mockResolvedValue(assetUrl);
	const request = (method = "GET", body?: unknown, headers: Record<string, string> = {}, query = "project=fixture-app") => applicationSettingsRequest(new Request(`${origin}/api/admin/application-settings?${query}`, { method, headers: { cookie, ...(body === undefined ? {} : { origin, "content-type": "application/json" }), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
	const upload = (form: FormData, headers: Record<string, string> = {}) => applicationAssetRequest(new Request(`${origin}/api/admin/application-settings/assets?project=fixture-app`, { method: "POST", headers: { cookie, origin, ...headers }, body: form }));
	const form = (type = "image/png") => { const form = new FormData(); form.set("kind", "logo"); form.set("version", "0"); form.set("file", new Blob([Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh1kAAAAASUVORK5CYII=", "base64"))], { type }), "logo.png"); return form; };
	return { fixture, context, cookie, userId: result.user.id, settings, request, upload, form };
}

describe("application settings native-cookie API", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => { vi.clearAllMocks(); state = await setup(); });
	it("authenticates the root cookie for a selected application, preserving no-store and avoiding tenant auth dispatch", async () => {
		const response = await state.request(); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store"); expect(await response.json()).toEqual(state.settings); expect(mocks.tenant).not.toHaveBeenCalled();
		expect(mocks.read.mock.calls[0]?.[1]).toMatchObject({ user: { id: state.userId, emailVerified: true }, session: { userId: state.userId } });
	});
	it("rejects bearer, anonymous/tenant-only cookies, impersonation and fresh verification revocation before accessing settings", async () => {
		expect((await state.request("GET", undefined, { authorization: "Bearer fixture" })).status).toBe(403);
		expect((await state.request("GET", undefined, { cookie: "allauth_project_fixture-app.session_token=forged" })).status).toBe(401);
		const current = await state.fixture.auth.api.getSession({ headers: new Headers({ cookie: state.cookie }) });
		await state.context.adapter.update({ model: "session", where: [{ field: "id", value: current!.session.id }], update: { impersonatedBy: "fixture-other-user" } }); expect((await state.request()).status).toBe(403);
		await state.context.adapter.update({ model: "session", where: [{ field: "id", value: current!.session.id }], update: { impersonatedBy: null } });
		await state.context.adapter.update({ model: "user", where: [{ field: "id", value: state.userId }], update: { emailVerified: false } }); expect((await state.request()).status).toBe(403); expect(mocks.read).not.toHaveBeenCalled(); expect(mocks.write).not.toHaveBeenCalled();
	});
	it("requires exact-origin writes, strict complete fields and one selected project", async () => {
		const payload = { version: 0, branding: state.settings.branding };
		const invalidHeaders: Record<string, string>[] = [{ origin: "https://evil.example" }, { origin: "" }, { origin, "sec-fetch-site": "cross-site" }];
		for (const headers of invalidHeaders) expect((await state.request("PATCH", payload, headers)).status).toBe(403);
		for (const query of ["", "project=fixture-app&project=other-app", "project=fixture-app&workspaceId=forged"]) expect((await state.request("GET", undefined, {}, query)).status).toBe(400);
		expect((await state.request("PATCH", { ...payload, workspaceId })).status).toBe(400); expect((await state.request("PATCH", { ...payload, branding: { ...payload.branding, secret: "hidden" } })).status).toBe(400);
		expect((await state.request("PATCH", payload)).status).toBe(200); expect(mocks.write.mock.calls[0]?.[0]).toBe("fixture-selected-project"); expect(mocks.write.mock.calls[0]?.[2]).toBe(0);
	});
	it("returns honest workspace denial and version conflicts without calling storage", async () => {
		mocks.read.mockRejectedValueOnce(new APIError("FORBIDDEN")); expect((await state.upload(state.form())).status).toBe(403); expect(mocks.store).not.toHaveBeenCalled();
		mocks.write.mockRejectedValueOnce(new APIError("CONFLICT", { message: "Application settings changed. Reload before saving." })); const response = await state.request("PATCH", { version: 0, branding: state.settings.branding }); expect(response.status).toBe(409); expect(await response.json()).toEqual({ error: "Application settings changed. Reload before saving." });
	});
	it("validates uploads before storage and saves only the chosen field with the initial expected version", async () => {
		const response = await state.upload(state.form()); expect(response.status).toBe(201); expect(await response.json()).toEqual({ url: assetUrl, settings: { ...state.settings, version: 1 } });
		expect(mocks.write.mock.calls[0]?.[3]).toEqual({ asset: { kind: "logo", url: assetUrl } });
		mocks.store.mockClear(); expect((await state.upload(state.form("image/jpeg"))).status).toBe(400);
		const duplicate = state.form(); duplicate.append("file", new Blob(["bad"]), "other.png"); expect((await state.upload(duplicate)).status).toBe(400);
		const stale = state.form(); stale.set("version", "1"); expect((await state.upload(stale)).status).toBe(409);
		const injected = state.form(); injected.set("applicationId", "other"); expect((await state.upload(injected)).status).toBe(400); expect(mocks.store).not.toHaveBeenCalled();
	});
	it("cancels an unbounded stream as soon as the cap is crossed", async () => {
		let pulls = 0; let cancelled = false;
		const body = new ReadableStream<Uint8Array>({ pull(controller) { pulls++; controller.enqueue(new Uint8Array(1024)); }, cancel() { cancelled = true; } });
		const request = new Request(`${origin}/api/admin/application-settings`, { method: "POST", body, duplex: "half" } as RequestInit);
		await expect(boundedBrandingBody(request, 1500)).rejects.toMatchObject({ statusCode: 413 }); expect(cancelled).toBe(true); expect(pulls).toBeLessThanOrEqual(3);
	});
});
