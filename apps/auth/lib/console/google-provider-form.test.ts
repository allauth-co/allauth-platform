import { afterEach, describe, expect, it, vi } from "vitest";
import { googleProviderConflict, googleProviderEditor, googleProviderIsDirty, googleProviderPatch, googleProviderRequest, googleProviderValidation } from "@/components/console/google-provider-form";
import type { GoogleProviderSettings } from "@/components/console/google-provider-form";

const saved: GoogleProviderSettings = {
	project: { id: "environment-a", name: "NativeApp", slug: "nativeapp-development", workspaceId: "workspace-a", applicationId: "application-a", environment: "development" },
	version: 7, updatedAt: null,
	google: { enabled: true, clientId: "fixture.apps.googleusercontent.com", clientSecretConfigured: true },
	effectiveProvider: "google", callbackUrls: ["http://localhost:5100/api/allauth/callback/google"],
};
afterEach(() => vi.unstubAllGlobals());

describe("Google provider console form", () => {
	it("starts with a blank replacement secret and excludes unexpected server fields from writes", () => {
		const editor = googleProviderEditor({ ...saved, google: { ...saved.google, clientSecret: "server-value-must-not-be-shown" } } as GoogleProviderSettings);
		expect(editor.clientSecret).toBe("");
		expect(googleProviderIsDirty(editor)).toBe(false);
		expect(googleProviderPatch(editor)).toEqual({ version: 7, google: { enabled: true, clientId: saved.google.clientId } });
	});
	it("preserves the original version and omits a blank secret while switching to AllAuth fallback", () => {
		const editor = { ...googleProviderEditor(saved), enabled: false, clientSecret: "   " };
		expect(googleProviderIsDirty(editor)).toBe(true);
		expect(googleProviderPatch(editor)).toEqual({ version: 7, google: { enabled: false, clientId: saved.google.clientId } });
		expect(editor.base.version).toBe(7);
	});
	it("requires credentials before enabling a new direct connection and accepts a saved secret", () => {
		const editor = googleProviderEditor({ ...saved, google: { enabled: false, clientId: "", clientSecretConfigured: false }, effectiveProvider: "allauth" });
		editor.enabled = true;
		expect(googleProviderValidation(editor)).toContain("client ID");
		editor.clientId = saved.google.clientId;
		expect(googleProviderValidation(editor)).toContain("client secret");
		editor.clientSecret = "fixture-replacement";
		expect(googleProviderValidation(editor)).toBeNull();
		expect(googleProviderPatch(editor).google.clientSecret).toBe("fixture-replacement");
		expect(googleProviderValidation(googleProviderEditor(saved))).toBeNull();
	});
	it("keeps HTTP409 conflicts distinct without returning raw error bodies containing secrets", async () => {
		const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "fixture-private-submitted-secret" }), { status: 409 }));
		vi.stubGlobal("fetch", fetcher);
		let failure: unknown;
		try { await googleProviderRequest("/api/admin/projects/nativeapp-development/providers/google", { method: "PATCH", body: "{}" }); } catch (error) { failure = error; }
		expect(googleProviderConflict(failure)).toBe(true);
		expect(String(failure)).toContain("Reload");
		expect(String(failure)).not.toContain("private");
		expect(fetcher).toHaveBeenCalledWith("/api/admin/projects/nativeapp-development/providers/google", expect.objectContaining({ credentials: "same-origin", cache: "no-store" }));
	});
	it("explains a rejected last-sign-in-method removal without displaying arbitrary server errors", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ error: "Enable another sign-in method before disabling direct Google." }), { status: 400 }))
			.mockResolvedValueOnce(new Response(JSON.stringify({ error: "fixture-private-submitted-secret" }), { status: 400 })));
		await expect(googleProviderRequest("/api/admin/projects/nativeapp-development/providers/google")).rejects.toThrow("Enable another sign-in method");
		await expect(googleProviderRequest("/api/admin/projects/nativeapp-development/providers/google")).rejects.not.toThrow("private");
	});
});
