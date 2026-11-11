import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApplicationSettings } from "@/lib/branding/types";
import {
	brandingAfterUpload,
	brandingIsDirty,
	brandingPatch,
	brandingValidation,
	uploadApplicationBranding,
	validateBrandingAsset,
} from "./branding-form";

const saved: ApplicationSettings = {
	applicationId: "application-a",
	workspaceId: "workspace-a",
	version: 7,
	branding: {
		name: "Example app",
		supportEmail: "support@example.com",
		logoUrl: null,
		logoDarkUrl: null,
		faviconUrl: "https://assets.allauth.co/branding/workspace-a/application-a/favicon.png",
		primaryColor: "#315bff",
		darkPrimaryColor: "#7892ff",
		showPoweredBy: true,
	},
	createdAt: "2026-10-07T00:00:00.000Z",
	updatedAt: "2026-10-07T00:00:00.000Z",
	storage: {
		available: true,
		maxFileSize: 2_097_152,
		formats: ["image/png", "image/jpeg", "image/webp", "image/x-icon"],
	},
};

afterEach(() => vi.unstubAllGlobals());

describe("application branding form state", () => {
	it("does not mark formatting-only differences dirty or serialize server fields", () => {
		const branding = Object.assign({}, saved.branding, {
			name: "  Example app  ",
			primaryColor: "#315BFF",
			updatedAt: "untrusted-extra-field",
		});
		const editor = { base: saved, branding };
		expect(brandingIsDirty(editor)).toBe(false);
		expect(brandingPatch(editor)).toEqual({ version: 7, branding: saved.branding });
	});

	it("preserves explicit asset removal, blank support email and false attribution", () => {
		const editor = {
			base: saved,
			branding: {
				...saved.branding,
				supportEmail: " ",
				faviconUrl: null,
				showPoweredBy: false,
			},
		};
		expect(brandingIsDirty(editor)).toBe(true);
		expect(brandingPatch(editor)).toEqual({
			version: 7,
			branding: { ...saved.branding, supportEmail: null, faviconUrl: null, showPoweredBy: false },
		});
	});

	it("keeps unsaved details and removals when an immediate logo upload advances the version", () => {
		const editor = {
			base: saved,
			branding: { ...saved.branding, name: "Unsaved name", faviconUrl: null },
		};
		const uploaded = {
			...saved,
			version: 8,
			branding: { ...saved.branding, logoUrl: "https://assets.allauth.co/branding/workspace-a/application-a/new.png" },
		};
		const next = brandingAfterUpload(editor, "logo", uploaded);
		expect(next.base).toEqual(uploaded);
		expect(next.branding).toEqual({ ...editor.branding, logoUrl: uploaded.branding.logoUrl });
		expect(brandingIsDirty(next)).toBe(true);
		expect(brandingPatch(next).version).toBe(8);
	});

	it("an upload alone leaves no pending draft and cannot be rebased onto another application", () => {
		const uploaded = {
			...saved,
			version: 8,
			branding: { ...saved.branding, logoDarkUrl: "https://assets.allauth.co/branding/workspace-a/application-a/dark.webp" },
		};
		const editor = { base: saved, branding: saved.branding };
		expect(brandingIsDirty(brandingAfterUpload(editor, "logoDark", uploaded))).toBe(false);
		expect(() => brandingAfterUpload(editor, "logo", { ...uploaded, applicationId: "application-b" })).toThrow("different application");
		expect(() => brandingAfterUpload(editor, "logo", { ...uploaded, workspaceId: "workspace-b" })).toThrow("different application");
	});

	it("a background refresh cannot silently advance the version of a pending edit", () => {
		const editor = { base: saved, branding: { ...saved.branding, name: "Draft" } };
		const newerSavedSettings = { ...saved, version: 9 };
		expect(editor.base.version).not.toBe(newerSavedSettings.version);
		expect(brandingPatch(editor).version).toBe(7);
	});

	it("validates colors, email and required name before submitting a full object", () => {
		expect(brandingValidation(saved.branding)).toBeNull();
		expect(brandingValidation({ ...saved.branding, name: " " })).toMatch(/name/);
		expect(brandingValidation({ ...saved.branding, name: "a".repeat(101) })).toMatch(/100/);
		expect(brandingValidation({ ...saved.branding, supportEmail: "bad email" })).toMatch(/email/);
		expect(brandingValidation({ ...saved.branding, primaryColor: "#fff" })).toMatch(/six-digit/);
		expect(brandingValidation({ ...saved.branding, darkPrimaryColor: "red" })).toMatch(/six-digit/);
	});
});

describe("application brand asset upload", () => {
	it("accepts supported logo files and exactly the maximum size, rejecting SVG and oversized files", () => {
		for (const type of ["image/png", "image/jpeg", "image/webp"])
			expect(() => validateBrandingAsset("logo", { type, name: "logo", size: 2_097_152 }, 2_097_152)).not.toThrow();
		expect(() => validateBrandingAsset("logo", { type: "image/svg+xml", name: "logo.svg", size: 20 }, 2_097_152)).toThrow("PNG, JPG or WebP");
		expect(() => validateBrandingAsset("logoDark", { type: "image/png", name: "logo.png", size: 2_097_153 }, 2_097_152)).toThrow("2 MB");
		expect(() => validateBrandingAsset("logo", { type: "image/png", name: "logo.png", size: 0 }, 2_097_152)).toThrow("empty");
	});

	it("limits favicon uploads to PNG and ICO, including the browser's ICO MIME alias", () => {
		for (const type of ["image/png", "image/x-icon", "image/vnd.microsoft.icon", ""])
			expect(() => validateBrandingAsset("favicon", { type, name: "favicon.ico", size: 32 }, 2_097_152)).not.toThrow();
		expect(() => validateBrandingAsset("favicon", { type: "image/webp", name: "favicon.webp", size: 32 }, 2_097_152)).toThrow("PNG or ICO");
	});

	it("sends an authenticated multipart request with the selected kind and exact optimistic version", async () => {
		const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ url: "uploaded-url", settings: saved }), { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);
		const file = new File([new Uint8Array([1, 2])], "logo.png", { type: "image/png" });
		const path = "/api/admin/application-settings/assets?project=selected-project";
		expect(await uploadApplicationBranding(path, "logoDark", file, 7)).toEqual({ url: "uploaded-url", settings: saved });
		const [calledPath, request] = fetchMock.mock.calls[0]!;
		expect(calledPath).toBe(path);
		expect(request?.method).toBe("POST");
		expect(request?.credentials).toBe("same-origin");
		expect(request?.cache).toBe("no-store");
		expect(new Headers(request?.headers).has("content-type")).toBe(false);
		expect(request?.body).toBeInstanceOf(FormData);
		const body = request?.body as FormData;
		expect(body.get("kind")).toBe("logoDark");
		expect(body.get("version")).toBe("7");
		expect((body.get("file") as File).name).toBe("logo.png");
	});

	it("canonicalizes a browser's missing ICO MIME before the server validates its bytes", async () => {
		const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ url: "uploaded-url", settings: saved })));
		vi.stubGlobal("fetch", fetchMock);
		await uploadApplicationBranding("/assets?project=a", "favicon", new File([new Uint8Array([0, 0, 1])], "favicon.ico"), 7);
		const body = fetchMock.mock.calls[0]![1]?.body as FormData;
		expect((body.get("file") as File).type).toBe("image/x-icon");
	});

	it("keeps a server version conflict visible instead of presenting an uploaded asset as successful", async () => {
		vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ error: "Application settings changed. Reload before saving." }), { status: 409 })));
		await expect(uploadApplicationBranding("/assets?project=a", "logo", new File(["x"], "logo.png", { type: "image/png" }), 7)).rejects.toMatchObject({ status: 409, message: "Application settings changed. Reload before saving." });
	});
});
