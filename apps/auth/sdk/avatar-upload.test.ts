// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example"}

import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AllAuthProvider, UserProfile } from "./react";
import { normalizeProfileImage, uploadProfileImage } from "./avatar-upload";

const native = vi.hoisted(() => ({ updateUser: vi.fn(), getSession: vi.fn(), refetch: vi.fn(), listAccounts: vi.fn() }));
vi.mock("./client", () => ({ createAllAuthClient: () => ({
	useSession: () => ({ data: { user: { id: "photo-user", name: "Photo User", email: "photo@example.test", emailVerified: true, image: "https://assets.example.test/original.png" }, session: { id: "photo-session" } }, isPending: false, error: null, refetch: native.refetch }),
	updateUser: native.updateUser, getSession: native.getSession, listAccounts: native.listAccounts,
}) }));

const uploadedUrl = "https://assets.allauth.co/avatars/fixture/new-photo.webp";
let container: HTMLDivElement; let root: Root;
let close: ReturnType<typeof vi.fn>; let draw: ReturnType<typeof vi.fn>;
beforeEach(() => {
	vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
	for (const method of Object.values(native)) method.mockReset().mockResolvedValue({ data: {}, error: null });
	native.listAccounts.mockResolvedValue({ data: [], error: null });
	close = vi.fn(); draw = vi.fn();
	vi.stubGlobal("createImageBitmap", vi.fn(async () => ({ width: 4000, height: 2000, close })));
	vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({ drawImage: draw } as unknown as CanvasRenderingContext2D);
	vi.spyOn(HTMLCanvasElement.prototype, "toBlob").mockImplementation((callback) => callback(new Blob([new Uint8Array([1, 2, 3])], { type: "image/webp" })));
	vi.stubGlobal("fetch", vi.fn(async () => Response.json({ url: uploadedUrl })));
	container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("native profile photo preparation", () => {
	it("rejects unsupported, empty and oversized source files before decoding or uploading", async () => {
		await expect(normalizeProfileImage(new File(["svg"], "photo.svg", { type: "image/svg+xml" }))).rejects.toThrow("PNG, JPG or WebP");
		await expect(normalizeProfileImage(new File([], "empty.png", { type: "image/png" }))).rejects.toThrow("not empty");
		await expect(normalizeProfileImage(new File([new Uint8Array(5 * 1024 * 1024 + 1)], "large.jpg", { type: "image/jpeg" }))).rejects.toThrow("5 MB");
		expect(createImageBitmap).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
	});

	it("preserves aspect ratio within 512px and reduces encoded bytes below 128KiB", async () => {
		vi.mocked(HTMLCanvasElement.prototype.toBlob).mockImplementationOnce((callback) => callback(new Blob([new Uint8Array(180000)], { type: "image/webp" })))
			.mockImplementationOnce((callback) => callback(new Blob([new Uint8Array(100000)], { type: "image/webp" })));
		const result = await normalizeProfileImage(new File(["source"], "source.jpg", { type: "image/jpeg" }));
		expect(draw).toHaveBeenCalledWith(expect.anything(), 0, 0, 512, 256);
		expect(HTMLCanvasElement.prototype.toBlob).toHaveBeenCalledTimes(2);
		expect(result.contentType).toBe("image/webp"); expect(atob(result.data)).toHaveLength(100000);
		expect(close).toHaveBeenCalledOnce();
	});

	it("reduces dimensions when a browser falls back to lossless PNG and quality alone cannot meet the bound", async () => {
		vi.mocked(HTMLCanvasElement.prototype.toBlob).mockImplementation(function (this: HTMLCanvasElement, callback) {
			callback(new Blob([new Uint8Array(this.width > 384 ? 180000 : 100000)], { type: "image/png" }));
		});
		const result = await normalizeProfileImage(new File(["source"], "source.png", { type: "image/png" }));
		expect(result.contentType).toBe("image/png"); expect(atob(result.data).length).toBeLessThanOrEqual(128 * 1024);
		expect(draw).toHaveBeenLastCalledWith(expect.anything(), 0, 0, 384, 192);
		expect(close).toHaveBeenCalledOnce();
	});

	it("uses the same-origin signed JSON upload contract and accepts only an HTTPS result", async () => {
		const payload = { contentType: "image/webp" as const, data: "AQID" };
		await expect(uploadProfileImage("/api/allauth", payload)).resolves.toBe(uploadedUrl);
		expect(fetch).toHaveBeenCalledWith("/api/allauth/sdk/avatar", expect.objectContaining({ method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }));
		for (const url of ["javascript:alert(1)", "http://foreign.example/photo.png", "https://user:password@assets.example/photo.png"]) {
			vi.mocked(fetch).mockResolvedValueOnce(Response.json({ url }));
			await expect(uploadProfileImage("/api/allauth", payload)).rejects.toThrow("invalid image URL");
		}
		vi.mocked(fetch).mockResolvedValueOnce(Response.json({ message: "Image storage is unavailable." }, { status: 503 }));
		await expect(uploadProfileImage("/api/allauth", payload)).rejects.toThrow("Image storage is unavailable");
	});
});

describe("shared native profile photo editor", () => {
	async function render(available: boolean, onUpdated = vi.fn()) {
		await act(async () => root.render(createElement(AllAuthProvider, { capabilities: { emailPassword: true, organizations: true, google: false, twoFactor: false, profileImageUpload: available }, children: createElement(UserProfile, { section: "profile", embedded: true, onUpdated }) })));
		const edit = [...container.querySelectorAll("button")].find((button) => button.textContent === "Update profile");
		await act(async () => edit?.click());
	}
	it("hides upload when storage is unavailable and keeps the optional URL editor collapsed", async () => {
		await render(false);
		expect(container.querySelector('input[type="file"]')).toBeNull(); expect(container.textContent).toContain("Photo upload is not available");
		expect(container.querySelector(".allauth-avatar-advanced")?.hasAttribute("open")).toBe(false);
		expect(native.updateUser).not.toHaveBeenCalled();
	});

	it("uploads a draft first, then applies the photo only through explicit native Save profile and fresh session refresh", async () => {
		const onUpdated = vi.fn(); await render(true, onUpdated);
		const picker = container.querySelector('input[type="file"]') as HTMLInputElement;
		Object.defineProperty(picker, "files", { value: [new File(["source"], "photo.jpg", { type: "image/jpeg" })] });
		await act(async () => picker.dispatchEvent(new Event("change", { bubbles: true })));
		expect(fetch).toHaveBeenCalledOnce(); expect(native.updateUser).not.toHaveBeenCalled(); expect(native.getSession).not.toHaveBeenCalled();
		expect(container.textContent).toContain("Photo ready. Save your profile to apply it.");
		expect(container.querySelector('.allauth-avatar-upload img')?.getAttribute("src")).toBe(uploadedUrl);
		const form = container.querySelector("form");
		if (!form) throw new Error("Missing profile form");
		await act(async () => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
		expect(native.updateUser).toHaveBeenCalledWith({ name: "Photo User", image: uploadedUrl });
		expect(native.getSession).toHaveBeenCalledWith({ query: { disableCookieCache: true } }); expect(native.refetch).toHaveBeenCalled(); expect(onUpdated).toHaveBeenCalledOnce();
	});
});
