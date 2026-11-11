import { afterEach, describe, expect, it, vi } from "vitest";
import type { AllAuthClient } from "./client";
import { addNativePasskey, passkeyBrowserError, passkeyError } from "./passkey";

afterEach(() => vi.unstubAllGlobals());

describe("native passkey failure guidance", () => {
	it.each([
		[{ code: "SESSION_NOT_FRESH" }, /sign out and sign in again/i],
		[{ error: { code: "CHALLENGE_NOT_FOUND", status: 400 } }, /expired.*start again/i],
		[{ status: 400, error: { code: "FAILED_TO_VERIFY_REGISTRATION", message: "Failed to verify registration" } }, /could not be verified.*start setup again/i],
		[{ error: { status: 401 } }, /sign-in has expired/i],
		[{ code: "ERROR_CEREMONY_ABORTED", status: 400 }, /cancelled.*try again/i],
		[{ name: "NotAllowedError", message: "The operation was not allowed" }, /cancelled.*browser/i],
		[{ cause: { name: "NotSupportedError" } }, /browser or device cannot create/i],
		[new Error("WebAuthn is not supported in this browser"), /browser or device cannot create/i],
		[{ code: "ERROR_INVALID_RP_ID", status: 400 }, /not configured.*ERROR_INVALID_RP_ID/i],
		[{ code: "UNKNOWN_PROVIDER_ERROR" }, /UNKNOWN_PROVIDER_ERROR/],
		[{ error: { status: 429 } }, /too many.*wait/i],
		[{ code: "AUTH_CANCELLED", status: 503 }, /temporarily unavailable.*HTTP 503/i],
	])("keeps actionable native details from a wrapped failure", (error, expected) => { expect(passkeyError(error)).toMatch(expected); });

	it("rejects an unsupported or insecure browser without starting the native flow", async () => {
		const addPasskey = vi.fn(); const client = { passkey: { addPasskey } } as unknown as Pick<AllAuthClient, "passkey">;
		vi.stubGlobal("window", { isSecureContext: false }); expect(passkeyBrowserError()).toMatch(/secure HTTPS/i);
		await expect(addNativePasskey(client)).rejects.toThrow(/secure HTTPS/i);
		vi.stubGlobal("window", { isSecureContext: true }); vi.stubGlobal("navigator", {});
		await expect(addNativePasskey(client)).rejects.toThrow(/browser does not support/i); expect(addPasskey).not.toHaveBeenCalled();
	});

	it("preserves native options/verification and converts a mocked failed verify response into guidance", async () => {
		const create = vi.fn(); vi.stubGlobal("window", { isSecureContext: true, PublicKeyCredential: function fixtureCredential() {} }); vi.stubGlobal("navigator", { credentials: { create } });
		const addPasskey = vi.fn().mockResolvedValueOnce({ data: null, error: { status: 400, error: { code: "CHALLENGE_NOT_FOUND" } } }).mockResolvedValueOnce({ data: { id: "fixture-only" }, error: null });
		const client = { passkey: { addPasskey } } as unknown as Pick<AllAuthClient, "passkey">;
		await expect(addNativePasskey(client)).rejects.toThrow(/expired.*start again/i);
		await expect(addNativePasskey(client)).resolves.toBeUndefined(); expect(addPasskey).toHaveBeenCalledWith({ name: "My passkey" });
		expect(create).not.toHaveBeenCalled();
	});
});
