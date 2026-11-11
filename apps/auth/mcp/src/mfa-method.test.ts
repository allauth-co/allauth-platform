import { describe, expect, it, vi } from "vitest";
import { promptMFAMethod } from "./login.js";

describe("terminal MFA method selection", () => {
	it("lets an accidental code be corrected before native verification, with every input hidden", async () => {
		const prompt = vi
			.fn()
			.mockResolvedValueOnce("123456")
			.mockResolvedValueOnce("");
		await expect(promptMFAMethod(prompt)).resolves.toBe("totp");
		expect(prompt).toHaveBeenCalledTimes(2);
		expect(prompt.mock.calls.every(([, secret]) => secret === true)).toBe(true);
		expect(prompt.mock.calls[1]![0]).toContain("method first, not the code");
	});
	it("keeps recovery available without revealing or reusing accidental input", async () => {
		const prompt = vi
			.fn()
			.mockResolvedValueOnce("a mistaken recovery code")
			.mockResolvedValueOnce(" recovery ");
		await expect(promptMFAMethod(prompt)).resolves.toBe("recovery");
	});
	it("bounds invalid selection retries and never includes the entered value in the error", async () => {
		const prompt = vi.fn().mockResolvedValue("private-input");
		await expect(promptMFAMethod(prompt)).rejects.toThrow(
			"Choose totp or recovery before entering a code",
		);
		expect(prompt).toHaveBeenCalledTimes(3);
	});
});
