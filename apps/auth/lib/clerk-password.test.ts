import { hash as bcryptHash } from "bcryptjs";
import { hashPassword } from "better-auth/crypto";
import { describe, expect, it } from "vitest";
import { clerkCompatiblePasswords, isClerkBcryptHash } from "./clerk-password";

describe("Clerk credential compatibility", () => {
	it("verifies imported bcrypt without changing its Unicode normalization", async () => {
		const password = "e\u0301-legacy-password";
		const hash = await bcryptHash(password, 4);
		expect(await clerkCompatiblePasswords.verify({ hash, password })).toBe(true);
		expect(await clerkCompatiblePasswords.verify({ hash, password: password.normalize("NFKC") })).toBe(false);
		expect(await clerkCompatiblePasswords.verify({ hash, password: "wrong" })).toBe(false);
	});
	it("retains native scrypt credentials and writes new passwords as scrypt", async () => {
		const hash = await hashPassword("existing-native-password");
		expect(await clerkCompatiblePasswords.verify({ hash, password: "existing-native-password" })).toBe(true);
		expect(await clerkCompatiblePasswords.verify({ hash, password: "wrong" })).toBe(false);
		expect(await clerkCompatiblePasswords.hash("new-native-password")).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
	});
	it.each(["plaintext", "$2b$31$" + "a".repeat(53), "$2x$04$" + "a".repeat(53), "aa:bb", "", "$argon2id$unhandled"])("rejects malformed or unsupported digests safely", async (hash) => {
		expect(await clerkCompatiblePasswords.verify({ hash, password: "fixture" })).toBe(false);
	});
	it("bounds imported bcrypt work factors", () => {
		expect(isClerkBcryptHash("$2b$12$" + "a".repeat(53))).toBe(true);
		expect(isClerkBcryptHash("$2b$15$" + "a".repeat(53))).toBe(false);
	});
});
