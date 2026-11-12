import { hash as bcryptHash } from "bcryptjs";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { clerkCompatiblePasswords, isClerkBcryptHash } from "./clerk-password";

afterEach(() => vi.unstubAllEnvs());

describe("Clerk credential compatibility", () => {
	it("verifies imported bcrypt without changing its Unicode normalization", async () => {
		const password = "e\u0301-legacy-password";
		const hash = await bcryptHash(password, 4);
		expect(await clerkCompatiblePasswords.verify({ hash, password })).toBe(true);
		expect(await clerkCompatiblePasswords.verify({ hash, password: password.normalize("NFKC") })).toBe(false);
		expect(await clerkCompatiblePasswords.verify({ hash, password: "wrong" })).toBe(false);
	});
	it.each(["node", "worker"])("reads legacy scrypt and writes rollback-compatible credentials on %s", async (runtime) => {
		vi.stubEnv("AUTH_RUNTIME", runtime);
		vi.stubEnv("RAILWAY_SERVICE_ID", undefined);
		const password = "e\u0301-native-password";
		const normalized = password.normalize("NFKC");
		const legacy = await hashPassword(password);
		expect(await clerkCompatiblePasswords.verify({ hash: legacy, password: normalized })).toBe(true);
		expect(await clerkCompatiblePasswords.verify({ hash: legacy, password: "wrong" })).toBe(false);
		const hash = await clerkCompatiblePasswords.hash(password);
		expect(hash).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
		expect(hash.split(":")[0]).not.toBe(legacy.split(":")[0]);
		expect(await verifyPassword({ hash, password: normalized })).toBe(true);
	});
	it.each(["plaintext", "$2b$31$" + "a".repeat(53), "$2x$04$" + "a".repeat(53), "aa:bb", "", "$argon2id$unhandled"])("rejects malformed or unsupported digests safely", async (hash) => {
		expect(await clerkCompatiblePasswords.verify({ hash, password: "fixture" })).toBe(false);
	});
	it("bounds imported bcrypt work factors", () => {
		expect(isClerkBcryptHash("$2b$12$" + "a".repeat(53))).toBe(true);
		expect(isClerkBcryptHash("$2b$15$" + "a".repeat(53))).toBe(false);
	});
});
