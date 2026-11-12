import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { describe, expect, it } from "vitest";
import { openLegacyMfaRecord, sealLegacyMfaRecord } from "./legacy-mfa-record";

const oldSecret = "isolated-historical-mfa-key-in-a-synthetic-fixture";
const newSecret = "isolated-current-mfa-key-in-a-synthetic-fixture";
const keys = {
	currentVersion: 3,
	keys: new Map([[1, oldSecret], [3, newSecret]]),
	legacySecret: oldSecret,
};

describe("rollback-compatible MFA records", () => {
	it("reads bare legacy TOTP and records encrypted before and after rotation", async () => {
		const bare = await symmetricEncrypt({ key: oldSecret, data: "synthetic-totp-secret" });
		const rotated = await symmetricEncrypt({
			key: { ...keys, currentVersion: 1 }, data: '["used-one","unused-two"]',
		});
		expect(openLegacyMfaRecord(bare, { secret: oldSecret })).toBe("synthetic-totp-secret");
		expect(openLegacyMfaRecord(bare, keys)).toBe("synthetic-totp-secret");
		expect(openLegacyMfaRecord(rotated, keys)).toBe('["used-one","unused-two"]');
	});

	it("writes records the previous engine can read with its existing key settings", async () => {
		const remaining = '["unused-two"]';
		const bare = sealLegacyMfaRecord(remaining, { secret: oldSecret });
		const rotated = sealLegacyMfaRecord(remaining, keys);
		expect(rotated).toMatch(/^\$ba\$3\$/);
		await expect(symmetricDecrypt({ key: oldSecret, data: bare })).resolves.toBe(remaining);
		await expect(symmetricDecrypt({ key: keys, data: rotated })).resolves.toBe(remaining);
	});

	it("rejects ciphertext corruption, missing historical keys and other realm keys", () => {
		const original = sealLegacyMfaRecord("synthetic-totp-secret", keys);
		const damaged = original.slice(0, -2) + (original.endsWith("ff") ? "00" : "ff");
		for (const [record, ring] of [
			[damaged, keys],
			[original.replace("$3$", "$2$"), keys],
			[original, { ...keys, keys: new Map([[3, oldSecret]]) }],
		] as const) {
			expect(() => openLegacyMfaRecord(record, ring)).toThrow("Could not read the existing MFA record.");
		}
	});
});
