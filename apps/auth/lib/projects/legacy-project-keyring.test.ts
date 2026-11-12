import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { getTestInstance } from "better-auth/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { openLegacyMfaRecord, sealLegacyMfaRecord } from "./legacy-mfa-record";
import { readLegacyProjectKeyring } from "./legacy-project-keyring";

const projectSecret = "isolated-fixture-unversioned-project-key";
const old = "isolated-fixture-previous-versioned-key";
const active = "isolated-fixture-current-versioned-key";

afterEach(() => vi.unstubAllEnvs());

describe("legacy project key ring", () => {
	it("uses the existing derived project key when no versions were configured", () => {
		expect(readLegacyProjectKeyring(projectSecret, undefined)).toEqual({
			signingSecret: projectSecret,
			encryptionKeys: { secret: projectSecret },
		});
	});

	it("matches native signing and reads both historical encryption formats across the switch", async () => {
		const configured = `4:${active},12:${old}`;
		vi.stubEnv("BETTER_AUTH_SECRETS", configured);
		const { auth } = await getTestInstance(
			{ secret: projectSecret },
			{ disableTestUser: true },
		);
		const native = await auth.$context;
		const candidate = readLegacyProjectKeyring(projectSecret, configured);
		expect(candidate.signingSecret).toBe(native.secret);
		expect(candidate.signingSecret).toBe(active);
		const previouslyEncrypted = await symmetricEncrypt({
			key: { keys: new Map([[12, old]]), currentVersion: 12 },
			data: "fixture-previous-version",
		});
		const unversioned = await symmetricEncrypt({
			key: projectSecret,
			data: "fixture-pre-rotation",
		});
		expect(
			openLegacyMfaRecord(previouslyEncrypted, candidate.encryptionKeys),
		).toBe("fixture-previous-version");
		expect(openLegacyMfaRecord(unversioned, candidate.encryptionKeys)).toBe(
			"fixture-pre-rotation",
		);
		const rewritten = sealLegacyMfaRecord(
			"fixture-replacement",
			candidate.encryptionKeys,
		);
		expect(rewritten.startsWith("$ba$4$")).toBe(true);
		expect(
			await symmetricDecrypt({ key: native.secretConfig, data: rewritten }),
		).toBe("fixture-replacement");
	});

	it("rejects duplicate and missing entries without exposing key material", () => {
		for (const value of [`4:${active},4:${old}`, `4:${active},12:`, "invalid"])
			expect(() => readLegacyProjectKeyring(projectSecret, value)).toThrow(
				"The legacy authentication key ring is invalid.",
			);
	});
});
