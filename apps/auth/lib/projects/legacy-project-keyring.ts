import type { LegacyMfaKeys } from "./legacy-mfa-record";

/** Read the active signing key and the exact legacy encryption key ring. */
export function readLegacyProjectKeyring(
	projectSecret: string,
	configured: string | undefined,
): { signingSecret: string; encryptionKeys: LegacyMfaKeys } {
	if (!configured)
		return {
			signingSecret: projectSecret,
			encryptionKeys: { secret: projectSecret },
		};

	const keys = new Map<number, string>();
	for (const entry of configured.split(",")) {
		const colon = entry.indexOf(":");
		const version = Number.parseInt(entry.slice(0, colon), 10);
		const value = entry.slice(colon + 1).trim();
		if (
			colon === -1 ||
			!Number.isSafeInteger(version) ||
			version < 0 ||
			!value ||
			keys.has(version)
		)
			throw new Error("The legacy authentication key ring is invalid.");
		keys.set(version, value);
	}
	const active = keys.entries().next();
	if (active.done)
		throw new Error("The legacy authentication key ring has no active key.");
	const [currentVersion, signingSecret] = active.value;
	return {
		signingSecret,
		encryptionKeys: { currentVersion, keys, legacySecret: projectSecret },
	};
}
