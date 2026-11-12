import { createHash } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToHex, hexToBytes, managedNonce } from "@noble/ciphers/utils.js";

/** Supply only the keys that historically encrypted records in this realm. */
export type LegacyMfaKeys =
	| { secret: string }
	| { currentVersion: number; keys: ReadonlyMap<number, string>; legacySecret?: string };

const versionedRecord = /^\$ba\$(0|[1-9]\d*)\$([a-fA-F0-9]+)$/;

function cipher(secret: string) {
	return managedNonce(xchacha20poly1305)(createHash("sha256").update(secret).digest());
}

/** Open an existing nonce-prefixed XChaCha20-Poly1305 record. */
export function openLegacyMfaRecord(record: string, keys: LegacyMfaKeys): string {
	try {
		if (record.length > 65536) throw new Error("Oversized encrypted record.");
		const envelope = versionedRecord.exec(record);
		const version = envelope ? Number(envelope[1]) : undefined;
		const secret = version === undefined
			? "secret" in keys ? keys.secret : keys.legacySecret
			: "keys" in keys && Number.isSafeInteger(version) ? keys.keys.get(version) : undefined;
		const ciphertext = envelope?.[2] ?? record;
		if (!secret || !/^(?:[a-f0-9]{2}){40,}$/i.test(ciphertext)) {
			throw new Error("Invalid encrypted record.");
		}
		return new TextDecoder("utf-8", { fatal: true }).decode(cipher(secret).decrypt(hexToBytes(ciphertext)));
	} catch {
		throw new Error("Could not read the existing MFA record.");
	}
}

/** Use the existing write format during the rollback window. */
export function sealLegacyMfaRecord(value: string, keys: LegacyMfaKeys): string {
	if ("secret" in keys) {
		if (!keys.secret) throw new Error("No MFA encryption key is configured.");
		return bytesToHex(cipher(keys.secret).encrypt(new TextEncoder().encode(value)));
	}
	const { currentVersion } = keys;
	const secret = keys.keys.get(currentVersion);
	if (!secret || !Number.isSafeInteger(currentVersion) || currentVersion < 0) {
		throw new Error("No active MFA encryption key is configured.");
	}
	const ciphertext = bytesToHex(cipher(secret).encrypt(new TextEncoder().encode(value)));
	return `$ba$${currentVersion}$${ciphertext}`;
}
