import { createHash } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToHex, hexToBytes, managedNonce } from "@noble/ciphers/utils.js";

function recordCipher(secret: string) {
	return managedNonce(xchacha20poly1305)(
		createHash("sha256").update(secret).digest(),
	);
}

/** Read the existing hex-encoded nonce and authenticated ciphertext with the supplied key. */
export function openLegacyUnversionedRecord(
	record: string,
	secret: string,
	decodeOptions?: TextDecoderOptions,
): string {
	const plaintext = recordCipher(secret).decrypt(hexToBytes(record));
	return new TextDecoder("utf-8", decodeOptions).decode(plaintext);
}

/** Preserve the existing unversioned write format for stored project credentials. */
export function sealLegacyUnversionedRecord(
	value: string,
	secret: string,
): string {
	return bytesToHex(
		recordCipher(secret).encrypt(new TextEncoder().encode(value)),
	);
}
