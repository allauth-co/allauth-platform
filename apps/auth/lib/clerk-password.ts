import { scrypt, timingSafeEqual } from "node:crypto";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { compare } from "bcryptjs";
import { isNodeRuntime } from "./runtime";

const nativeHash = /^([a-f0-9]{32}):([a-f0-9]{128})$/;
const scryptOptions = { N: 16384, r: 16, p: 1, maxmem: 64 * 1024 * 1024 };
const keyLength = 64;

function derivePasswordKey(password: string, salt: string): Promise<Uint8Array> {
	// Existing records use the hex salt as text and normalize only scrypt passwords.
	const normalized = password.normalize("NFKC");
	if (!isNodeRuntime()) {
		return scryptAsync(normalized, salt, { ...scryptOptions, dkLen: keyLength });
	}
	return new Promise((resolve, reject) => {
		scrypt(normalized, salt, keyLength, scryptOptions, (error, key) => {
			if (error) reject(error);
			else resolve(key);
		});
	});
}

/** Accept only explicit bcrypt encodings with a bounded verification cost. */
export function isClerkBcryptHash(value: string): boolean {
	const match = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/.exec(value);
	return Boolean(match && Number(match[1]) >= 4 && Number(match[1]) <= 14);
}

/** Preserve native scrypt credentials; legacy bcrypt is accepted only for verification. */
export const clerkCompatiblePasswords = {
	async hash(password: string): Promise<string> {
		const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
		const key = await derivePasswordKey(password, salt);
		return `${salt}:${bytesToHex(key)}`;
	},
	async verify(input: { hash: string; password: string }): Promise<boolean> {
		try {
			if (isClerkBcryptHash(input.hash)) return await compare(input.password, input.hash);
			const match = nativeHash.exec(input.hash);
			if (!match) return false;
			const [, salt, key] = match;
			return timingSafeEqual(await derivePasswordKey(input.password, salt), hexToBytes(key));
		} catch {
			return false;
		}
	},
};
