import { createHmac, timingSafeEqual } from "node:crypto";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const encoder = new TextEncoder();

/** Existing MFA secrets are UTF-8 keys; the authenticator URI encodes those bytes as Base32. */
export function ownedMfaTotpUri(secret: string, issuer: string, email: string) {
	let bits = 0;
	let remaining = 0;
	let base32 = "";
	for (const byte of encoder.encode(secret)) {
		bits = (bits << 8) | byte;
		remaining += 8;
		while (remaining >= 5) {
			remaining -= 5;
			base32 += alphabet[(bits >>> remaining) & 31];
		}
	}
	if (remaining) base32 += alphabet[(bits << (5 - remaining)) & 31];
	const query = new URLSearchParams({
		secret: base32,
		issuer,
		digits: "6",
		period: "30",
	});
	return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${query}`;
}

/** Match existing six-digit SHA-1 TOTP enrolments and their ±1 step window. */
export function verifyOwnedMfaTotp(
	secret: string,
	code: string,
	now = Date.now(),
) {
	if (!/^[0-9]{6}$/.test(code)) return false;
	const clock = Math.floor(now / 30_000);
	const input = new Uint8Array(8);
	const counter = new DataView(input.buffer);
	const submitted = encoder.encode(code);
	let valid = false;
	for (const offset of [-1, 0, 1]) {
		counter.setBigUint64(0, BigInt(clock + offset));
		const mac = createHmac("sha1", secret).update(input).digest();
		const index = mac[mac.length - 1]! & 15;
		const value = new DataView(
			mac.buffer,
			mac.byteOffset,
			mac.byteLength,
		).getUint32(index);
		const expected = encoder.encode(
			String((value & 0x7fff_ffff) % 1_000_000).padStart(6, "0"),
		);
		valid = timingSafeEqual(submitted, expected) || valid;
	}
	return valid;
}
