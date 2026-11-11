import { compare } from "bcryptjs";
import { hashPassword, verifyPassword } from "better-auth/crypto";

/** Accept only explicit bcrypt encodings with a bounded verification cost. */
export function isClerkBcryptHash(value: string): boolean {
	const match = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/.exec(value);
	return Boolean(match && Number(match[1]) >= 4 && Number(match[1]) <= 14);
}

/** Preserve native scrypt credentials; legacy bcrypt is accepted only for verification. */
export const clerkCompatiblePasswords = {
	hash: hashPassword,
	async verify(input: { hash: string; password: string }): Promise<boolean> {
		try {
			if (isClerkBcryptHash(input.hash)) return await compare(input.password, input.hash);
			if (/^[a-f0-9]{32}:[a-f0-9]{128}$/.test(input.hash)) return await verifyPassword(input);
			return false;
		} catch {
			return false;
		}
	},
};
