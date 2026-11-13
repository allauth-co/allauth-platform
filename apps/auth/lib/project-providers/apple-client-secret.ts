import { importPKCS8, SignJWT } from "jose";
import type { ProjectAppleProvider } from "./apple";

/** Mint a short-lived Apple client secret from the selected project's signing key. */
export async function generateAppleClientSecret(
	provider: Pick<
		ProjectAppleProvider,
		"clientId" | "teamId" | "keyId" | "privateKey"
	>,
): Promise<string> {
	const key = await importPKCS8(provider.privateKey, "ES256");
	const issuedAt = Math.floor(Date.now() / 1000);
	return new SignJWT({})
		.setProtectedHeader({ alg: "ES256", kid: provider.keyId })
		.setIssuer(provider.teamId)
		.setSubject(provider.clientId)
		.setAudience("https://appleid.apple.com")
		.setIssuedAt(issuedAt)
		.setExpirationTime(issuedAt + 7 * 24 * 60 * 60)
		.sign(key);
}
