import type { JWTVerifyGetKey } from "jose";
import { decodeJwt, jwtVerify } from "jose";
import type { ProjectAppleProvider } from "./apple";
import { generateAppleClientSecret } from "./apple-client-secret";

export interface AppleAccountGrant {
	userId: string;
	providerId: string;
	accountId: string;
	idToken?: string | null;
	refreshToken?: string | null;
}

export type AppleRevocationFailure =
	| "APPLE_BROWSER_REAUTHENTICATION_REQUIRED"
	| "APPLE_PROVIDER_CONFIGURATION_REQUIRED"
	| "APPLE_REVOCATION_UNAVAILABLE";

export const appleRevocationMessage =
	"Apple authorization could not be revoked. Retry account deletion or sign in with Apple again.";
export const maximumAppleAccounts = 100;

const issuer = "https://appleid.apple.com";
const reauthenticate = "APPLE_BROWSER_REAUTHENTICATION_REQUIRED";

async function boundClient(
	idToken: string,
	subject: string,
	configured: ProjectAppleProvider,
	key: JWTVerifyGetKey,
) {
	try {
		const { iat, exp } = decodeJwt(idToken);
		const now = Math.floor(Date.now() / 1000);
		if (
			typeof iat !== "number" ||
			!Number.isSafeInteger(iat) ||
			iat <= 0 ||
			iat > now + 60 ||
			typeof exp !== "number" ||
			exp <= iat
		)
			return null;
		// A stored ID token attests the original client and subject even after
		// expiry. The persisted account associates its opaque refresh grant.
		const { payload } = await jwtVerify(idToken, key, {
			issuer,
			audience: configured.appBundleIdentifier
				? [configured.clientId, configured.appBundleIdentifier]
				: configured.clientId,
			algorithms: ["RS256"],
			requiredClaims: ["iss", "aud", "sub", "iat", "exp"],
			currentDate: new Date(iat * 1000),
		});
		return payload.sub === subject && typeof payload.aud === "string"
			? payload.aud
			: null;
	} catch {
		return null;
	}
}

/** Revoke only refresh grants tied to the selected project's Apple credentials. */
export async function revokeAppleAccountGrants({
	accounts,
	userId,
	configured,
	key,
	readToken,
	request = fetch,
}: {
	accounts: readonly AppleAccountGrant[];
	userId: string;
	configured?: ProjectAppleProvider;
	key?: JWTVerifyGetKey;
	readToken(token: string): string | Promise<string>;
	request?: typeof fetch;
}): Promise<AppleRevocationFailure | null> {
	if (!accounts.length) return null;
	if (!configured) return "APPLE_PROVIDER_CONFIGURATION_REQUIRED";
	if (accounts.length > maximumAppleAccounts)
		return "APPLE_REVOCATION_UNAVAILABLE";
	try {
		for (const account of accounts) {
			if (account.userId !== userId || account.providerId !== "apple")
				return "APPLE_REVOCATION_UNAVAILABLE";
			if (
				!account.refreshToken ||
				!account.idToken ||
				!account.accountId ||
				account.idToken.length > 32768
			)
				return reauthenticate;
			if (!key) return "APPLE_PROVIDER_CONFIGURATION_REQUIRED";
			const clientId = await boundClient(
				account.idToken,
				account.accountId,
				configured,
				key,
			);
			if (!clientId) return reauthenticate;
			const token = await readToken(account.refreshToken);
			if (!token || token.length > 32768) return reauthenticate;
			const response = await request(`${issuer}/auth/revoke`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					client_id: clientId,
					client_secret: await generateAppleClientSecret({
						...configured,
						clientId,
					}),
					token,
					token_type_hint: "refresh_token",
				}),
				redirect: "error",
				signal: AbortSignal.timeout(10_000),
			});
			// Apple returns 200 for both a newly invalidated and an already
			// invalidated grant. Keep the local grant available for retry.
			if (response.status !== 200) return "APPLE_REVOCATION_UNAVAILABLE";
		}
		return null;
	} catch {
		return "APPLE_REVOCATION_UNAVAILABLE";
	}
}
