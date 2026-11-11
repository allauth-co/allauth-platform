import { getCurrentAdapter } from "@better-auth/core/context";
import type { Account } from "@better-auth/core/db";
import { APIError } from "better-auth";
import type { AuthContext, BetterAuthOptions } from "better-auth";
import { decryptOAuthToken } from "better-auth/oauth2";
import { decodeJwt, jwtVerify } from "jose";
import { generateAppleClientSecret } from "./apple";
import type { ProjectAppleProvider } from "./apple";

const guarded = new WeakSet<AuthContext["internalAdapter"]>();
type FailureReason =
	| "APPLE_BROWSER_REAUTHENTICATION_REQUIRED"
	| "APPLE_PROVIDER_CONFIGURATION_REQUIRED"
	| "APPLE_REVOCATION_UNAVAILABLE";
const unavailable = (code: FailureReason = "APPLE_REVOCATION_UNAVAILABLE") =>
	new APIError("SERVICE_UNAVAILABLE", {
		code,
		message:
			"Apple authorization could not be revoked. Retry account deletion or sign in with Apple again.",
	});

async function boundAppleClient(
	context: AuthContext,
	account: Account,
	configured: ProjectAppleProvider,
): Promise<string> {
	if (!account.idToken || !account.accountId || account.idToken.length > 32768)
		throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
	const provider = context.socialProviders.find(
			(value) => value.id === "apple",
		),
		verifier = provider?.idToken;
	if (!verifier || !("jwks" in verifier))
		throw unavailable("APPLE_PROVIDER_CONFIGURATION_REQUIRED");
	try {
		const claims = decodeJwt(account.idToken),
			now = Math.floor(Date.now() / 1000);
		if (
			typeof claims.iat !== "number" ||
			!Number.isSafeInteger(claims.iat) ||
			claims.iat <= 0 ||
			claims.iat > now + 60 ||
			typeof claims.exp !== "number" ||
			claims.exp <= claims.iat
		)
			throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
		// The owning server authorization-code exchange/account row associates this
		// refresh grant with the saved identity. The historical JWT proves issuer,
		// audience and subject; it does not cryptographically bind the opaque grant.
		// The persisted ID token was validated during the server authorization-code
		// exchange. Verify its signature again at its signed issuance time: expiration
		// of that identity proof does not erase the saved refresh grant's client binding.
		const { payload } = await jwtVerify(account.idToken, verifier.jwks, {
			issuer: "https://appleid.apple.com",
			audience: [
				configured.clientId,
				...(configured.appBundleIdentifier
					? [configured.appBundleIdentifier]
					: []),
			],
			algorithms: ["RS256"],
			requiredClaims: ["iss", "aud", "sub", "iat", "exp"],
			currentDate: new Date(claims.iat * 1000),
		});
		if (payload.sub !== account.accountId || typeof payload.aud !== "string")
			throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
		return payload.aud;
	} catch {
		throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
	}
}

/** Revoke only the selected realm's server-obtained Apple refresh grants before erasing their identity rows. */
export async function revokeAppleBeforeUserDeletion<
	Options extends BetterAuthOptions,
>(
	input: AuthContext<Options>,
	userId: string,
	configured: ProjectAppleProvider | undefined,
): Promise<void> {
	// Better Auth's adapter transaction type is invariant in inferred options;
	// this preserves the exact realm instance while using the shared token utility.
	const context = input as unknown as AuthContext;
	try {
		const adapter = await getCurrentAdapter(context.adapter);
		const accounts = await adapter.findMany<Account>({
			model: "account",
			where: [
				{ field: "userId", value: userId },
				{ field: "providerId", value: "apple" },
			],
			limit: 101,
		});
		if (!accounts.length) return;
		if (!configured) throw unavailable("APPLE_PROVIDER_CONFIGURATION_REQUIRED");
		if (accounts.length > 100) throw unavailable();
		for (const account of accounts) {
			if (account.userId !== userId || account.providerId !== "apple")
				throw unavailable();
			if (!account.refreshToken)
				throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
			const clientId = await boundAppleClient(context, account, configured);
			const token = await decryptOAuthToken(account.refreshToken, context);
			if (!token || token.length > 32768)
				throw unavailable("APPLE_BROWSER_REAUTHENTICATION_REQUIRED");
			const body = new URLSearchParams({
				client_id: clientId,
				client_secret: await generateAppleClientSecret({
					...configured,
					clientId,
				}),
				token,
				token_type_hint: "refresh_token",
			});
			const response = await fetch("https://appleid.apple.com/auth/revoke", {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body,
				redirect: "error",
				signal: AbortSignal.timeout(10000),
			});
			// Apple's revoke operation is idempotent for already-invalid tokens. Keep
			// the saved grant intact until user/account erasure so partial failures can
			// retry the same request; acceptance is not proof of all-device sign-out.
			if (response.status !== 200) throw unavailable();
		}
	} catch (error) {
		const code = error instanceof APIError ? error.body?.code : undefined;
		throw unavailable(
			code === "APPLE_BROWSER_REAUTHENTICATION_REQUIRED" ||
				code === "APPLE_PROVIDER_CONFIGURATION_REQUIRED"
				? code
				: "APPLE_REVOCATION_UNAVAILABLE",
		);
	}
}

/** Install after Better Auth constructs its final adapter; includes administrator-triggered deletion. */
export function guardAppleUserDeletion<Options extends BetterAuthOptions>(
	context: AuthContext<Options>,
	configured: ProjectAppleProvider | undefined,
): void {
	const adapter = context.internalAdapter;
	if (guarded.has(adapter)) return;
	const remove = adapter.deleteUser.bind(adapter);
	adapter.deleteUser = async (userId) => {
		await revokeAppleBeforeUserDeletion(context, userId, configured);
		return remove(userId);
	};
	guarded.add(adapter);
}
