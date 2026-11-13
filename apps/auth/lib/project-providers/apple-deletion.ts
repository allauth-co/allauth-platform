import { getCurrentAdapter } from "@better-auth/core/context";
import type { AuthContext, BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth";
import { decryptOAuthToken } from "better-auth/oauth2";
import type { ProjectAppleProvider } from "./apple";
import type {
	AppleAccountGrant,
	AppleRevocationFailure,
} from "./apple-grant-revocation";
import {
	appleRevocationMessage,
	maximumAppleAccounts,
	revokeAppleAccountGrants,
} from "./apple-grant-revocation";

const guarded = new WeakSet<AuthContext["internalAdapter"]>();

/** Revoke the owning realm's Apple grants before native account or administrator deletion. */
export async function revokeAppleBeforeUserDeletion<
	Options extends BetterAuthOptions,
>(
	input: AuthContext<Options>,
	userId: string,
	configured: ProjectAppleProvider | undefined,
): Promise<void> {
	// The adapter's transaction type is invariant in its inferred options.
	const context = input as unknown as AuthContext;
	let failure: AppleRevocationFailure | null;
	try {
		const adapter = await getCurrentAdapter(context.adapter);
		const accounts = await adapter.findMany<AppleAccountGrant>({
			model: "account",
			where: [
				{ field: "userId", value: userId },
				{ field: "providerId", value: "apple" },
			],
			limit: maximumAppleAccounts + 1,
		});
		const verifier = context.socialProviders.find(
			(value) => value.id === "apple",
		)?.idToken;
		failure = await revokeAppleAccountGrants({
			accounts,
			userId,
			configured,
			key: verifier && "jwks" in verifier ? verifier.jwks : undefined,
			readToken: (token) => decryptOAuthToken(token, context),
		});
	} catch {
		failure = "APPLE_REVOCATION_UNAVAILABLE";
	}
	if (failure)
		throw new APIError("SERVICE_UNAVAILABLE", {
			code: failure,
			message: appleRevocationMessage,
		});
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
