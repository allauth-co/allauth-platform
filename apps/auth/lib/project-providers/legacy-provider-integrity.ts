import { verifyProviderIdToken } from "@better-auth/core/oauth2";
import { APIError } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";

/** Add nonce binding around the existing native Apple provider without bypassing its token verifier. */
export function appleIntegrity(): BetterAuthPlugin {
	return {
		id: "allauth-apple-integrity",
		init(ctx) {
			const provider = ctx.socialProviders.find(
				(value) => value.id === "apple",
			);
			if (!provider) return;
			provider.requiresIdTokenNonce = true;
			const nativeAuthorization = provider.createAuthorizationURL;
			provider.createAuthorizationURL = async (input) => {
				if (!input.idTokenNonce)
					throw new APIError("BAD_REQUEST", {
						message: "Apple sign-in requires a fresh authorization attempt.",
					});
				const url = await nativeAuthorization(input);
				// Apply the server-generated nonce after native reserved-parameter filtering.
				url.searchParams.set("nonce", input.idTokenNonce);
				return url;
			};
			const nativeUserInfo = provider.getUserInfo;
			provider.getUserInfo = async (tokens) => {
				// Native Apple profile parsing decodes the token. Verify its signature,
				// audience, issuer and state-bound nonce before that parsing can run.
				if (
					!tokens.idToken ||
					!(await verifyProviderIdToken(
						provider,
						tokens.idToken,
						tokens.expectedIdTokenNonce,
					))
				)
					return null;
				const result = await nativeUserInfo(tokens);
				if (!result?.user || result.user.email) return result;
				// Apple may omit email after first consent. Recover it only through the
				// cryptographically verified stable subject in this realm's adapter.
				const subject = await provider.accountSubject({
					tokens,
					profile: result.data,
				});
				if (
					typeof subject !== "string" ||
					!subject.trim() ||
					subject.length > 512
				)
					return null;
				const existing = await ctx.internalAdapter.findAccountOwnerByKey({
					providerId: provider.id,
					accountId: subject,
				});
				if (!existing || existing.kind !== "owned") return result;
				return {
					...result,
					user: {
						...result.user,
						email: existing.user.email,
						emailVerified: existing.user.emailVerified,
						name: result.user.name || existing.user.name,
					},
				};
			};
		},
	};
}

/** Verify the native Microsoft's token contract and state-bound nonce before parsing its profile. */
export function microsoftIntegrity(): BetterAuthPlugin {
	return {
		id: "allauth-microsoft-integrity",
		init(ctx) {
			const provider = ctx.socialProviders.find(
				(value) => value.id === "microsoft",
			);
			if (!provider) return;
			provider.requiresIdTokenNonce = true;
			const nativeAuthorization = provider.createAuthorizationURL;
			provider.createAuthorizationURL = async (input) => {
				if (!input.idTokenNonce)
					throw new APIError("BAD_REQUEST", {
						message:
							"Microsoft sign-in requires a fresh authorization attempt.",
					});
				const url = await nativeAuthorization(input);
				url.searchParams.set("nonce", input.idTokenNonce);
				return url;
			};
			const nativeUserInfo = provider.getUserInfo;
			provider.getUserInfo = async (tokens) => {
				if (
					!tokens.idToken ||
					!(await verifyProviderIdToken(
						provider,
						tokens.idToken,
						tokens.expectedIdTokenNonce,
					))
				)
					return null;
				return nativeUserInfo(tokens);
			};
		},
	};
}
