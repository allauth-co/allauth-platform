import {
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
	AuthenticationResponseJSON,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type { projectPasskeyStore, StoredProjectPasskey } from "./passkey-store";

/** The stored shape shared with existing project WebAuthn ceremonies. */
export interface ProjectPasskeyChallenge {
	type: "registration" | "authentication";
	expectedChallenge: string;
	userData: { id: string };
}

type VerificationFailure =
	| "challenge"
	| "owner"
	| "credential"
	| "verification"
	| "counter";
type Result<Value> =
	| { ok: true; value: Value }
	| { ok: false; reason: VerificationFailure };
type PasskeyVerificationStore = Pick<
	ReturnType<typeof projectPasskeyStore>,
	"findCredential" | "recordAssertion" | "registerForUser"
>;

/**
 * Verify project WebAuthn ceremonies using trusted RP policy and realm storage.
 * The caller verifies the signed challenge cookie and supplies a consumer that
 * atomically returns a single unexpired challenge from the same realm.
 */
export function projectPasskeyVerification(
	store: PasskeyVerificationStore,
	options: {
		rpId: string;
		origins: readonly string[];
		requireUserVerification: boolean;
		consumeChallenge: (token: string) => Promise<ProjectPasskeyChallenge | null>;
	},
) {
	const expected = {
		expectedOrigin: [...options.origins],
		expectedRPID: options.rpId,
		requireUserVerification: options.requireUserVerification,
	};
	return {
		/** Registration is bound to a fresh authenticated account in this realm. */
		async register(input: {
			token: string;
			response: RegistrationResponseJSON;
			name?: string;
			freshUserId: () => Promise<string | null>;
		}): Promise<Result<StoredProjectPasskey>> {
			const userId = await input.freshUserId();
			if (!userId) return { ok: false, reason: "owner" };
			const challenge = await options.consumeChallenge(input.token);
			if (challenge?.type !== "registration") return { ok: false, reason: "challenge" };
			if (challenge.userData.id !== userId) return { ok: false, reason: "owner" };
			let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
			try {
				verification = await verifyRegistrationResponse({
					...expected,
					expectedChallenge: challenge.expectedChallenge,
					response: input.response,
				});
			} catch {
				return { ok: false, reason: "verification" };
			}
			if (!verification.verified) return { ok: false, reason: "verification" };
			const {
				credential,
				aaguid,
				credentialBackedUp,
				credentialDeviceType,
			} = verification.registrationInfo;
			const stored = await store.registerForUser(userId, {
				...credential,
				name: input.name,
				aaguid,
				backedUp: credentialBackedUp,
				deviceType: credentialDeviceType,
				transports: input.response.response.transports,
			});
			return stored ? { ok: true, value: stored } : { ok: false, reason: "credential" };
		},

		/** Return a verified account only after the credential counter is committed. */
		async authenticate(input: {
			token: string;
			response: AuthenticationResponseJSON;
		}): Promise<Result<{ userId: string }>> {
			const challenge = await options.consumeChallenge(input.token);
			if (challenge?.type !== "authentication") return { ok: false, reason: "challenge" };
			const stored = await store.findCredential(input.response.id);
			if (!stored) return { ok: false, reason: "credential" };
			// A discoverable sign-in can select any credential in this realm.
			// A challenge issued with an account allowlist stays bound to it.
			if (challenge.userData.id && challenge.userData.id !== stored.userId)
				return { ok: false, reason: "owner" };
			let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
			try {
				verification = await verifyAuthenticationResponse({
					...expected,
					expectedChallenge: challenge.expectedChallenge,
					response: input.response,
					credential: {
						id: stored.credentialID,
						publicKey: isoBase64URL.toBuffer(stored.publicKey, "base64"),
						counter: stored.counter,
					},
				});
			} catch {
				return { ok: false, reason: "verification" };
			}
			if (!verification.verified) return { ok: false, reason: "verification" };
			if (!await store.recordAssertion(stored, verification.authenticationInfo.newCounter))
				return { ok: false, reason: "counter" };
			return { ok: true, value: { userId: stored.userId } };
		},
	};
}
