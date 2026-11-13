import type { JWTPayload } from "jose";
import { validAvatarPath } from "../avatars/protocol";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord } from "./legacy-mfa-record";
import type { LinkedAccountGrant } from "./owned-project-linked-accounts";
import type { ProjectOAuthProvider } from "./owned-project-oauth-store";
import { microsoftEmailVerified } from "./owned-project-provider-tokens";

/** Match existing encrypted and older plaintext provider grant rows. */
export function readLinkedOAuthToken(
	value: string | null,
	keys: LegacyMfaKeys,
) {
	if (!value) return undefined;
	const clear =
		value.startsWith("$ba$") || /^(?:[a-f0-9]{2})+$/i.test(value)
			? openLegacyMfaRecord(value, keys)
			: value;
	if (clear.length > 32768 || /[\u0000-\u0020\u007f]/.test(clear))
		throw new Error("Invalid stored OAuth grant.");
	return clear;
}

function profileImage(value: unknown) {
	if (typeof value !== "string" || value.length > 2048) return undefined;
	try {
		const url = new URL(value);
		if (
			url.protocol === "https:" &&
			!url.username &&
			!url.password &&
			!validAvatarPath(url.pathname)
		)
			return url.href;
	} catch {
		return undefined;
	}
}

/** The projected profile describes a linked account and never grants authentication authority. */
export function linkedProviderProfile(
	account: LinkedAccountGrant,
	provider: ProjectOAuthProvider,
	profile: JWTPayload,
) {
	if (
		(provider === "microsoft" ? profile.oid : profile.sub) !== account.accountId
	)
		throw new Error("Linked provider subject does not match the account.");
	const text = (value: unknown, max: number) =>
		typeof value === "string" &&
		value.length <= max &&
		!/[\u0000-\u001f\u007f]/.test(value)
			? value
			: undefined;
	const emailVerified =
		provider === "microsoft"
			? microsoftEmailVerified(profile)
			: profile.email_verified === true ||
				(provider === "apple" && profile.email_verified === "true");
	const email = text(profile.email, 320);
	const name =
		text(profile.name, 256) ?? (provider === "apple" ? "" : undefined);
	const login = text(profile.login, 256);
	const username = text(profile.username, 256);
	return {
		account: {
			id: account.id,
			accountId: account.accountId,
			providerId: account.providerId,
		},
		user: { name, email, image: profileImage(profile.picture), emailVerified },
		data: { login, username },
	};
}
