import { createHmac, randomBytes } from "node:crypto";

export const ownedSCIMScopes = [
	"scim.users.read",
	"scim.users.write",
	"scim.groups.read",
	"scim.groups.write",
] as const;
export const ownedSCIMCredentialHashVersion = "v1";
export const ownedSCIMLastUsedIntervalMs = 300_000;
export const ownedSCIMConnectionPrefix = "ba_scim_connection_";
export const ownedSCIMCredentialPrefix = "ba_scim_credential_";
export type OwnedSCIMScope = (typeof ownedSCIMScopes)[number];

export function parseOwnedSCIMScopes(
	value: string,
): readonly OwnedSCIMScope[] | undefined {
	try {
		const parsed: unknown = JSON.parse(value);
		if (
			Array.isArray(parsed) &&
			parsed.length > 0 &&
			new Set(parsed).size === parsed.length &&
			parsed.every((scope: unknown): scope is OwnedSCIMScope =>
				ownedSCIMScopes.some((known) => known === scope),
			)
		)
			return parsed;
	} catch {
		return;
	}
}

export function ownedSCIMCredentialDigest(secret: string, token: string) {
	return createHmac("sha256", secret).update(token).digest("base64url");
}

export function ownedSCIMCredentialId(token: string) {
	return /^(ba_scim_credential_[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(
		token,
	)?.[1];
}

export function newOwnedSCIMConnectionId() {
	return `${ownedSCIMConnectionPrefix}${randomBytes(24).toString("base64url")}`;
}

export function newOwnedSCIMCredential(secret: string) {
	const credentialId = `${ownedSCIMCredentialPrefix}${randomBytes(24).toString("base64url")}`;
	const token = `${credentialId}.${randomBytes(36).toString("base64url")}`;
	return {
		credentialId,
		token,
		tokenDigest: ownedSCIMCredentialDigest(secret, token),
	};
}
