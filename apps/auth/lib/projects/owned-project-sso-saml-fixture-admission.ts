import { createHash } from "node:crypto";

type FixtureProvider = {
	id: string;
	providerId: string;
	issuer: string;
	domain: string;
	organizationId: string | null;
	oidcConfig?: unknown;
	samlConfig?: Record<string, unknown>;
};

export type ProjectEncryptedSamlFixtureAdmission = Readonly<{
	projectId: string;
	schemaName: string;
	providerId: string;
	recordId: string;
	configurationDigest: string;
}>;

/** The isolated rehearsal pins one exact stored provider without sending its keys to the selector. */
export function encryptedSamlFixtureConfigurationDigest(
	provider: FixtureProvider,
) {
	return createHash("sha256")
		.update(
			JSON.stringify([
				provider.issuer,
				provider.domain,
				provider.organizationId,
				provider.samlConfig,
			]),
		)
		.digest("base64url");
}

export function allowsEncryptedSamlFixtureProvider(
	admission: ProjectEncryptedSamlFixtureAdmission | undefined,
	schemaName: string,
	provider: FixtureProvider,
) {
	if (admission?.providerId !== provider.providerId) return false;
	if (
		admission.schemaName !== schemaName ||
		admission.recordId !== provider.id ||
		provider.oidcConfig ||
		!provider.samlConfig ||
		admission.configurationDigest !==
			encryptedSamlFixtureConfigurationDigest(provider)
	)
		throw new Error("The encrypted SAML fixture provider changed.");
	return true;
}
