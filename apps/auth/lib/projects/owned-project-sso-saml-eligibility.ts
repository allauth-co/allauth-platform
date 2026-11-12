import { createPrivateKey, X509Certificate } from "node:crypto";
import {
	configureOwnedSaml,
	declaredSignedSamlAcs,
} from "./owned-project-sso-saml-protocol";

function certificatePem(certificate: string) {
	return certificate.includes("-----BEGIN CERTIFICATE-----")
		? certificate
		: `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
}

export type AuthorizeCustomSamlAcs = (
	url: string,
	providerId: string,
) => Promise<boolean>;

export interface ProjectCustomSamlTransport {
	authorizeAcs: AuthorizeCustomSamlAcs;
}

type StoredSamlProvider = {
	issuer: string;
	samlConfig: Record<string, unknown>;
};

/** Check that a persisted SAML provider can serve the exact selected transport. */
export function checkProjectSamlConfiguration(
	provider: StoredSamlProvider,
	acs: string,
	generatedSPOnly?: boolean,
	allowEncrypted?: boolean,
) {
	try {
		const configured = configureOwnedSaml(provider.samlConfig, acs, {
			generatedSPOnly,
			allowEncrypted,
		});
		assertProjectSamlConfiguration(provider, acs, configured, allowEncrypted);
	} catch {
		throw new Error(
			"This configured SAML provider is outside the candidate transport.",
		);
	}
}

/** Resolve the saved receiver through project transport authority before configuring the protocol. */
export async function configureProjectSamlTransport(
	provider: StoredSamlProvider & { providerId: string },
	localAcs: string,
	options: {
		generatedSPOnly?: boolean;
		allowEncrypted?: boolean;
		customTransport?: ProjectCustomSamlTransport;
		relayState?: string;
		validateAll?: boolean;
	},
) {
	const authorize = options.customTransport?.authorizeAcs;
	const declared =
		authorize &&
		declaredSignedSamlAcs(provider.samlConfig, options.allowEncrypted);
	if (
		authorize &&
		declared !== undefined &&
		!(await authorize(declared, provider.providerId))
	)
		throw new Error(
			"This configured SAML provider is outside the candidate transport.",
		);
	const acs = declared ?? localAcs;
	const configured = configureOwnedSaml(provider.samlConfig, acs, {
		generatedSPOnly: options.generatedSPOnly && !authorize,
		allowEncrypted: options.allowEncrypted,
		relayState: options.relayState,
	});
	const custom = declared !== undefined;
	if (custom || options.validateAll)
		assertProjectSamlConfiguration(
			provider,
			acs,
			configured,
			options.allowEncrypted,
		);
	return { configured, acs, custom };
}

function assertProjectSamlConfiguration(
	provider: StoredSamlProvider,
	acs: string,
	configuration: ReturnType<typeof configureOwnedSaml>,
	allowEncrypted?: boolean,
) {
	const { saved, service, idp, postLocations, requestsSigned } = configuration;
	if (
		saved.issuer !== provider.issuer ||
		configuration.encrypted !== Boolean(allowEncrypted) ||
		postLocations.length !== 1 ||
		postLocations[0] !== acs
	)
		throw new Error(
			"This configured SAML provider is outside the candidate transport.",
		);

	const certificate = idp.entityMeta.getX509Certificate("signing");
	for (const signingCertificate of Array.isArray(certificate)
		? certificate
		: [certificate]) {
		const key = new X509Certificate(certificatePem(signingCertificate))
			.publicKey;
		if (!["rsa", "ec"].includes(key.asymmetricKeyType ?? ""))
			throw new Error(
				"This configured SAML provider uses an unsupported signing certificate.",
			);
	}
	if (requestsSigned) {
		const privateKey = service.entitySetting.privateKey;
		if (!privateKey)
			throw new Error(
				"This configured SAML provider is missing its signing key.",
			);
		const key = createPrivateKey({
			key: privateKey,
			passphrase: saved.spMetadata?.privateKeyPass,
		});
		if (key.asymmetricKeyType !== "rsa")
			throw new Error(
				"This configured SAML provider uses an unsupported request signing key.",
			);
		if (saved.spMetadata?.metadata) {
			if (
				(key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 ||
				!idp.entityMeta.isWantAuthnRequestsSigned()
			)
				throw new Error(
					"This configured SAML provider has incompatible request signing settings.",
				);
			const declared = service.entityMeta.getX509Certificate("signing");
			const certificates = Array.isArray(declared)
				? declared
				: declared
					? [declared]
					: [];
			if (
				certificates.length &&
				!certificates.some((certificate) =>
					new X509Certificate(certificatePem(certificate)).checkPrivateKey(key),
				)
			)
				throw new Error(
					"The configured SAML service metadata does not describe the request signing key.",
				);
		}
	}
}
