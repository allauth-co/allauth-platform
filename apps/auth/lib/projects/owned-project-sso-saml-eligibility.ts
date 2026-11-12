import { createPrivateKey, X509Certificate } from "node:crypto";
import { configureOwnedSaml } from "./owned-project-sso-saml-protocol";

function certificatePem(certificate: string) {
	return certificate.includes("-----BEGIN CERTIFICATE-----")
		? certificate
		: `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
}

/** Check that a persisted plaintext SAML provider can serve the exact selected transport. */
export function checkProjectSamlConfiguration(
	provider: { issuer: string; samlConfig: Record<string, unknown> },
	acs: string,
) {
	try {
		assertProjectSamlConfiguration(provider, acs);
	} catch {
		throw new Error(
			"This configured SAML provider is outside the candidate transport.",
		);
	}
}

function assertProjectSamlConfiguration(
	provider: { issuer: string; samlConfig: Record<string, unknown> },
	acs: string,
) {
	const configuration = configureOwnedSaml(provider.samlConfig, acs);
	const { saved, service, idp, postLocations, requestsSigned } = configuration;
	const logout = service.entityMeta.getSingleLogoutService(undefined);
	if (
		saved.issuer !== provider.issuer ||
		postLocations.length !== 1 ||
		postLocations[0] !== acs ||
		saved.idpInitiatedCallbackUrl ||
		(logout && (!Array.isArray(logout) || logout.length))
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
		const privateKey = saved.spMetadata?.privateKey || saved.privateKey;
		if (!privateKey)
			throw new Error(
				"This configured SAML provider is missing its signing key.",
			);
		const key = createPrivateKey({
			key: privateKey.trim(),
			passphrase: saved.spMetadata?.privateKeyPass,
		});
		if (key.asymmetricKeyType !== "rsa")
			throw new Error(
				"This configured SAML provider uses an unsupported request signing key.",
			);
	}
}
