import { X509Certificate } from "node:crypto";

export interface StoredProjectSsoProvider {
	id: string;
	providerId: string;
	issuer: string;
	domain: string;
	domainVerified: boolean | null;
	organizationId: string | null;
	userId: string;
	oidcConfig: string | null;
	samlConfig: string | null;
}

function object(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

export function readStoredSsoConfiguration(value: string | null) {
	if (!value) return undefined;
	try {
		return object(JSON.parse(value));
	} catch {
		return undefined;
	}
}

function string(value: unknown) {
	return value === null || typeof value === "string" ? value : undefined;
}

function boolean(value: unknown) {
	return value === null || typeof value === "boolean" ? value : undefined;
}

function certificateSummaries(config: Record<string, unknown>) {
	const certs = object(config.idpMetadata)?.cert ?? config.cert;
	if (certs === undefined) return undefined;
	return (Array.isArray(certs) ? certs : [certs]).map((value: unknown) => {
		try {
			if (typeof value !== "string") throw new Error();
			const pem = value.includes("-----BEGIN")
				? value
				: `-----BEGIN CERTIFICATE-----\n${value}\n-----END CERTIFICATE-----`;
			const cert = new X509Certificate(pem);
			return {
				fingerprintSha256: cert.fingerprint256,
				notBefore: cert.validFrom,
				notAfter: cert.validTo,
				publicKeyAlgorithm:
					cert.publicKey.asymmetricKeyType?.toUpperCase() || "UNKNOWN",
			};
		} catch {
			return { error: "Failed to parse certificate" };
		}
	});
}

/** Public management projection keeps credential objects, mappings and metadata documents server-only. */
export function projectSsoProviderResponse(
	provider: StoredProjectSsoProvider,
	baseURL: string,
) {
	const oidc = readStoredSsoConfiguration(provider.oidcConfig);
	const saml = readStoredSsoConfiguration(provider.samlConfig);
	const clientId = typeof oidc?.clientId === "string" ? oidc.clientId : "";
	const scopes = oidc?.scopes;
	return {
		providerId: provider.providerId,
		type: saml ? "saml" : "oidc",
		issuer: provider.issuer,
		domain: provider.domain,
		organizationId: provider.organizationId || null,
		domainVerified: provider.domainVerified ?? false,
		oidcConfig: oidc
			? {
					discoveryEndpoint: string(oidc.discoveryEndpoint),
					clientIdLastFour:
						clientId.length > 4 ? `****${clientId.slice(-4)}` : "****",
					pkce: boolean(oidc.pkce),
					authorizationEndpoint: string(oidc.authorizationEndpoint),
					tokenEndpoint: string(oidc.tokenEndpoint),
					userInfoEndpoint: string(oidc.userInfoEndpoint),
					jwksEndpoint: string(oidc.jwksEndpoint),
					scopes:
						scopes === null ||
						(Array.isArray(scopes) &&
							scopes.every((item: unknown) => typeof item === "string"))
							? scopes
							: undefined,
					tokenEndpointAuthentication: string(oidc.tokenEndpointAuthentication),
				}
			: undefined,
		samlConfig: saml
			? {
					entryPoint: string(saml.entryPoint),
					callbackUrl: string(saml.callbackUrl),
					idpInitiatedCallbackUrl: string(saml.idpInitiatedCallbackUrl),
					audience: string(saml.audience),
					wantAssertionsSigned: boolean(saml.wantAssertionsSigned),
					authnRequestsSigned: boolean(saml.authnRequestsSigned),
					identifierFormat: string(saml.identifierFormat),
					signatureAlgorithm: string(saml.signatureAlgorithm),
					digestAlgorithm: string(saml.digestAlgorithm),
					certificate: certificateSummaries(saml),
				}
			: undefined,
		spMetadataUrl: `${baseURL}/sso/saml2/sp/metadata?providerId=${encodeURIComponent(provider.providerId)}`,
	};
}
