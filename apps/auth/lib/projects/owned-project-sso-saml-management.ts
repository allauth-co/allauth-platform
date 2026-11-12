import * as z from "zod";
import { ssoHttpsUrl } from "./owned-project-sso-network";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureOwnedSaml } from "./owned-project-sso-saml-protocol";

const identifier = z.string().min(1).max(2048);
const metadata = z.string().min(1).max(102400);
const certificate = z.string().min(1).max(16384);
const cert = z.union([certificate, z.array(certificate).min(1).max(16)]);
const key = z.string().min(1).max(16384);
const passphrase = z.string().max(4096);
const https = identifier.refine((input) => {
	try {
		ssoHttpsUrl(input);
		return true;
	} catch {
		return false;
	}
});
const digest =
	/^(?:sha(?:256|384|512)|http:\/\/www\.w3\.org\/2001\/(?:04\/xmlenc#sha(?:256|512)|04\/xmldsig-more#sha384))$/i;
const signature =
	/^(?:(?:rsa-|ecdsa-)?sha(?:256|384|512)|http:\/\/www\.w3\.org\/2001\/04\/xmldsig-more#(?:rsa|ecdsa)-sha(?:256|384|512))$/i;

const projectSamlInput = z.strictObject({
	entryPoint: https,
	cert: cert.optional(),
	audience: identifier.optional(),
	callbackUrl: identifier.refine((url) => !url.includes("#")).optional(),
	idpInitiatedCallbackUrl: z.null().optional(),
	idpMetadata: z.strictObject({
		metadata: metadata.optional(),
		entityID: identifier.optional(),
		cert: cert.optional(),
		isAssertionEncrypted: z.literal(false).optional(),
		singleSignOnService: z
			.array(z.strictObject({ Binding: identifier, Location: https }))
			.min(1)
			.max(16)
			.optional(),
	}),
	spMetadata: z
		.strictObject({
			metadata: metadata.optional(),
			entityID: identifier.optional(),
			binding: identifier.optional(),
			privateKey: key.optional(),
			privateKeyPass: passphrase.optional(),
			isAssertionEncrypted: z.literal(false).optional(),
		})
		.optional(),
	wantAssertionsSigned: z.boolean().optional(),
	authnRequestsSigned: z.boolean().optional(),
	signatureAlgorithm: identifier.regex(signature).optional(),
	digestAlgorithm: identifier.regex(digest).optional(),
	identifierFormat: identifier.optional(),
	privateKey: key.optional(),
	mapping: z
		.strictObject({
			email: identifier,
			emailVerified: identifier.optional(),
			name: identifier,
			firstName: identifier.optional(),
			lastName: identifier.optional(),
			extraFields: z.record(identifier, identifier).optional(),
		})
		.optional(),
});

export function projectSamlAcs(baseURL: string, providerId: string) {
	return `${baseURL}/sso/saml2/sp/acs/${encodeURIComponent(providerId)}`;
}

export interface ProjectSamlManagementScope {
	baseURL: string;
	generatedSPOnly: boolean;
	customTransport?: ProjectCustomSamlTransport;
}

export async function prepareProjectSamlRegistration(
	input: unknown,
	issuer: string,
	providerId: string,
	scope: ProjectSamlManagementScope,
) {
	ssoHttpsUrl(issuer);
	const parsed = projectSamlInput.parse(input);
	const { idpInitiatedCallbackUrl: _disabled, ...fields } = parsed;
	const configuration = { ...fields, issuer };
	await configureProjectSamlTransport(
		{ issuer, providerId, samlConfig: configuration },
		projectSamlAcs(scope.baseURL, providerId),
		{ ...scope, validateAll: true },
	);
	return configuration;
}

const updateInput = projectSamlInput.partial();

export async function mergeProjectSamlConfiguration(
	current: Record<string, unknown>,
	input: unknown,
	issuer: string,
	providerId: string,
	scope: ProjectSamlManagementScope,
) {
	ssoHttpsUrl(issuer);
	const updates = updateInput.parse(input ?? {});
	const configuration = { ...current, ...updates, issuer };
	if (updates.idpMetadata) {
		configuration.idpMetadata = {
			...projectSamlInput.shape.idpMetadata.parse(current.idpMetadata),
			...updates.idpMetadata,
		};
	}
	if (updates.spMetadata) {
		configuration.spMetadata = {
			...projectSamlInput.shape.spMetadata.parse(current.spMetadata),
			...updates.spMetadata,
		};
	}
	if (updates.idpInitiatedCallbackUrl === null)
		configuration.idpInitiatedCallbackUrl = undefined;
	await configureProjectSamlTransport(
		{ issuer, providerId, samlConfig: configuration },
		projectSamlAcs(scope.baseURL, providerId),
		{ ...scope, validateAll: true },
	);
	return configuration;
}

function identityBoundary(value: Record<string, unknown>, acs: string) {
	const { idp, service, saved, postLocations, wantAssertion } =
		configureOwnedSaml(value, acs);
	const identity = idp.entityMeta;
	const certificates = identity.getX509Certificate("signing");
	const serviceMetadata = service.entityMeta;
	return JSON.stringify({
		idpEntityId: identity.getEntityID(),
		idpRedirectService: identity.getSingleSignOnService("redirect"),
		idpPostService: identity.getSingleSignOnService("post"),
		idpSigningCerts: (Array.isArray(certificates)
			? certificates
			: [certificates]
		)
			.map((item) =>
				item
					.split(/\r?\n/)
					.map((line) => line.trim())
					.join("\n")
					.trim(),
			)
			.sort(),
		spEntityId: serviceMetadata.getEntityID(),
		spNameIDFormat:
			serviceMetadata.getNameIDFormat()?.[0] ?? saved.identifierFormat,
		spPostServices: saved.spMetadata?.metadata ? postLocations : [],
		wantAssertionsSigned: wantAssertion,
		audience: saved.audience,
		callbackUrl: saved.callbackUrl,
	});
}

/** Use the same effective certificate and IdP/SP identity checks as native SSO. */
export function projectSamlIdentityChanged(
	current: Record<string, unknown>,
	updated: Record<string, unknown>,
	acs: string,
) {
	return identityBoundary(current, acs) !== identityBoundary(updated, acs);
}

export function publicSamlRegistration(
	config: z.infer<typeof projectSamlInput>,
) {
	const { privateKey: _privateKey, spMetadata, ...publicConfig } = config;
	if (!spMetadata) return publicConfig;
	const {
		privateKey: _spKey,
		privateKeyPass: _spPassphrase,
		...publicSpMetadata
	} = spMetadata;
	return { ...publicConfig, spMetadata: publicSpMetadata };
}
