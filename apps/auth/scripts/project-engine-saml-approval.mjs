import { createHmac, X509Certificate } from "node:crypto";
import { DOMParser } from "@xmldom/xmldom";
import * as z from "zod";
import {
	developmentEncryptedSamlApprovalsSetting,
	encryptedSamlApprovalSetting,
	productionEncryptedSamlApprovalsSetting,
	readProjectEngineApprovalValue,
} from "./project-engine-rollout-selection.mjs";

export { encryptedSamlApprovalSetting };
export const encryptedSamlApprovalKind =
	"operator-verified-encrypted-saml-policy-v1";
export const maximumSamlApprovalAge = 7 * 24 * 60 * 60 * 1000;

const reservedProviders = new Set([
	"credential",
	"allauth",
	"google",
	"apple",
	"microsoft",
	"github",
	"passkey",
	"email-otp",
	"magic-link",
	"phone-number",
	"anonymous",
	"siwe",
]);
export const storedSamlProviderId = z
	.string()
	.regex(/^[A-Za-z0-9._-]{1,128}$/)
	.refine((value) => !reservedProviders.has(value.toLowerCase()));

const identifier = z.string().min(1).max(2048);
const certificate = z.union([
	z.string().min(1),
	z.array(z.string().min(1)).min(1).max(16),
]);
const endpoint = z.object({
	Binding: z.string().min(1),
	Location: z.string().min(1),
});
export const samlMetadataShape = z.object({
	metadata: z.string().max(102400).optional(),
	entityID: identifier.optional(),
	privateKey: z.string().max(16384).optional(),
	privateKeyPass: z.string().max(4096).optional(),
	isAssertionEncrypted: z.boolean().optional(),
	encPrivateKey: z.string().min(1).max(16384).optional(),
	encPrivateKeyPass: z.string().max(4096).optional(),
});
export const storedProjectSamlConfig = z.object({
	issuer: identifier,
	entryPoint: z.string().max(2048).optional(),
	cert: certificate.optional(),
	audience: identifier.optional(),
	callbackUrl: z.string().max(2048).optional(),
	idpInitiatedCallbackUrl: z.string().max(2048).optional(),
	idpMetadata: samlMetadataShape.extend({
		cert: certificate.optional(),
		singleSignOnService: z.array(endpoint).max(16).optional(),
	}),
	spMetadata: samlMetadataShape.optional(),
	wantAssertionsSigned: z.boolean().optional(),
	authnRequestsSigned: z.boolean().optional(),
	identifierFormat: identifier.optional(),
	privateKey: z.string().max(16384).optional(),
	mapping: z
		.object({
			email: identifier.optional(),
			name: identifier.optional(),
			firstName: identifier.optional(),
			lastName: identifier.optional(),
			extraFields: z.record(z.string(), z.string()).optional(),
		})
		.optional(),
});

const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata";
const post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/** @returns {never} */
function invalid() {
	throw new Error("Invalid configured SAML authentication message.");
}

/** @param {import("@xmldom/xmldom").Element} element @param {string} name */
function metadataChildren(element, name) {
	/** @type {import("@xmldom/xmldom").Element[]} */
	const matches = [];
	for (const node of Array.from(element.childNodes)) {
		if (node.nodeType === 1) {
			const child = /** @type {import("@xmldom/xmldom").Element} */ (node);
			if (child.namespaceURI === metadataNS && child.localName === name)
				matches.push(child);
		}
	}
	return matches;
}

/** @param {import("@xmldom/xmldom").Element} element @param {string} name */
function requiredMetadataChild(element, name) {
	const matches = metadataChildren(element, name);
	if (matches.length !== 1) invalid();
	return matches[0];
}

/** @param {string} xml */
export function parseSamlXml(xml) {
	if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) invalid();
	const options = { locator: false, onError: invalid };
	return new DOMParser(options).parseFromString(xml, "text/xml");
}

/** @param {string} xml @param {"SPSSODescriptor" | "IDPSSODescriptor"} name */
export function configuredSamlMetadataDescriptor(xml, name) {
	const root = parseSamlXml(xml).documentElement;
	if (
		!root ||
		root.localName !== "EntityDescriptor" ||
		root.namespaceURI !== metadataNS
	)
		invalid();
	return requiredMetadataChild(root, name);
}

/** @param {import("@xmldom/xmldom").Element} element @param {string} name */
function metadataFlag(element, name) {
	const value = element.getAttribute(name)?.trim();
	if (value === undefined || value === "false" || value === "0") return false;
	if (value === "true" || value === "1") return true;
	return invalid();
}

/** Read only the direct, namespace-qualified SP elements consumed by native SAML. */
/** @param {string} xml */
export function configuredServiceMetadata(xml) {
	if (new TextEncoder().encode(xml).length > 102400) invalid();
	const document = parseSamlXml(xml);
	const root = document.documentElement;
	if (
		root?.localName !== "EntityDescriptor" ||
		root.namespaceURI !== metadataNS
	)
		invalid();
	const descriptor = requiredMetadataChild(root, "SPSSODescriptor");
	const entityID = root.getAttribute("entityID");
	if (!entityID || entityID.length > 2048 || entityID !== entityID.trim())
		invalid();
	for (const node of Array.from(root.getElementsByTagName("*"))) {
		if (
			node.localName === "EntityDescriptor" ||
			(node.localName === "SPSSODescriptor" && node !== descriptor) ||
			((node.localName === "AssertionConsumerService" ||
				node.localName === "NameIDFormat") &&
				(node.namespaceURI !== metadataNS || node.parentNode !== descriptor))
		)
			invalid();
	}
	const consumers = metadataChildren(descriptor, "AssertionConsumerService");
	const postLocations = consumers
		.filter((item) => item.getAttribute("Binding") === post)
		.map((item) => item.getAttribute("Location") ?? "");
	return {
		descriptor,
		entityID,
		postLocations,
		consumerCount: consumers.length,
		wantAssertion: metadataFlag(descriptor, "WantAssertionsSigned"),
		requestsSigned: metadataFlag(descriptor, "AuthnRequestsSigned"),
	};
}

/** @param {ReturnType<typeof configuredServiceMetadata>} custom */
export function requiredSignedSamlPostReceiver(custom) {
	if (
		!custom.requestsSigned ||
		custom.consumerCount !== 1 ||
		custom.postLocations.length !== 1
	)
		invalid();
	return custom.postLocations[0];
}

/** @param {boolean | undefined} saved @param {{wantAssertion:boolean} | undefined} custom */
export function effectiveSamlAssertionSigning(saved, custom) {
	const wantAssertion = custom?.wantAssertion ?? saved === true;
	if (saved && !wantAssertion) invalid();
	return wantAssertion;
}

/** @param {unknown} value @returns {unknown} */
function canonical(value) {
	if (Array.isArray(value)) return value.map(canonical);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => [key, canonical(item)]),
	);
}

/**
 * @param {string} secret
 * @param {string} projectId
 * @param {string} schemaName
 * @param {string} receiver
 * @param {{id:string,providerId:string,issuer:string,domain:string,domainVerified:boolean|null,organizationId:string|null,samlConfig?:Record<string,unknown>}} provider
 */
export function encryptedSamlConfigurationFingerprint(
	secret,
	projectId,
	schemaName,
	receiver,
	provider,
) {
	return createHmac("sha256", secret)
		.update("allauth:encrypted-saml-configuration:v1\n")
		.update(
			JSON.stringify([
				projectId,
				schemaName,
				receiver,
				provider.id,
				provider.providerId,
				provider.issuer,
				provider.domain,
				provider.domainVerified === true,
				provider.organizationId ?? null,
				canonical(provider.samlConfig),
			]),
		)
		.digest("base64url");
}

const profile = z.strictObject({
	cipher: z.enum(["aes128-gcm", "aes256-gcm"]),
	signatures: z.enum(["assertion", "response", "both"]),
});
const approvalSchema = z.strictObject({
	kind: z.literal(encryptedSamlApprovalKind),
	projectId: z.uuid(),
	schemaName: z.string().regex(/^allauth_project_[a-f0-9]{32}$/),
	providerId: storedSamlProviderId,
	providerRecordId: z.string().min(1).max(256),
	receiver: z.url().max(2048),
	configurationFingerprint: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
	legacyWriterRevision: z.number().int().min(0).max(2_147_483_646),
	policyRevision: z.string().regex(/^[A-Za-z0-9._:/-]{1,128}$/),
	verifiedAt: z.iso.datetime(),
	expiresAt: z.iso.datetime(),
	profiles: z.array(profile).min(1).max(6),
});

/** @param {{verified:number,expires:number}} window @param {boolean} preparing @param {number} now */
export function samlApprovalIsCurrent(window, preparing, now) {
	return window.verified <= now && (!preparing || now < window.expires);
}

/**
 * @param {string} raw
 * @param {{id:string,schemaName:string}} binding
 * @param {{revision:number,preparing:boolean}} writer
 * @param {number} now
 */
export function parseProjectEncryptedSamlApproval(raw, binding, writer, now) {
	if (raw.length > 8192) return null;
	try {
		const approval = approvalSchema.parse(JSON.parse(raw));
		const receiver = new URL(approval.receiver);
		const verified = Date.parse(approval.verifiedAt);
		const expires = Date.parse(approval.expiresAt);
		const profiles = new Set(
			approval.profiles.map(
				({ cipher, signatures }) => `${cipher}:${signatures}`,
			),
		);
		const window = { verified, expires };
		if (
			approval.projectId !== binding.id ||
			approval.schemaName !== binding.schemaName ||
			approval.legacyWriterRevision + (writer.preparing ? 0 : 1) !==
				writer.revision ||
			!Number.isFinite(verified) ||
			!Number.isFinite(expires) ||
			expires <= verified ||
			expires - verified > maximumSamlApprovalAge ||
			!samlApprovalIsCurrent(window, writer.preparing, now) ||
			receiver.protocol !== "https:" ||
			receiver.username ||
			receiver.password ||
			receiver.search ||
			receiver.hash ||
			receiver.href !== approval.receiver ||
			profiles.size !== approval.profiles.length
		)
			return null;
		return { approval, profiles, ...window };
	} catch {
		return null;
	}
}

function approvalWindow(raw, projectId, schemaName, revision) {
	const parsed = parseProjectEncryptedSamlApproval(
		raw,
		{ id: projectId, schemaName },
		{ revision, preparing: true },
		Date.now(),
	);
	if (parsed) return parsed.approval;
	throw new Error(
		"The project encrypted SAML approval is outside its activation window.",
	);
}

function configuredEncryption(config) {
	if (!config || typeof config !== "object" || Array.isArray(config))
		throw new Error();
	return [config.idpMetadata, config.spMetadata].some(
		(metadata) =>
			metadata &&
			(metadata.isAssertionEncrypted ||
				metadata.encPrivateKey ||
				metadata.encPrivateKeyPass),
	);
}

function inspectStoredProvider(row) {
	const samlConfig = JSON.parse(row.samlConfig);
	const saved = storedProjectSamlConfig.parse(samlConfig);
	if (saved.issuer !== row.issuer || row.oidcConfig) invalid();
	const serviceMetadata = saved.spMetadata?.metadata;
	const custom =
		serviceMetadata === undefined
			? undefined
			: configuredServiceMetadata(serviceMetadata);
	const receiver = custom && requiredSignedSamlPostReceiver(custom);
	const wantAssertion = effectiveSamlAssertionSigning(
		saved.wantAssertionsSigned,
		custom,
	);
	const idp = saved.idpMetadata;
	if (idp.metadata) {
		configuredSamlMetadataDescriptor(idp.metadata, "IDPSSODescriptor");
	} else {
		const certificates = idp.cert ?? saved.cert;
		const location =
			idp.singleSignOnService === undefined
				? saved.entryPoint
				: idp.singleSignOnService.find(({ Binding }) => Binding === redirect)
						?.Location;
		if (!idp.entityID || !certificates || !location) invalid();
		const endpoint = new URL(location);
		if (
			endpoint.protocol !== "https:" ||
			endpoint.username ||
			endpoint.password ||
			endpoint.hash
		)
			invalid();
		for (const certificate of Array.isArray(certificates)
			? certificates
			: [certificates]) {
			const pem = certificate.includes("-----BEGIN CERTIFICATE-----")
				? certificate
				: `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
			const key = new X509Certificate(pem).publicKey.asymmetricKeyType;
			if (key !== "rsa" && key !== "ec") invalid();
		}
	}
	if (
		(custom?.requestsSigned || saved.authnRequestsSigned) &&
		!(saved.spMetadata?.privateKey || saved.privateKey)?.trim()
	)
		invalid();
	return {
		...row,
		samlConfig,
		receiver,
		wantAssertion,
		encrypted: configuredEncryption(saved),
	};
}

async function verifyActivationReceiver(client, projectId, approval, env) {
	const receiver = new URL(approval.receiver);
	if (
		receiver.protocol !== "https:" ||
		receiver.href !== approval.receiver ||
		receiver.username ||
		receiver.password ||
		receiver.search ||
		receiver.hash
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const {
		rows: [project],
	} = await client.query(
		`SELECT slug FROM public."allauthProject" WHERE id=$1 FOR SHARE`,
		[projectId],
	);
	const path = `/sso/saml2/sp/acs/${encodeURIComponent(approval.providerId)}`;
	const currentOrigin = env.ALLAUTH_AUTH_URL;
	const legacyOrigin = env.BETTER_AUTH_URL;
	const platform = currentOrigin ?? legacyOrigin ?? "https://allauth.co";
	if (
		currentOrigin != null &&
		legacyOrigin != null &&
		currentOrigin !== legacyOrigin
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	if (
		project &&
		receiver.origin === new URL(platform).origin &&
		receiver.pathname === `/api/projects/${project.slug}/auth${path}`
	)
		return;
	if (
		!project ||
		receiver.port ||
		receiver.origin === new URL(platform).origin ||
		receiver.pathname !== `/api/auth${path}` ||
		env.CLOUDFLARE_SAAS_READY !== "true" ||
		(env.ALLAUTH_EDGE_SECRET?.length ?? 0) < 32
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const base = (env.ALLAUTH_HOSTING_BASE_DOMAIN || "allauth.co")
		.trim()
		.toLowerCase();
	if (receiver.hostname === `${project.slug}-accounts.${base}`) return;
	if (
		!/^[a-f0-9]{32}$/.test(env.CLOUDFLARE_SAAS_ZONE_ID ?? "") ||
		!env.CLOUDFLARE_SAAS_API_TOKEN ||
		!env.CLOUDFLARE_SAAS_CNAME_TARGET
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const { rowCount } = await client.query(
		`SELECT 1 FROM public."allauthCustomHostname" h
		 JOIN public."allauthDomainPair" d ON d.id=h."pairId" AND d."projectId"=h."projectId"
		 WHERE h.hostname=$1 AND h."projectId"=$2 AND h.kind='accounts' AND d.deleting=false
		 AND (SELECT count(*) FROM public."allauthCustomHostname" s WHERE s."pairId"=d.id
		   AND s."ownershipVerifiedAt" IS NOT NULL AND s."providerStatus"='active' AND s."sslStatus"='active'
		   AND s."routingVerifiedAt" IS NOT NULL AND s."lastIssue" IS NULL)=2 FOR SHARE OF h,d`,
		[receiver.hostname, projectId],
	);
	if (!rowCount)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
}

/** Recheck the approved SAML row under the selected writer's exclusive admission lock.
 * @param {"protected" | "development" | "production"} scope
 */
export async function verifyEncryptedSamlActivation(
	client,
	projectId,
	schemaName,
	revision,
	env,
	scope = "protected",
) {
	if (
		!/^allauth_project_[a-f0-9]{32}$/.test(schemaName) ||
		schemaName !== `allauth_project_${projectId.replaceAll("-", "")}`
	)
		throw new Error("The project encrypted SAML realm is unavailable.");
	const { rows } = await client.query(
		`SELECT id,"providerId",issuer,domain,"domainVerified","organizationId","oidcConfig","samlConfig"
		 FROM "${schemaName}"."ssoProvider" WHERE "samlConfig" IS NOT NULL FOR SHARE`,
	);
	let encrypted;
	try {
		encrypted = rows.map(inspectStoredProvider).filter((row) => row.encrypted);
	} catch {
		throw new Error("The stored project SAML configuration is unavailable.");
	}
	const raw =
		scope === "protected"
			? env[encryptedSamlApprovalSetting]?.trim()
			: readProjectEngineApprovalValue(
					env[
						scope === "production"
							? productionEncryptedSamlApprovalsSetting
							: developmentEncryptedSamlApprovalsSetting
					],
					projectId,
				);
	if (!raw && !encrypted.length) return;
	if (!raw)
		throw new Error(
			"The stored encrypted SAML provider requires deployment approval.",
		);
	const approval = approvalWindow(raw, projectId, schemaName, revision);
	const [provider] = encrypted;
	const currentSecret = env.ALLAUTH_AUTH_SECRET;
	const legacySecret = env.BETTER_AUTH_SECRET;
	const secret = currentSecret ?? legacySecret;
	if (
		encrypted.length !== 1 ||
		!secret ||
		secret.length < 32 ||
		(currentSecret != null &&
			legacySecret != null &&
			currentSecret !== legacySecret) ||
		provider.id !== approval.providerRecordId ||
		provider.providerId !== approval.providerId ||
		!provider.domainVerified ||
		provider.oidcConfig ||
		provider.samlConfig.issuer !== provider.issuer ||
		provider.samlConfig.idpMetadata?.isAssertionEncrypted !== true ||
		typeof provider.samlConfig.spMetadata?.metadata !== "string" ||
		!provider.samlConfig.spMetadata?.encPrivateKey ||
		provider.receiver !== approval.receiver ||
		(provider.wantAssertion &&
			approval.profiles.some(({ signatures }) => signatures === "response")) ||
		typeof approval.receiver !== "string" ||
		encryptedSamlConfigurationFingerprint(
			secret,
			projectId,
			schemaName,
			approval.receiver,
			provider,
		) !== approval.configurationFingerprint
	)
		throw new Error(
			"The stored encrypted SAML provider does not match deployment approval.",
		);
	await verifyActivationReceiver(client, projectId, approval, env);
	approvalWindow(raw, projectId, schemaName, revision);
}
