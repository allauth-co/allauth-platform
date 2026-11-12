import { createPrivateKey, type KeyObject, X509Certificate } from "node:crypto";
import type {
	Document as XmlDocument,
	Element as XmlElement,
} from "@xmldom/xmldom";
import { DOMParser } from "@xmldom/xmldom";
import samlifyDefault, * as samlifyNamespace from "samlify";
import * as z from "zod";
import { validAvatarPath } from "../avatars/protocol";
import { ssoHttpsUrl } from "./owned-project-sso-network";
import type { SsoIdentity } from "./owned-project-sso-store";

const saml =
	typeof samlifyNamespace.SPMetadata === "function"
		? samlifyNamespace
		: samlifyDefault;
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion";
const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol";
const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata";
const signatureNS = "http://www.w3.org/2000/09/xmldsig#";
const encryptionNS = "http://www.w3.org/2001/04/xmlenc#";
const encryption11NS = "http://www.w3.org/2009/xmlenc11#";
const post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const success = "urn:oasis:names:tc:SAML:2.0:status:Success";
const clockSkew = 60_000;
const signedId = /^[A-Za-z_][A-Za-z0-9._:-]{0,255}$/;
const algorithms = new Set(
	[256, 384, 512].flatMap((size) => [
		`http://www.w3.org/2001/04/xmldsig-more#rsa-sha${size}`,
		`http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha${size}`,
		`http://www.w3.org/2007/05/xmldsig-more#sha${size}-rsa-MGF1`,
	]),
);
const digests = new Set([
	"http://www.w3.org/2001/04/xmlenc#sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512",
]);
const canonicalizations = new Set([
	"http://www.w3.org/2001/10/xml-exc-c14n#",
	"http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
]);
const enveloped = `${signatureNS}enveloped-signature`;
const identifier = z.string().min(1).max(2048);
const certificate = z.union([
	z.string().min(1),
	z.array(z.string().min(1)).min(1).max(16),
]);
const endpoint = z.object({
	Binding: z.string().min(1),
	Location: z.string().min(1),
});
const metadata = z.object({
	metadata: z.string().max(102400).optional(),
	entityID: identifier.optional(),
	privateKey: z.string().max(16384).optional(),
	privateKeyPass: z.string().max(4096).optional(),
	isAssertionEncrypted: z.boolean().optional(),
	encPrivateKey: z.string().min(1).max(16384).optional(),
	encPrivateKeyPass: z.string().max(4096).optional(),
});
const config = z.object({
	issuer: identifier,
	entryPoint: z.string().max(2048).optional(),
	cert: certificate.optional(),
	audience: identifier.optional(),
	callbackUrl: z.string().max(2048).optional(),
	idpInitiatedCallbackUrl: z.string().max(2048).optional(),
	idpMetadata: metadata.extend({
		cert: certificate.optional(),
		singleSignOnService: z.array(endpoint).max(16).optional(),
	}),
	spMetadata: metadata.optional(),
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

function invalid(): never {
	throw new Error("Invalid configured SAML authentication message.");
}

function parseXML(xml: string) {
	if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) invalid();
	const options = { locator: false, onError: invalid };
	return new DOMParser(options).parseFromString(xml, "text/xml");
}

function children(element: XmlElement, namespace: string, name: string) {
	return Array.from(element.childNodes).filter(
		(node): node is XmlElement =>
			node.nodeType === 1 &&
			node.namespaceURI === namespace &&
			node.localName === name,
	);
}

function child(element: XmlElement, namespace: string, name: string) {
	const matches = children(element, namespace, name);
	if (matches.length !== 1) invalid();
	return matches[0]!;
}

function text(element: XmlElement) {
	if (Array.from(element.childNodes).some((node) => node.nodeType === 1))
		invalid();
	return element.textContent ?? "";
}

function metadataDescriptor(
	xml: string,
	name: "SPSSODescriptor" | "IDPSSODescriptor",
) {
	const root = parseXML(xml).documentElement;
	if (
		!root ||
		root.localName !== "EntityDescriptor" ||
		root.namespaceURI !== metadataNS
	)
		invalid();
	return child(root, metadataNS, name);
}

function metadataFlag(element: XmlElement, name: string) {
	const value = element.getAttribute(name)?.trim();
	if (value === undefined || value === "false" || value === "0") return false;
	if (value === "true" || value === "1") return true;
	return invalid();
}

/** Read only the direct, namespace-qualified SP elements consumed by native SAML. */
function configuredServiceMetadata(xml: string) {
	if (new TextEncoder().encode(xml).length > 102400) invalid();
	const document = parseXML(xml);
	const root = document.documentElement;
	if (
		root?.localName !== "EntityDescriptor" ||
		root.namespaceURI !== metadataNS
	)
		invalid();
	const descriptor = child(root, metadataNS, "SPSSODescriptor");
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
	const consumers = children(
		descriptor,
		metadataNS,
		"AssertionConsumerService",
	);
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

/** Resolve one signed POST receiver, with encryption limited to the fixture admission. */
export function declaredSignedSamlAcs(
	value: unknown,
	allowEncrypted?: boolean,
) {
	const saved = config.parse(value);
	const metadata = saved.spMetadata?.metadata;
	if (metadata === undefined) return undefined;
	const custom = configuredServiceMetadata(metadata);
	if (
		!custom.requestsSigned ||
		custom.consumerCount !== 1 ||
		custom.postLocations.length !== 1 ||
		(!allowEncrypted &&
			(saved.idpMetadata.isAssertionEncrypted ||
				saved.spMetadata?.isAssertionEncrypted))
	)
		invalid();
	return custom.postLocations[0]!;
}

function pem(value: string | undefined) {
	return value
		?.split(/\r?\n/)
		.map((line) => line.trim())
		.join("\n")
		.trim();
}

function decryptionKey(
	idp: z.infer<typeof metadata>,
	sp: z.infer<typeof metadata> | undefined,
	allowEncrypted: boolean | undefined,
) {
	if (
		!sp?.isAssertionEncrypted &&
		!idp.isAssertionEncrypted &&
		!sp?.encPrivateKey &&
		!idp.encPrivateKey &&
		!sp?.encPrivateKeyPass &&
		!idp.encPrivateKeyPass
	)
		return undefined;
	// The native receive path uses the IdP flag to require encryption and the SP key to decrypt.
	if (!allowEncrypted || !idp.isAssertionEncrypted || !sp?.encPrivateKey)
		invalid();
	const privateKey = createPrivateKey({
		key: pem(sp.encPrivateKey)!,
		passphrase: sp.encPrivateKeyPass,
	});
	if (
		privateKey.asymmetricKeyType !== "rsa" ||
		(privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
	)
		invalid();
	return privateKey;
}

function validateCustomEncryptionCertificate(
	descriptor: XmlElement,
	serviceCertificate: string | string[] | null,
	privateKey: KeyObject,
) {
	const keys = children(descriptor, metadataNS, "KeyDescriptor").filter(
		(item) => item.getAttribute("use") === "encryption",
	);
	if (keys.length !== 1 || typeof serviceCertificate !== "string") invalid();
	const info = child(keys[0]!, signatureNS, "KeyInfo");
	const data = child(info, signatureNS, "X509Data");
	const certificate = text(child(data, signatureNS, "X509Certificate")).replace(
		/\s/g,
		"",
	);
	if (certificate !== serviceCertificate.replace(/\s/g, "")) invalid();
	if (
		!new X509Certificate(
			`-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`,
		).checkPrivateKey(privateKey)
	)
		invalid();
}

/** The configured SP/IdP pair, built with the same library as legacy SSO. */
export function configureOwnedSaml(
	value: unknown,
	acs: string,
	options: {
		relayState?: string;
		generatedSPOnly?: boolean;
		allowEncrypted?: boolean;
	} = {},
) {
	const saved = config.parse(value);
	const sp = saved.spMetadata;
	const idp = saved.idpMetadata;
	const encryptionKey = decryptionKey(idp, sp, options.allowEncrypted);
	const spMetadata = sp?.metadata;
	if (options.generatedSPOnly && spMetadata !== undefined) invalid();
	const custom =
		spMetadata === undefined
			? undefined
			: configuredServiceMetadata(spMetadata);
	const wantAssertion =
		custom?.wantAssertion ?? saved.wantAssertionsSigned === true;
	if (saved.wantAssertionsSigned && !wantAssertion) invalid();
	const postLocations = custom?.postLocations ?? [acs];
	if (!postLocations.length) invalid();
	for (const location of postLocations) {
		const parsed = new URL(location);
		if (
			!/^https?:\/\//i.test(location) ||
			/[\\\u0000-\u0020\u007f]/.test(location) ||
			parsed.username ||
			parsed.password ||
			location.includes("#")
		)
			invalid();
	}
	const requestPrivateKey = pem(sp?.privateKey || saved.privateKey);
	const requestsSigned =
		saved.authnRequestsSigned === true || custom?.requestsSigned === true;
	if (requestsSigned && !requestPrivateKey) invalid();
	const service = saml.ServiceProvider({
		metadata:
			spMetadata ??
			saml
				.SPMetadata({
					entityID: sp?.entityID ?? saved.issuer,
					assertionConsumerService: [{ Binding: post, Location: acs }],
					wantAssertionsSigned: wantAssertion,
					authnRequestsSigned: saved.authnRequestsSigned === true,
					nameIDFormat: saved.identifierFormat
						? [saved.identifierFormat]
						: undefined,
				})
				.getMetadata(),
		privateKey: requestPrivateKey,
		privateKeyPass: sp?.privateKeyPass,
		...(encryptionKey
			? {
					isAssertionEncrypted: true,
					encPrivateKey: encryptionKey.export({ type: "pkcs8", format: "pem" }),
				}
			: {}),
		allowCreate: true,
		relayState: options.relayState,
	});
	if (requestsSigned && !service.entityMeta.isAuthnRequestSigned()) invalid();
	const advertisedAcs = postLocations.at(-1)!;
	if (
		service.entityMeta.getAssertionConsumerService("post") !== advertisedAcs ||
		(custom && service.entityMeta.getEntityID() !== custom.entityID)
	)
		invalid();
	if (custom && encryptionKey)
		validateCustomEncryptionCertificate(
			custom.descriptor,
			service.entityMeta.getX509Certificate("encryption"),
			encryptionKey,
		);
	if (idp.metadata) metadataDescriptor(idp.metadata, "IDPSSODescriptor");
	const configuredCerts = idp.cert ?? saved.cert;
	const certs =
		typeof configuredCerts === "string" ? [configuredCerts] : configuredCerts;
	if (!idp.metadata && (!idp.entityID || !certs?.length)) invalid();
	const idpEntity = saml.IdentityProvider(
		idp.metadata
			? { metadata: idp.metadata, isAssertionEncrypted: Boolean(encryptionKey) }
			: {
					entityID: idp.entityID,
					signingCert: certs?.map((cert) => pem(cert)!),
					wantAuthnRequestsSigned: saved.authnRequestsSigned === true,
					isAssertionEncrypted: Boolean(encryptionKey),
					singleSignOnService: idp.singleSignOnService ?? [
						{ Binding: redirect, Location: saved.entryPoint ?? "" },
					],
				},
	);
	const endpoint = idpEntity.entityMeta.getSingleSignOnService("redirect");
	if (typeof endpoint !== "string") invalid();
	ssoHttpsUrl(endpoint);
	const signingCerts = idpEntity.entityMeta.getX509Certificate("signing");
	if (!signingCerts?.length || !idpEntity.entityMeta.getEntityID()) invalid();
	return {
		service,
		idp: idpEntity,
		wantAssertion,
		requestsSigned,
		encrypted: Boolean(encryptionKey),
		postLocations,
		recipients: new Set([...postLocations, acs]),
		saved,
	};
}

type ConfiguredSaml = ReturnType<typeof configureOwnedSaml>;

function checkSignature(signature: XmlElement, id: string) {
	const signed = child(signature, signatureNS, "SignedInfo");
	const reference = child(signed, signatureNS, "Reference");
	const transforms = children(
		child(reference, signatureNS, "Transforms"),
		signatureNS,
		"Transform",
	).map((item) => item.getAttribute("Algorithm") ?? "");
	if (
		reference.getAttribute("URI") !== `#${id}` ||
		!algorithms.has(
			child(signed, signatureNS, "SignatureMethod").getAttribute("Algorithm") ??
				"",
		) ||
		!digests.has(
			child(reference, signatureNS, "DigestMethod").getAttribute("Algorithm") ??
				"",
		) ||
		!canonicalizations.has(
			child(signed, signatureNS, "CanonicalizationMethod").getAttribute(
				"Algorithm",
			) ?? "",
		) ||
		transforms.length < 1 ||
		transforms.length > 2 ||
		transforms[0] !== enveloped ||
		(transforms[1] !== undefined && !canonicalizations.has(transforms[1]))
	)
		invalid();
}

function time(value: string | null) {
	if (!value || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value))
		invalid();
	const result = Date.parse(value);
	if (!Number.isFinite(result)) invalid();
	return result;
}

function optionalTime(element: XmlElement, name: string) {
	const value = element.getAttribute(name);
	return value === null ? undefined : time(value);
}

function assertionWindow(
	assertion: XmlElement,
	now: number,
	audiences: ReadonlySet<string>,
	requiredAudience: string,
) {
	const conditions = child(assertion, assertionNS, "Conditions");
	const after = optionalTime(conditions, "NotBefore");
	const until = optionalTime(conditions, "NotOnOrAfter");
	if (
		(after === undefined && until === undefined) ||
		(after !== undefined && after > now + clockSkew) ||
		(until !== undefined &&
			(now >= until + clockSkew || (after !== undefined && after >= until)))
	)
		invalid();
	const restrictions = children(
		conditions,
		assertionNS,
		"AudienceRestriction",
	).map((group) => children(group, assertionNS, "Audience").map(text));
	if (
		!restrictions.length ||
		!restrictions.some((group) => group.includes(requiredAudience)) ||
		restrictions.some((group) => !group.some((item) => audiences.has(item)))
	)
		invalid();
	return until;
}

function attributes(assertion: XmlElement) {
	const values = new Map<string, string>();
	for (const statement of children(
		assertion,
		assertionNS,
		"AttributeStatement",
	)) {
		for (const attribute of children(statement, assertionNS, "Attribute")) {
			const name = attribute.getAttribute("Name");
			const first = children(attribute, assertionNS, "AttributeValue")[0];
			if (name && first && !values.has(name)) values.set(name, text(first));
		}
	}
	return values;
}

function parseSamlEnvelope(xml: string) {
	const document = parseXML(xml);
	const response = document.documentElement;
	if (
		!response ||
		response.namespaceURI !== protocolNS ||
		response.localName !== "Response" ||
		response.getAttribute("Version") !== "2.0"
	)
		invalid();
	const responseId = response.getAttribute("ID") ?? "";
	const elements = Array.from(response.getElementsByTagName("*"));
	const ids = [response, ...elements].flatMap((item) =>
		Array.from(item.attributes)
			.filter((attr) => attr.localName?.toLowerCase() === "id")
			.map((attr) => attr.value),
	);
	if (!signedId.test(responseId) || new Set(ids).size !== ids.length) invalid();
	return { document, response, responseId, elements };
}

function authenticatedEnvelope(
	xml: string,
	envelope: ReturnType<typeof parseSamlEnvelope>,
	configured: ConfiguredSaml,
) {
	const outer = children(envelope.response, signatureNS, "Signature");
	if (outer.length > 1) invalid();
	if (!outer[0]) return;
	checkSignature(outer[0], envelope.responseId);
	const [verified, content] = saml.SamlLib.verifySignature(xml, {
		metadata: configured.idp.entityMeta,
		allowedSignatureAlgorithms: [...algorithms],
		requireMessageSignature: true,
	});
	if (!verified || !content) invalid();
	return { node: outer[0], content };
}

function plaintextAssertion(envelope: ReturnType<typeof parseSamlEnvelope>) {
	if (
		envelope.elements.filter((item) => item.localName === "Assertion")
			.length !== 1 ||
		envelope.elements.some((item) => item.localName === "EncryptedAssertion")
	)
		invalid();
	return child(envelope.response, assertionNS, "Assertion");
}

function verifyAssertionSignature(
	document: XmlDocument,
	plain: XmlElement,
	signature: XmlElement,
	configured: ConfiguredSaml,
) {
	checkSignature(signature, plain.getAttribute("ID") ?? "");
	const [verified, content] = saml.SamlLib.verifySignature(
		document.toString(),
		{
			metadata: configured.idp.entityMeta,
			allowedSignatureAlgorithms: [...algorithms],
		},
	);
	if (!verified || !content) invalid();
	return parseXML(content).documentElement;
}

function checkCiphertext(parent: XmlElement) {
	const value = child(
		child(parent, encryptionNS, "CipherData"),
		encryptionNS,
		"CipherValue",
	);
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text(value).replace(/[\t\n\r ]/g, "")))
		invalid();
}

function checkEncryptedAssertion(
	envelope: ReturnType<typeof parseSamlEnvelope>,
) {
	if (
		envelope.elements.filter((item) => item.localName === "EncryptedAssertion")
			.length !== 1 ||
		envelope.elements.some((item) => item.localName === "Assertion") ||
		envelope.elements.filter((item) => item.localName === "EncryptedData")
			.length !== 1 ||
		envelope.elements.filter((item) => item.localName === "EncryptedKey")
			.length !== 1 ||
		envelope.elements.filter((item) => item.localName === "EncryptionMethod")
			.length !== 2 ||
		envelope.elements.filter((item) => item.localName === "CipherData")
			.length !== 2 ||
		envelope.elements.filter((item) => item.localName === "CipherValue")
			.length !== 2 ||
		envelope.elements.some(
			(item) =>
				item.localName === "CipherReference" ||
				item.localName === "RetrievalMethod",
		)
	)
		invalid();
	const encrypted = child(envelope.response, assertionNS, "EncryptedAssertion");
	const data = child(encrypted, encryptionNS, "EncryptedData");
	const key = child(
		child(data, signatureNS, "KeyInfo"),
		encryptionNS,
		"EncryptedKey",
	);
	const dataMethod = child(data, encryptionNS, "EncryptionMethod");
	const keyMethod = child(key, encryptionNS, "EncryptionMethod");
	const keyParameters = Array.from(keyMethod.childNodes).filter(
		(node) => node.nodeType === 1,
	);
	if (
		![`${encryption11NS}aes128-gcm`, `${encryption11NS}aes256-gcm`].includes(
			dataMethod.getAttribute("Algorithm") ?? "",
		) ||
		keyMethod.getAttribute("Algorithm") !== `${encryptionNS}rsa-oaep-mgf1p` ||
		keyParameters.length > 1 ||
		keyParameters.some((node) => {
			const element = node as XmlElement;
			return (
				element.namespaceURI !== signatureNS ||
				element.localName !== "DigestMethod" ||
				element.getAttribute("Algorithm") !== `${signatureNS}sha1`
			);
		})
	)
		invalid();
	checkCiphertext(data);
	checkCiphertext(key);
}

async function authenticatedAssertion(
	xml: string,
	envelope: ReturnType<typeof parseSamlEnvelope>,
	configured: ConfiguredSaml,
) {
	const initialAssertion = configured.encrypted
		? undefined
		: plaintextAssertion(envelope);
	if (configured.encrypted) {
		checkEncryptedAssertion(envelope);
		if (
			envelope.elements.filter((item) => item.localName === "Signature")
				.length !== children(envelope.response, signatureNS, "Signature").length
		)
			invalid();
	}
	const outer = authenticatedEnvelope(xml, envelope, configured);
	// A response signature authenticates the ciphertext. Decrypt that authenticated
	// serialization when available, then validate the separately signed assertion.
	const decrypted = configured.encrypted
		? parseSamlEnvelope(
				(
					await saml.SamlLib.decryptAssertion(
						configured.service,
						outer?.content ?? xml,
					)
				)[0],
			)
		: envelope;
	const plain = initialAssertion ?? plaintextAssertion(decrypted);
	const id = plain.getAttribute("ID") ?? "";
	const inner = children(plain, signatureNS, "Signature");
	const outerNodes = children(decrypted.response, signatureNS, "Signature");
	if (
		!signedId.test(id) ||
		inner.length > 1 ||
		decrypted.elements.filter((item) => item.localName === "Signature")
			.length !==
			outerNodes.length + inner.length ||
		(!outer && !inner.length) ||
		(configured.wantAssertion && !inner.length)
	)
		invalid();
	for (const signature of outerNodes) decrypted.response.removeChild(signature);
	const assertion = inner[0]
		? verifyAssertionSignature(decrypted.document, plain, inner[0], configured)
		: configured.encrypted
			? plain
			: parseXML(outer!.content).documentElement;
	if (
		!assertion ||
		assertion.localName !== "Assertion" ||
		assertion.namespaceURI !== assertionNS ||
		assertion.getAttribute("ID") !== id ||
		assertion.getAttribute("Version") !== "2.0"
	)
		invalid();
	return { assertion, id };
}

/** Verify the assertion with Samlify before its identity or timing claims are used. */
export async function verifyOwnedSaml(
	encoded: string,
	configured: ConfiguredSaml,
) {
	if (encoded.length > 256 * 1024) invalid();
	const wire = encoded.replace(/[\t\n\r ]/g, "");
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(wire)) invalid();
	const xml = new TextDecoder("utf-8", { fatal: true }).decode(
		Uint8Array.from(atob(wire), (item) => item.charCodeAt(0)),
	);
	const envelope = parseSamlEnvelope(xml);
	const { response } = envelope;
	const { assertion, id } = await authenticatedAssertion(
		xml,
		envelope,
		configured,
	);
	const issuer = configured.idp.entityMeta.getEntityID();
	if (
		text(child(assertion, assertionNS, "Issuer")) !== issuer ||
		text(child(response, assertionNS, "Issuer")) !== issuer ||
		child(
			child(response, protocolNS, "Status"),
			protocolNS,
			"StatusCode",
		).getAttribute("Value") !== success
	)
		invalid();
	const requestId = response.getAttribute("InResponseTo") ?? "";
	const destination = response.getAttribute("Destination") ?? "";
	if (!signedId.test(requestId) || !configured.recipients.has(destination))
		invalid();
	const now = Date.now();
	const entityId = configured.service.entityMeta.getEntityID();
	const audience = configured.saved.audience ?? entityId;
	const until = assertionWindow(
		assertion,
		now,
		new Set([entityId, audience]),
		audience,
	);
	const subject = child(assertion, assertionNS, "Subject");
	const confirmed = children(subject, assertionNS, "SubjectConfirmation")
		.filter((item) => item.getAttribute("Method") === bearer)
		.flatMap((item) => children(item, assertionNS, "SubjectConfirmationData"))
		.filter(
			(item) =>
				item.getAttribute("Recipient") === destination &&
				item.getAttribute("InResponseTo") === requestId,
		)
		.map((item) => ({
			until: time(item.getAttribute("NotOnOrAfter")),
			after: optionalTime(item, "NotBefore"),
		}))
		.filter(
			(item) =>
				item.until + clockSkew > now &&
				(item.after === undefined || item.after <= now + clockSkew),
		);
	if (!confirmed.length) invalid();
	const statement = child(assertion, assertionNS, "AuthnStatement");
	const sessionUntil = optionalTime(statement, "SessionNotOnOrAfter");
	if (sessionUntil !== undefined && now >= sessionUntil + clockSkew) invalid();
	const nameId = text(child(subject, assertionNS, "NameID"));
	if (
		!nameId.trim() ||
		nameId.length > 512 ||
		/[\u0000-\u001f\u007f]/.test(nameId)
	)
		invalid();
	const profile = attributes(assertion);
	const mapping = configured.saved.mapping;
	const email = (
		profile.get(mapping?.email ?? "email") || nameId
	).toLowerCase();
	if (!email || email.length > 320) invalid();
	const name =
		[
			profile.get(mapping?.firstName ?? "givenName"),
			profile.get(mapping?.lastName ?? "surname"),
		]
			.filter(Boolean)
			.join(" ") ||
		profile.get(mapping?.name ?? "displayName") ||
		nameId;
	let image: string | undefined;
	const picture =
		mapping?.extraFields?.image && profile.get(mapping.extraFields.image);
	if (picture) {
		try {
			const parsed = ssoHttpsUrl(picture);
			if (!validAvatarPath(parsed.pathname)) image = parsed.href;
		} catch {
			/* The optional picture has its own URL policy. */
		}
	}
	return {
		assertionId: id,
		issuer,
		requestId,
		replayExpiresAt:
			Math.min(
				until ?? Infinity,
				Math.max(...confirmed.map((item) => item.until)),
			) + clockSkew,
		identity: {
			subject: nameId,
			email,
			name: name.slice(0, 256),
			image,
			accessToken: "",
			refreshToken: "",
		} satisfies SsoIdentity,
	};
}
