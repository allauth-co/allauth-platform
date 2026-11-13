import { createPrivateKey, type KeyObject, X509Certificate } from "node:crypto";
import type {
	Document as XmlDocument,
	Element as XmlElement,
} from "@xmldom/xmldom";
import samlifyDefault, * as samlifyNamespace from "samlify";
import type * as z from "zod";
import {
	configuredSamlMetadataDescriptor,
	configuredServiceMetadata,
	effectiveSamlAssertionSigning,
	parseSamlXml as parseXML,
	requiredSignedSamlPostReceiver,
	samlMetadataShape,
	storedProjectSamlConfig,
} from "../../scripts/project-engine-saml-approval.mjs";
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

function invalid(): never {
	throw new Error("Invalid configured SAML authentication message.");
}

export function isSamlRelativeRedirect(value: string) {
	return /^\/(?!\/|\\|%2f|%5c)/i.test(value);
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

/** Resolve one signed POST receiver, with encryption limited to the fixture admission. */
export function declaredSignedSamlAcs(
	value: unknown,
	allowEncrypted?: boolean,
) {
	const saved = storedProjectSamlConfig.parse(value);
	const metadata = saved.spMetadata?.metadata;
	if (metadata === undefined) return undefined;
	const custom = configuredServiceMetadata(metadata);
	if (
		!allowEncrypted &&
		(saved.idpMetadata.isAssertionEncrypted ||
			saved.spMetadata?.isAssertionEncrypted)
	)
		invalid();
	return requiredSignedSamlPostReceiver(custom);
}

function pem(value: string | undefined) {
	return value
		?.split(/\r?\n/)
		.map((line) => line.trim())
		.join("\n")
		.trim();
}

function decryptionKey(
	idp: z.infer<typeof samlMetadataShape>,
	sp: z.infer<typeof samlMetadataShape> | undefined,
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

function validateCustomEncryptionCertificates(
	descriptor: XmlElement,
	serviceCertificate: string | string[] | null,
	privateKey: KeyObject,
) {
	const keys = children(descriptor, metadataNS, "KeyDescriptor").filter(
		(item) => item.getAttribute("use") === "encryption",
	);
	const advertised = serviceCertificate ? [serviceCertificate].flat() : [];
	if (!keys.length || keys.length > 16 || keys.length !== advertised.length)
		invalid();
	// Certificate renewal can keep a key. Every advertised certificate must
	// resolve to that key because the saved provider has a single decryption key.
	for (const [index, key] of keys.entries()) {
		const info = child(key, signatureNS, "KeyInfo");
		const data = child(info, signatureNS, "X509Data");
		const certificate = text(
			child(data, signatureNS, "X509Certificate"),
		).replace(/\s/g, "");
		if (
			certificate !== advertised[index]!.replace(/\s/g, "") ||
			!new X509Certificate(
				`-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`,
			).checkPrivateKey(privateKey)
		)
			invalid();
	}
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
	const saved = storedProjectSamlConfig.parse(value);
	const sp = saved.spMetadata;
	const idp = saved.idpMetadata;
	const encryptionKey = decryptionKey(idp, sp, options.allowEncrypted);
	const spMetadata = sp?.metadata;
	if (options.generatedSPOnly && spMetadata !== undefined) invalid();
	const custom =
		spMetadata === undefined
			? undefined
			: configuredServiceMetadata(spMetadata);
	const wantAssertion = effectiveSamlAssertionSigning(
		saved.wantAssertionsSigned,
		custom,
	);
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
		validateCustomEncryptionCertificates(
			custom.descriptor,
			service.entityMeta.getX509Certificate("encryption"),
			encryptionKey,
		);
	if (idp.metadata)
		configuredSamlMetadataDescriptor(idp.metadata, "IDPSSODescriptor");
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
	const dataAlgorithm = dataMethod.getAttribute("Algorithm");
	const keyParameters = Array.from(keyMethod.childNodes).filter(
		(node) => node.nodeType === 1,
	);
	if (
		(dataAlgorithm !== `${encryption11NS}aes128-gcm` &&
			dataAlgorithm !== `${encryption11NS}aes256-gcm`) ||
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
	return dataAlgorithm === `${encryption11NS}aes128-gcm`
		? ("aes128-gcm" as const)
		: ("aes256-gcm" as const);
}

async function authenticatedAssertion(
	xml: string,
	envelope: ReturnType<typeof parseSamlEnvelope>,
	configured: ConfiguredSaml,
) {
	const initialAssertion = configured.encrypted
		? undefined
		: plaintextAssertion(envelope);
	const cipher = configured.encrypted
		? checkEncryptedAssertion(envelope)
		: undefined;
	if (cipher) {
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
	const encryption = cipher
		? {
				cipher,
				keyTransport: "rsa-oaep-mgf1p" as const,
				envelopeSigned: Boolean(outer),
				assertionSigned: Boolean(inner.length),
			}
		: undefined;
	return { assertion, id, encryption };
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
	const { assertion, id, encryption } = await authenticatedAssertion(
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
	const requestId = response.getAttribute("InResponseTo");
	const destination = response.getAttribute("Destination") ?? "";
	if (
		(requestId === null
			? !configured.saved.idpInitiatedCallbackUrl
			: !signedId.test(requestId)) ||
		!configured.recipients.has(destination)
	)
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
	// A verified assertion without a request may only produce the disabled-flow redirect.
	if (requestId === null) return { requestId: null } as const;
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
		encryption,
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
