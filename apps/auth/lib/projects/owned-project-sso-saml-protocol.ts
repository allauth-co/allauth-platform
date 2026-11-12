import type { Element as XmlElement } from "@xmldom/xmldom";
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
	encPrivateKey: z.string().optional(),
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

function pem(value: string | undefined) {
	return value
		?.split(/\r?\n/)
		.map((line) => line.trim())
		.join("\n")
		.trim();
}

/** The configured plaintext SP/IdP pair, built with the same library as legacy SSO. */
export function configureOwnedSaml(
	value: unknown,
	acs: string,
	options: { relayState?: string; generatedSPOnly?: boolean } = {},
) {
	const saved = config.parse(value);
	const sp = saved.spMetadata;
	const idp = saved.idpMetadata;
	if (
		sp?.isAssertionEncrypted ||
		idp.isAssertionEncrypted ||
		sp?.encPrivateKey ||
		idp.encPrivateKey
	)
		invalid();
	const spMetadata = sp?.metadata;
	if (options.generatedSPOnly && spMetadata !== undefined) invalid();
	const spDescriptor =
		spMetadata && metadataDescriptor(spMetadata, "SPSSODescriptor");
	const wantAssertion = spDescriptor
		? ["true", "1"].includes(
				spDescriptor.getAttribute("WantAssertionsSigned")?.trim() ?? "",
			)
		: saved.wantAssertionsSigned === true;
	if (saved.wantAssertionsSigned && !wantAssertion) invalid();
	const postLocations = spDescriptor
		? children(spDescriptor, metadataNS, "AssertionConsumerService")
				.filter((item) => item.getAttribute("Binding") === post)
				.map((item) => item.getAttribute("Location") ?? "")
		: [acs];
	if (!postLocations.length) invalid();
	for (const location of postLocations) {
		const parsed = new URL(location);
		if (
			!/^https?:\/\//i.test(location) ||
			/[\\\u0000-\u0020\u007f]/.test(location) ||
			parsed.username ||
			parsed.password ||
			parsed.hash
		)
			invalid();
	}
	const requestPrivateKey = pem(sp?.privateKey || saved.privateKey);
	const metadataRequestsSigned =
		spDescriptor &&
		["true", "1"].includes(
			spDescriptor.getAttribute("AuthnRequestsSigned")?.trim() ?? "",
		);
	const requestsSigned =
		saved.authnRequestsSigned === true || metadataRequestsSigned === true;
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
		allowCreate: true,
		relayState: options.relayState,
	});
	if (requestsSigned && !service.entityMeta.isAuthnRequestSigned()) invalid();
	if (idp.metadata) metadataDescriptor(idp.metadata, "IDPSSODescriptor");
	const configuredCerts = idp.cert ?? saved.cert;
	const certs =
		typeof configuredCerts === "string" ? [configuredCerts] : configuredCerts;
	if (!idp.metadata && (!idp.entityID || !certs?.length)) invalid();
	const idpEntity = saml.IdentityProvider(
		idp.metadata
			? { metadata: idp.metadata }
			: {
					entityID: idp.entityID,
					signingCert: certs?.map((cert) => pem(cert)!),
					wantAuthnRequestsSigned: saved.authnRequestsSigned === true,
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
		postLocations,
		recipients: new Set([...postLocations, acs]),
		saved,
	};
}

/** Publish only the SP metadata for the callback served by the selected realm transport. */
export function projectSamlServiceMetadata(
	value: unknown,
	acs: string,
	generatedSPOnly?: boolean,
) {
	const configured = configureOwnedSaml(value, acs, { generatedSPOnly });
	if (!configured.postLocations.includes(acs)) invalid();
	return configured.service.getMetadata();
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

/** Verify XML signatures with Samlify and read identity only from its authenticated assertion. */
export function verifyOwnedSaml(encoded: string, configured: ConfiguredSaml) {
	if (encoded.length > 256 * 1024) invalid();
	const wire = encoded.replace(/[\t\n\r ]/g, "");
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(wire)) invalid();
	const xml = new TextDecoder("utf-8", { fatal: true }).decode(
		Uint8Array.from(atob(wire), (item) => item.charCodeAt(0)),
	);
	const document = parseXML(xml);
	const response = document.documentElement;
	if (
		!response ||
		response.namespaceURI !== protocolNS ||
		response.localName !== "Response" ||
		response.getAttribute("Version") !== "2.0"
	)
		invalid();
	const plain = child(response, assertionNS, "Assertion");
	const all = Array.from(response.getElementsByTagName("*"));
	if (
		all.filter((item) => item.localName === "Assertion").length !== 1 ||
		all.some((item) => item.localName === "EncryptedAssertion")
	)
		invalid();
	const responseId = response.getAttribute("ID") ?? "";
	const id = plain.getAttribute("ID") ?? "";
	const ids = [response, ...all].flatMap((item) =>
		Array.from(item.attributes)
			.filter((attr) => attr.localName?.toLowerCase() === "id")
			.map((attr) => attr.value),
	);
	if (
		!signedId.test(responseId) ||
		!signedId.test(id) ||
		new Set(ids).size !== ids.length
	)
		invalid();
	const outer = children(response, signatureNS, "Signature");
	const inner = children(plain, signatureNS, "Signature");
	if (
		outer.length > 1 ||
		inner.length > 1 ||
		all.filter((item) => item.localName === "Signature").length !==
			outer.length + inner.length ||
		(!outer.length && !inner.length) ||
		(configured.wantAssertion && !inner.length)
	)
		invalid();
	if (outer[0]) checkSignature(outer[0], responseId);
	if (inner[0]) checkSignature(inner[0], id);
	// Isolate the assertion signature when present. When it is absent, the sole
	// signature is the envelope signature referencing the unique response ID.
	const verification = {
		metadata: configured.idp.entityMeta,
		allowedSignatureAlgorithms: [...algorithms],
	};
	const outerResult =
		outer[0] &&
		saml.SamlLib.verifySignature(xml, {
			...verification,
			requireMessageSignature: true,
		});
	if (outerResult && !outerResult[0]) invalid();
	if (inner.length && outer[0]) response.removeChild(outer[0]);
	const [verified, authenticated] = inner.length
		? saml.SamlLib.verifySignature(document.toString(), verification)
		: outerResult || [false, null];
	if (!verified || !authenticated) invalid();
	const assertion = parseXML(authenticated).documentElement;
	if (
		!assertion ||
		assertion.localName !== "Assertion" ||
		assertion.namespaceURI !== assertionNS ||
		assertion.getAttribute("ID") !== id ||
		assertion.getAttribute("Version") !== "2.0"
	)
		invalid();
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
