import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { inflateRawSync } from "node:zlib";
import { DOMParser } from "@xmldom/xmldom";
import samlifyDefault, * as samlifyNamespace from "samlify";

const saml =
	typeof samlifyNamespace.SamlLib === "object"
		? samlifyNamespace
		: samlifyDefault;
export const runtimeSamlProvider = "runtime-fixture-saml";
export const runtimeSamlEntity = "https://saml.runtime.fixture.example/sp";
export const runtimeSamlIssuer =
	"https://idp.runtime.fixture.example/saml/entity";
export const runtimeSamlOrigin = new URL(runtimeSamlIssuer).origin;
export const runtimeSamlSubject = "fixture-runtime-saml-subject";

export async function createRuntimeSamlKeys() {
	const directory = await mkdtemp(join(tmpdir(), "allauth-runtime-saml-"));
	try {
		const key = join(directory, "key.pem");
		const cert = join(directory, "cert.pem");
		await promisify(execFile)(
			"openssl",
			[
				"req",
				"-x509",
				"-newkey",
				"rsa:2048",
				"-sha256",
				"-nodes",
				"-days",
				"1",
				"-subj",
				"/CN=allauth-runtime-saml",
				"-keyout",
				key,
				"-out",
				cert,
			],
			{ timeout: 5000 },
		);
		const [privateKey, certificate] = await Promise.all([
			readFile(key, "utf8"),
			readFile(cert, "utf8"),
		]);
		return { privateKey, certificate };
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

export async function renewRuntimeSamlCertificate(privateKey: string) {
	const directory = await mkdtemp(
		join(tmpdir(), "allauth-runtime-saml-renew-"),
	);
	try {
		const key = join(directory, "key.pem");
		await writeFile(key, privateKey, { mode: 0o600 });
		const { stdout } = await promisify(execFile)(
			"openssl",
			[
				"req",
				"-x509",
				"-new",
				"-key",
				key,
				"-sha256",
				"-days",
				"2",
				"-subj",
				"/CN=allauth-runtime-saml-renewed",
			],
			{ timeout: 5000 },
		);
		return stdout;
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

export function runtimeSamlConfiguration(
	keys: Awaited<ReturnType<typeof createRuntimeSamlKeys>>,
) {
	return {
		issuer: runtimeSamlEntity,
		entryPoint: `${runtimeSamlOrigin}/saml/redirect`,
		cert: keys.certificate,
		idpMetadata: { entityID: runtimeSamlIssuer },
		wantAssertionsSigned: true,
		authnRequestsSigned: true,
		privateKey: keys.privateKey,
	};
}

export function runtimeSamlAuthnRequest(location: URL) {
	const raw = location.searchParams.get("SAMLRequest");
	const relay = location.searchParams.get("RelayState");
	if (!raw || !relay) throw new Error("Missing synthetic SAML request.");
	const xml = inflateRawSync(Buffer.from(raw, "base64")).toString("utf8");
	const node = new DOMParser().parseFromString(xml, "text/xml").documentElement;
	const id = node?.getAttribute("ID");
	const acs = node?.getAttribute("AssertionConsumerServiceURL");
	if (!id || !acs) throw new Error("Invalid synthetic SAML request.");
	return { id, acs, relay };
}

export function runtimeSamlSPMetadata(
	acs: string,
	encryptCert?: string | string[],
	logout?: string,
) {
	const binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	return saml
		.SPMetadata({
			entityID: runtimeSamlEntity,
			assertionConsumerService: [{ Binding: binding, Location: acs }],
			singleLogoutService: logout
				? [{ Binding: binding, Location: logout }]
				: undefined,
			wantAssertionsSigned: true,
			authnRequestsSigned: true,
			encryptCert,
		})
		.getMetadata();
}

export async function runtimeSamlResponse(
	keys: Awaited<ReturnType<typeof createRuntimeSamlKeys>>,
	input: { acs: string; id?: string; relay?: string },
	email: string,
	encryption?: { certificate: string; dataAlgorithm?: string },
) {
	const now = new Date().toISOString();
	const expires = new Date(Date.now() + 120_000).toISOString();
	const id = `_${randomUUID()}`;
	const inResponseTo = input.id ? ` InResponseTo="${input.id}"` : "";
	const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}" Destination="${input.acs}"${inResponseTo}>
	<saml:Issuer>${runtimeSamlIssuer}</saml:Issuer>
	<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
	<saml:Assertion ID="${id}" Version="2.0" IssueInstant="${now}">
		<saml:Issuer>${runtimeSamlIssuer}</saml:Issuer>
		<saml:Subject><saml:NameID>${runtimeSamlSubject}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${inResponseTo} Recipient="${input.acs}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject>
		<saml:Conditions NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${runtimeSamlEntity}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
		<saml:AuthnStatement AuthnInstant="${now}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
		<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
	</saml:Assertion>
	</samlp:Response>`;
	const assertion = "/*[local-name(.)='Response']/*[local-name(.)='Assertion']";
	const signed = saml.SamlLib.constructSAMLSignature({
		rawSamlMessage: xml,
		referenceTagXPath: assertion,
		privateKey: keys.privateKey,
		signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		signingCert: saml.Utility.normalizeCerString(keys.certificate),
		isBase64Output: false,
		signatureConfig: {
			prefix: "ds",
			location: {
				reference: `${assertion}/*[local-name(.)='Issuer']`,
				action: "after",
			},
		},
	});
	const encoded = encryption
		? await encryptRuntimeSamlAssertion(signed, input.acs, encryption)
		: Buffer.from(signed).toString("base64");
	const form = new URLSearchParams({ SAMLResponse: encoded });
	if (input.relay) form.set("RelayState", input.relay);
	return form;
}

function encryptRuntimeSamlAssertion(
	signed: string,
	acs: string,
	encryption: { certificate: string; dataAlgorithm?: string },
) {
	const receiver = saml.ServiceProvider({
		entityID: runtimeSamlEntity,
		assertionConsumerService: [
			{
				Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: acs,
			},
		],
		encryptCert: encryption.certificate,
	});
	// Samlify consumes the encryption algorithms at runtime.
	const senderSettings: Parameters<typeof saml.IdentityProvider>[0] & {
		dataEncryptionAlgorithm: string;
		keyEncryptionAlgorithm: string;
	} = {
		entityID: runtimeSamlIssuer,
		isAssertionEncrypted: true,
		singleSignOnService: [
			{
				Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: `${runtimeSamlOrigin}/saml/redirect`,
			},
		],
		dataEncryptionAlgorithm:
			encryption.dataAlgorithm ?? "http://www.w3.org/2009/xmlenc11#aes256-gcm",
		keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	};
	return saml.SamlLib.encryptAssertion(
		saml.IdentityProvider(senderSettings),
		receiver,
		signed,
	);
}
