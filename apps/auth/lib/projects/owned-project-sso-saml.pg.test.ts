import { execFile } from "node:child_process";
import {
	createHash,
	createHmac,
	createPrivateKey,
	createVerify,
	randomUUID,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { inflateRawSync } from "node:zlib";
import { scim } from "@better-auth/scim";
import { sso } from "@better-auth/sso";
import { DOMParser } from "@xmldom/xmldom";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import samlifyDefault, * as samlifyNamespace from "samlify";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import { resolveEnterpriseUser } from "../enterprise";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { projectEmailAliases } from "../project-email-aliases";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { renewRuntimeSamlCertificate } from "./owned-project-runtime-saml-fixture";
import { createOwnedProjectSso } from "./owned-project-sso";
import { checkSsoPolicyFixture } from "./owned-project-sso-policy-fixture";
import { checkProjectSamlConfiguration } from "./owned-project-sso-saml-eligibility";
import {
	configureOwnedSaml,
	verifyOwnedSaml,
} from "./owned-project-sso-saml-protocol";

async function generateSamlKeys() {
	const directory = await mkdtemp(join(tmpdir(), "allauth-saml-fixture-"));
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
				"/CN=allauth-saml-fixture",
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

let fixtureKeys: Awaited<ReturnType<typeof generateSamlKeys>>;
let fixtureEncryptionKeys: Awaited<ReturnType<typeof generateSamlKeys>>;

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://owned-saml.fixture.example";
const issuer = "https://saml-idp.fixture.example/metadata";
const idpOrigin = new URL(issuer).origin;
const sp = `${origin}/saml/entity`;
const slug = "owned-saml-fixture";
const providerId = "fixture-saml";
const secret = "synthetic-project-saml-fixture-signing-secret";
const prefix = `allauth_project_${slug}`;
const destination = `${origin}/account?enterprise=saml`;
const defaultErrorURL = `${origin}/api/auth/error`;
const acs = `${origin}/api/auth/sso/saml2/sp/acs/${providerId}`;
const subject = "opaque-native-saml-directory-subject";
const managedEmail = "directory-profile@corp.example";
const decoyEmail = "decoy-profile@corp.example";
const signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const saml =
	typeof samlifyNamespace.SamlLib === "object"
		? samlifyNamespace
		: samlifyDefault;
const configuration = () => ({
	issuer: sp,
	entryPoint: `${idpOrigin}/redirect`,
	cert: fixtureKeys.certificate,
	idpMetadata: { entityID: issuer },
	wantAssertionsSigned: true,
	mapping: { email: "corpEmail" },
});
const body = {
	providerId,
	callbackURL: destination,
	providerType: "saml" as const,
};
const scopedKey = (parts: string[]) =>
	createHash("sha256").update(JSON.stringify(parts)).digest("base64url");
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

async function nativeSso(
	db: LegacyDatabase,
	withAudit = false,
	aliases: ProjectEmailAliasMap = {},
) {
	return (
		await getTestInstance(
			{
				baseURL: origin,
				secret,
				trustedOrigins: [idpOrigin],
				logger: { disabled: true },
				database: { db, type: "postgres", transaction: true },
				advanced: { cookiePrefix: prefix },
				account: {
					encryptOAuthTokens: true,
					accountLinking: { enabled: true, trustedProviders: [] },
				},
				plugins: [
					projectEmailAliases({
						project: slug,
						readConfiguration: () => JSON.stringify(aliases),
					}),
					...(withAudit
						? [
								allauthControl({
									database: db,
									secret,
									baseURL: origin,
									ipHeader: "x-real-ip",
								}),
							]
						: []),
					{
						id: "fixture-saml-directory",
						schema: {
							allauthDirectory: {
								fields: {
									providerId: { type: "string", required: true },
									organizationId: { type: "string", required: true },
									connectionId: { type: "string", required: true },
									createdAt: { type: "date", required: true },
								},
							},
						},
					},
					scim({
						connections: [],
						managedConnections: {
							credentialHashSecret: "synthetic-saml-scim-credential-secret",
						},
					}),
					sso({
						domainVerification: { enabled: true },
						resolveUser: resolveEnterpriseUser,
						saml: {
							enableInResponseToValidation: true,
							allowIdpInitiated: false,
							requireTimestamps: true,
							clockSkew: 60_000,
							algorithms: { onDeprecated: "reject" },
						},
					}),
				],
			},
			{ disableTestUser: true },
		)
	).auth;
}

function startRequest(input = body) {
	return new Request(`${origin}/api/auth/sign-in/sso`, {
		method: "POST",
		headers: { origin, "content-type": "application/json" },
		body: JSON.stringify(input),
	});
}

function callback(samlResponse: string, relay?: string, receiver = acs) {
	const data = new URLSearchParams({ SAMLResponse: samlResponse });
	if (relay) data.set("RelayState", relay);
	return new Request(receiver, {
		method: "POST",
		headers: {
			origin: idpOrigin,
			"content-type": "application/x-www-form-urlencoded",
			"sec-fetch-site": "cross-site",
			"sec-fetch-mode": "navigate",
		},
		body: data,
	});
}

function cookies(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((cookie) => !/;\s*Max-Age=0(?:;|$)/i.test(cookie))
		.map((cookie) => cookie.split(";", 1)[0])
		.join("; ");
}

async function pending(response: Response, receiver = acs) {
	expect(response.status, await response.clone().text()).toBe(200);
	const result = (await response.json()) as { url: string; redirect: boolean };
	expect(result.redirect).toBe(true);
	const redirect = new URL(result.url);
	expect(redirect.origin).toBe(idpOrigin);
	const raw = redirect.searchParams.get("SAMLRequest");
	expect(raw).toBeTruthy();
	const xml = inflateRawSync(Buffer.from(raw!, "base64")).toString("utf8");
	const root = new DOMParser().parseFromString(xml, "text/xml").documentElement;
	expect(root?.getAttribute("AssertionConsumerServiceURL")).toBe(receiver);
	const requestId = root?.getAttribute("ID");
	const relay = redirect.searchParams.get("RelayState");
	expect(requestId).toBeTruthy();
	expect(relay).toBeTruthy();
	return { requestId: requestId!, relay: relay!, redirect, document: root! };
}

function signedResponse(
	requestId: string | undefined,
	options: {
		assertionId?: string;
		issuer?: string;
		audience?: string;
		recipient?: string;
		receiver?: string;
		email?: string;
		subject?: string;
		expired?: boolean;
		signature?: "assertion" | "response" | "both" | "none";
	} = {},
) {
	const now = new Date().toISOString();
	const expires = new Date(
		Date.now() + (options.expired ? -120_000 : 180_000),
	).toISOString();
	const assertionId = options.assertionId ?? `_${randomUUID()}`;
	const actualIssuer = options.issuer ?? issuer;
	const signature = options.signature ?? "assertion";
	const receiver = options.receiver ?? acs;
	const inResponseTo = requestId ? ` InResponseTo="${requestId}"` : "";
	let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" Version="2.0" IssueInstant="${now}" Destination="${receiver}"${inResponseTo}>
		<saml:Issuer>${actualIssuer}</saml:Issuer>
		<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
		<saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${now}">
			<saml:Issuer>${actualIssuer}</saml:Issuer>
			<saml:Subject><saml:NameID>${options.subject ?? subject}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${inResponseTo} Recipient="${options.recipient ?? receiver}" NotOnOrAfter="${expires}"/></saml:SubjectConfirmation></saml:Subject>
			<saml:Conditions NotOnOrAfter="${expires}"><saml:AudienceRestriction><saml:Audience>${options.audience ?? sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
			<saml:AuthnStatement AuthnInstant="${now}" SessionIndex="_${randomUUID()}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
			<saml:AttributeStatement><saml:Attribute Name="corpEmail"><saml:AttributeValue>${options.email ?? decoyEmail}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
		</saml:Assertion>
	</samlp:Response>`;

	if (signature === "assertion" || signature === "both")
		xml = signSamlFixture(xml, true);
	if (signature === "response" || signature === "both")
		xml = signSamlFixture(xml, false);
	return { assertionId, encoded: Buffer.from(xml).toString("base64") };
}

function signSamlFixture(xml: string, assertion: boolean) {
	const node = assertion
		? "/*[local-name(.)='Response']/*[local-name(.)='Assertion']"
		: "/*[local-name(.)='Response']";
	return saml.SamlLib.constructSAMLSignature({
		rawSamlMessage: xml,
		referenceTagXPath: assertion ? node : undefined,
		privateKey: fixtureKeys.privateKey,
		signatureAlgorithm,
		signingCert: saml.Utility.normalizeCerString(fixtureKeys.certificate),
		isBase64Output: false,
		isMessageSigned: !assertion,
		signatureConfig: {
			prefix: "ds",
			location: {
				reference: `${node}/*[local-name(.)='Issuer']`,
				action: "after",
			},
		},
	});
}
type SAMLSigning = "assertion" | "response" | "both";

function encryptedConfiguration(wantAssertionsSigned = true) {
	const configured = configuration();
	const passphrase = "synthetic-realm-saml-key-passphrase";
	const key = createPrivateKey(fixtureEncryptionKeys.privateKey)
		.export({
			type: "pkcs8",
			format: "pem",
			cipher: "aes-256-cbc",
			passphrase,
		})
		.toString();
	return {
		...configured,
		wantAssertionsSigned,
		idpMetadata: { ...configured.idpMetadata, isAssertionEncrypted: true },
		spMetadata: {
			isAssertionEncrypted: true,
			encPrivateKey: key,
			encPrivateKeyPass: passphrase,
		},
	};
}

async function encryptedFixtureResponse(
	requestId: string,
	signing: SAMLSigning,
	options: {
		certificate?: string;
		dataAlgorithm?: string;
		keyAlgorithm?: string;
	} = {},
) {
	const fixture = signedResponse(requestId, {
		signature: signing === "response" ? "none" : "assertion",
	});
	const receiver = saml.ServiceProvider({
		entityID: sp,
		assertionConsumerService: [
			{
				Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: acs,
			},
		],
		encryptCert: options.certificate ?? fixtureEncryptionKeys.certificate,
	});
	// Samlify consumes these entity settings at runtime and omits them from its declarations.
	const senderSettings: Parameters<typeof saml.IdentityProvider>[0] & {
		dataEncryptionAlgorithm: string;
		keyEncryptionAlgorithm: string;
	} = {
		entityID: issuer,
		isAssertionEncrypted: true,
		singleSignOnService: [
			{
				Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: `${idpOrigin}/redirect`,
			},
		],
		dataEncryptionAlgorithm:
			options.dataAlgorithm ?? "http://www.w3.org/2009/xmlenc11#aes256-gcm",
		keyEncryptionAlgorithm:
			options.keyAlgorithm ?? "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	};
	const sender = saml.IdentityProvider(senderSettings);
	const encrypted = await saml.SamlLib.encryptAssertion(
		sender,
		receiver,
		Buffer.from(fixture.encoded, "base64").toString("utf8"),
	);
	if (signing === "assertion") return encrypted;
	return Buffer.from(
		signSamlFixture(Buffer.from(encrypted, "base64").toString("utf8"), false),
	).toString("base64");
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL project SAML interoperability",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const managed = randomUUID();
		const decoy = randomUUID();
		const organization = randomUUID();
		const connection = randomUUID();
		const source = randomUUID();
		const domain = `organization:${organization}`;
		let database: Pool;
		let administrator: Pool | undefined;
		let nativeDatabase: LegacyDatabase | undefined;
		let native: Awaited<ReturnType<typeof nativeSso>>;
		let created = false;

		beforeAll(async () => {
			[fixtureKeys, fixtureEncryptionKeys] = await Promise.all([
				generateSamlKeys(),
				generateSamlKeys(),
			]);
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error("SAML tests require the isolated PostgreSQL fixture.");
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 6 });
			await database.query(`CREATE SCHEMA "${schema}"`);
			const nativePool = new Pool({
				connectionString: url.toString(),
				options: `-c search_path=${schema}`,
				max: 2,
			});
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({ pool: nativePool }),
			});
			for (const migration of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"005-free-plugins.sql",
				"006-analytics.sql",
			])
				await nativePool.query(
					readFileSync(
						new URL(`../../migrations/${migration}`, import.meta.url),
						"utf8",
					),
				);
			await nativePool.query(
				`INSERT INTO "user"(id,email,name,"emailVerified","directoryManaged","directoryDisabled") VALUES ($1,$2,'Directory user',TRUE,TRUE,FALSE),($3,$4,'Decoy',TRUE,FALSE,FALSE)`,
				[managed, managedEmail, decoy, decoyEmail],
			);
			await nativePool.query(
				`INSERT INTO "organization"(id,name,slug,"createdAt") VALUES ($1,'Fixture Organization','fixture-company',statement_timestamp())`,
				[organization],
			);
			await nativePool.query(
				`INSERT INTO "ssoProvider"(id,"providerId",issuer,"samlConfig","userId","organizationId",domain,"domainVerified") VALUES ($1,$2,$3,$4,$5,$6,'corp.example',TRUE)`,
				[
					randomUUID(),
					providerId,
					sp,
					JSON.stringify(configuration()),
					decoy,
					organization,
				],
			);
			await nativePool.query(
				`INSERT INTO "allauthDirectory"(id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$2,$3,$4,statement_timestamp())`,
				[randomUUID(), providerId, organization, connection],
			);
			await nativePool.query(
				`INSERT INTO "scimManagedConnection"(id,"creationRequestId","connectionId","provisioningDomainId",status,revision,"createdAt","createdBy") VALUES ($1,$2,$3,$4,'active',0,statement_timestamp(),$5)`,
				[randomUUID(), randomUUID(), connection, domain, decoy],
			);
			await nativePool.query(
				`INSERT INTO "scimConnectionBinding"(id,"connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionReconciledUserCount","decommissionBatchCount","decommissionRevision") VALUES ($1,$2,$3,$4,statement_timestamp(),'active',0,0,0)`,
				[
					randomUUID(),
					connection,
					scopedKey(["scim-connection", connection]),
					domain,
				],
			);
			await nativePool.query(
				`INSERT INTO "scimSubject"(id,"userId","profileSourceId",revision,"createdAt","updatedAt") VALUES ($1,$2,$3,0,statement_timestamp(),statement_timestamp())`,
				[randomUUID(), managed, source],
			);
			await nativePool.query(
				`INSERT INTO "scimUser"(id,"connectionId","provisioningDomainId","userId","connectionUserKey","userName","userNameKey","primaryEmail","workEmailValueIndex","emailValueIndex","displayName","formattedName","serializedEmails","serializedAttributes","externalId","externalIdKey",active,"orderKey","createdAt","updatedAt") VALUES ($1,$2,$3,$4,$1,$5,$1,$5,'','','Directory user','Directory user','[]','{}',$6,$7,TRUE,$1,statement_timestamp(),statement_timestamp())`,
				[
					source,
					connection,
					domain,
					managed,
					managedEmail,
					subject,
					scopedKey(["scim-user-external-id", connection, subject]),
				],
			);
			native = await nativeSso(nativeDatabase);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		function owned(saml: true | "encrypted-fixture" = true) {
			const store = createProjectEngineStore(database, schema);
			return createOwnedProjectSso({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				defaultErrorURL: `${origin}/auth-error`,
				signUpEnabled: true,
				saml,
				async complete(client, input) {
					expect(input).toMatchObject({
						user: { id: managed },
						providerId,
						managed: true,
						protocol: "saml",
					});
					const token = randomUUID();
					await store.createSession(client, {
						id: randomUUID(),
						token,
						userId: input.user.id,
						expiresIn: 604800,
						ip: "192.0.2.12",
						userAgent: "SAML fixture",
					});
					const signature = createHmac("sha256", secret)
						.update(token)
						.digest("base64");
					return new Response(null, {
						status: 302,
						headers: {
							location: input.destination,
							"set-cookie": `__Secure-${prefix}.session_token=${encodeURIComponent(`${token}.${signature}`)}; Path=/; HttpOnly; Secure; SameSite=Lax`,
						},
					});
				},
			});
		}

		async function samlAdministrator() {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."user"(id,email,name,"emailVerified",role) VALUES ($1,$2,'SAML Admin',TRUE,'admin')`,
				[id, `${id}@corp.example`],
			);
			await database.query(
				`INSERT INTO "${schema}"."session"(id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
				[randomUUID(), token, id],
			);
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			return {
				id,
				cookie: `__Secure-${prefix}.session_token=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		function managementRequest(
			path: string,
			cookie: string,
			input?: object,
			requestOrigin = origin,
		) {
			return new Request(`${origin}/api/auth/sso/${path}`, {
				method: input ? "POST" : "GET",
				headers: {
					origin: requestOrigin,
					cookie,
					...(input ? { "content-type": "application/json" } : {}),
				},
				body: input ? JSON.stringify(input) : undefined,
			});
		}

		function managementEngine(enabled = true) {
			return createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: ["https://saml-application.fixture.example"],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "192.0.2.31",
				sso: { defaultErrorURL: `${origin}/auth-error`, saml: enabled },
			});
		}

		async function assertSession(response: Response, expected = destination) {
			expect(
				response.headers.get("location"),
				await response.clone().text(),
			).toBe(expected);
			expect(
				await native.api.getSession({
					headers: new Headers({ cookie: cookies(response) }),
					query: { disableRefresh: true },
				}),
			).toMatchObject({
				user: { id: managed, email: managedEmail, name: "Directory user" },
			});
			expect(
				(
					await database.query(
						`SELECT "userId", "accountId", "accessToken", "refreshToken" FROM "${schema}"."account" WHERE "providerId" = $1`,
						[providerId],
					)
				).rows,
			).toEqual([
				{
					userId: managed,
					accountId: subject,
					accessToken: "",
					refreshToken: "",
				},
			]);
		}

		async function startOwned() {
			return pending(await owned().start(startRequest(), body));
		}

		async function storeSamlConfiguration(value: object) {
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "samlConfig"=$1 WHERE "providerId"=$2`,
				[JSON.stringify(value), providerId],
			);
		}

		it("records the same redacted callback failure for a signed inactive-directory assertion", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped native database.");
			const stock = await nativeSso(nativeDatabase, true);
			const candidate = managementEngine();
			const userAgent = "Synthetic inactive SAML directory fixture";
			const ipAddress = "192.0.2.31";
			const path = "/sso/saml2/sp/acs/:providerId";
			await database.query(
				`UPDATE "${schema}"."scimUser" SET active=FALSE WHERE id=$1`,
				[source],
			);
			try {
				async function exercise(
					dispatch: (request: Request) => Promise<Response>,
				) {
					const countSessions = async () =>
						(await database.query(`SELECT id FROM "${schema}"."session"`))
							.rowCount;
					const before = await countSessions();
					const initial = await pending(await dispatch(startRequest()));
					const proof = signedResponse(initial.requestId);
					const incoming = callback(proof.encoded, initial.relay);
					incoming.headers.set("x-real-ip", ipAddress);
					incoming.headers.set("user-agent", userAgent);
					const result = await dispatch(incoming);
					expect(result.status).toBe(302);
					expect(
						new URL(result.headers.get("location")!).searchParams.has("error"),
					).toBe(true);
					expect(
						result.headers
							.getSetCookie()
							.some((value) => value.includes("session_token=")),
					).toBe(false);
					expect(await countSessions()).toBe(before);
					const rows = (
						await database.query(
							`SELECT type,outcome,"actorId","userId","targetId","ipAddress","userAgent",metadata
						 FROM "${schema}"."allauthEvent" WHERE "userAgent"=$1 ORDER BY type`,
							[userAgent],
						)
					).rows;
					await database.query(
						`DELETE FROM "${schema}"."allauthEvent" WHERE "userAgent"=$1`,
						[userAgent],
					);
					for (const privateValue of [
						subject,
						decoyEmail,
						initial.relay,
						proof.encoded,
						proof.assertionId,
					])
						expect(JSON.stringify(rows)).not.toContain(privateValue);
					return rows;
				}
				const expected = await exercise(stock.handler);
				expect(expected).toEqual([
					{
						type: "auth.sign-in",
						outcome: "failure",
						actorId: null,
						userId: null,
						targetId: null,
						ipAddress,
						userAgent,
						metadata: { path, errorCode: "directory_identity_inactive" },
					},
					{
						type: "security.sign-in-failed",
						outcome: "failure",
						actorId: null,
						userId: null,
						targetId: null,
						ipAddress,
						userAgent,
						metadata: { path, method: ":providerId" },
					},
				]);
				expect(await exercise(candidate.dispatch)).toEqual(expected);
			} finally {
				await database.query(
					`UPDATE "${schema}"."scimUser" SET active=TRUE WHERE id=$1`,
					[source],
				);
			}
		});

		it.each([
			{
				order: "sign-then-encrypt",
				signing: "assertion" as const,
				requireAssertion: true,
				bits: 128,
			},
			{
				order: "encrypt-then-sign",
				signing: "response" as const,
				requireAssertion: false,
				bits: 256,
			},
			{
				order: "both signatures",
				signing: "both" as const,
				requireAssertion: true,
				bits: 256,
			},
		])("round-trips encrypted $order through native and owned sessions", async ({
			signing,
			requireAssertion,
			bits,
		}) => {
			const encryptedConfig = encryptedConfiguration(requireAssertion);
			await storeSamlConfiguration({
				...encryptedConfig,
				spMetadata: {
					...encryptedConfig.spMetadata,
					isAssertionEncrypted: signing !== "response",
				},
			});
			const engine = owned("encrypted-fixture");
			const encryption = {
				dataAlgorithm: `http://www.w3.org/2009/xmlenc11#aes${bits}-gcm`,
			};
			try {
				const issuedByNative = await pending(
					await native.handler(startRequest()),
				);
				await assertSession(
					await engine.samlCallback(
						callback(
							await encryptedFixtureResponse(
								issuedByNative.requestId,
								signing,
								encryption,
							),
							issuedByNative.relay,
						),
						providerId,
					),
				);
				const issuedByOwned = await pending(
					await engine.start(startRequest(), body),
				);
				await assertSession(
					await native.handler(
						callback(
							await encryptedFixtureResponse(
								issuedByOwned.requestId,
								signing,
								encryption,
							),
							issuedByOwned.relay,
						),
					),
				);
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("requires the selected realm's decryption key and configured signed assertion policy", async () => {
			const configured = encryptedConfiguration();
			await storeSamlConfiguration(configured);
			const engine = owned("encrypted-fixture");
			try {
				const disabled = await owned().start(startRequest(), body);
				expect(disabled.status).toBe(400);
				await storeSamlConfiguration({
					...configured,
					spMetadata: {
						...configured.spMetadata,
						encPrivateKeyPass: "different-synthetic-passphrase",
					},
				});
				expect((await engine.start(startRequest(), body)).status).toBe(400);
				await storeSamlConfiguration(configured);
				const initial = await database.query<{ count: number }>(
					`SELECT count(*)::int AS count FROM "${schema}"."session" WHERE "userId"=$1`,
					[managed],
				);
				const state = await pending(await engine.start(startRequest(), body));
				for (const assertion of [
					signedResponse(state.requestId).encoded,
					await encryptedFixtureResponse(state.requestId, "assertion", {
						certificate: fixtureKeys.certificate,
					}),
					await encryptedFixtureResponse(state.requestId, "response"),
					await encryptedFixtureResponse(state.requestId, "assertion", {
						dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
					}),
				]) {
					const rejected = await engine.samlCallback(
						callback(assertion, state.relay),
						providerId,
					);
					expect(rejected.status, await rejected.clone().text()).toBe(400);
					expect(await rejected.json()).toEqual({
						code: "INVALID_SAML_RESPONSE",
						message: "Invalid SAML response.",
					});
					expect(cookies(rejected)).toBe("");
				}
				const after = await database.query<{ count: number }>(
					`SELECT count(*)::int AS count FROM "${schema}"."session" WHERE "userId"=$1`,
					[managed],
				);
				expect(after.rows).toEqual(initial.rows);
				await assertSession(
					await engine.samlCallback(
						callback(
							await encryptedFixtureResponse(state.requestId, "assertion"),
							state.relay,
						),
						providerId,
					),
				);
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("preserves encrypted sign-in across same-key certificate renewal and rollback", async () => {
			const original = fixtureEncryptionKeys.certificate;
			const renewed = await renewRuntimeSamlCertificate(
				fixtureEncryptionKeys.privateKey,
			);
			expect(renewed).not.toBe(original);
			const generated = encryptedConfiguration();
			const withCertificates = (certificates: string[]) => ({
				...generated,
				authnRequestsSigned: true,
				spMetadata: {
					...generated.spMetadata,
					privateKey: fixtureKeys.privateKey,
					metadata: saml
						.SPMetadata({
							entityID: sp,
							assertionConsumerService: [
								{
									Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
									Location: acs,
								},
							],
							wantAssertionsSigned: true,
							authnRequestsSigned: true,
							encryptCert: certificates,
						})
						.getMetadata(),
				},
			});
			const engine = owned("encrypted-fixture");
			try {
				await storeSamlConfiguration(withCertificates([original, renewed]));
				const legacy = await pending(await native.handler(startRequest()));
				await assertSession(
					await engine.samlCallback(
						callback(
							await encryptedFixtureResponse(legacy.requestId, "assertion", {
								certificate: original,
							}),
							legacy.relay,
						),
						providerId,
					),
				);
				const ownedPending = await pending(
					await engine.start(startRequest(), body),
				);
				await assertSession(
					await native.handler(
						callback(
							await encryptedFixtureResponse(
								ownedPending.requestId,
								"assertion",
								{
									certificate: renewed,
								},
							),
							ownedPending.relay,
						),
					),
				);
				await storeSamlConfiguration(
					withCertificates([original, fixtureKeys.certificate]),
				);
				const rejected = await engine.start(startRequest(), body);
				expect(rejected.status).toBe(400);
				expect(cookies(rejected)).toBe("");
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("keeps legacy CBC and XML Encryption 1.1 key transport outside the supported overlap", async () => {
			await storeSamlConfiguration(encryptedConfiguration());
			try {
				const legacy = await pending(await native.handler(startRequest()));
				const cbc = await encryptedFixtureResponse(
					legacy.requestId,
					"assertion",
					{
						dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
					},
				);
				await assertSession(await native.handler(callback(cbc, legacy.relay)));

				const candidate = owned("encrypted-fixture");
				const issued = await pending(
					await candidate.start(startRequest(), body),
				);
				const xml11 = await encryptedFixtureResponse(
					issued.requestId,
					"assertion",
					{
						keyAlgorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
					},
				);
				const result = await candidate.samlCallback(
					callback(xml11, issued.relay),
					providerId,
				);
				expect(result.status).toBe(400);
				expect(cookies(result)).toBe("");
				const libraryError = vi
					.spyOn(console, "error")
					.mockImplementation(() => {});
				try {
					const rollback = await native.handler(callback(xml11, issued.relay));
					expect(rollback.status).toBe(302);
					const error = new URL(rollback.headers.get("location")!);
					expect(error.searchParams.get("error")).toBe("saml_error");
					expect(cookies(rollback)).toBe("");
					expect(libraryError).toHaveBeenCalledWith(
						expect.objectContaining({
							message:
								"key encryption algorithm http://www.w3.org/2009/xmlenc11#rsa-oaep not supported",
						}),
					);
				} finally {
					libraryError.mockRestore();
				}
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("finishes a native request using a verified assertion and the exact managed subject", async () => {
			const state = await pending(await native.handler(startRequest()));
			const signed = signedResponse(state.requestId);
			const protocol = configureOwnedSaml(configuration(), acs);
			expect((await verifyOwnedSaml(signed.encoded, protocol)).requestId).toBe(
				state.requestId,
			);
			await assertSession(
				await owned().samlCallback(
					callback(signed.encoded, state.relay),
					providerId,
				),
			);
			const identifier = `saml-used-assertion:${signed.assertionId}`;
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."verification" WHERE identifier = $1`,
						[identifier],
					)
				).rows,
			).toEqual([
				{
					id: createHash("sha256")
						.update(`reserve:${identifier}`)
						.digest("base64url"),
				},
			]);
		});

		it("starts a legacy-readable request that the native ACS can complete after rollback", async () => {
			const state = await startOwned();
			const signed = signedResponse(state.requestId);
			await assertSession(
				await native.handler(callback(signed.encoded, state.relay)),
			);
		});

		it("rejects additional authorization parameters before either SAML writer issues state", async () => {
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.83",
				sso: { defaultErrorURL: `${origin}/auth-error`, saml: true },
			});
			for (const additionalParams of [{}, { prompt: "login" }]) {
				const input = { ...body, additionalParams };
				const legacy = await native.handler(startRequest(input));
				const candidate = await engine.dispatch(startRequest(input));
				expect(legacy.status).toBe(400);
				expect(candidate.status).toBe(legacy.status);
				expect(await candidate.json()).toEqual(await legacy.json());
				expect(cookies(legacy)).toBe("");
				expect(cookies(candidate)).toBe("");
			}
		});

		it("preserves reserved SAML email errors and an existing provider subject binding", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const email = "saml-reserved@corp.example";
			const aliases = { [email]: decoy };
			const provider = "reserved-saml-fixture";
			const receiver = `${origin}/api/auth/sso/saml2/sp/acs/${provider}`;
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"samlConfig","userId",domain,"domainVerified")
				 VALUES ($1,$2,$3,$4,$5,'corp.example',TRUE)`,
				[randomUUID(), provider, sp, JSON.stringify(configuration()), decoy],
			);
			const legacy = await nativeSso(nativeDatabase, false, aliases);
			const candidate = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.82",
				emailAliases: aliases,
				sso: { defaultErrorURL, saml: true },
			});
			const complete = async (
				dispatch: (request: Request) => Promise<Response>,
				errorCallbackURL?: string,
			) => {
				const input = { ...body, providerId: provider, errorCallbackURL };
				const state = await pending(
					await dispatch(startRequest(input)),
					receiver,
				);
				const signed = signedResponse(state.requestId, { email, receiver });
				return dispatch(callback(signed.encoded, state.relay, receiver));
			};
			for (const dispatch of [legacy.handler, candidate.dispatch]) {
				for (const errorCallbackURL of [
					undefined,
					`${origin}/saml-error?custom=1`,
				]) {
					const denied = await complete(dispatch, errorCallbackURL);
					expect(denied.status).toBe(302);
					const target = new URL(denied.headers.get("location")!);
					const expected = new URL(errorCallbackURL ?? defaultErrorURL);
					expect(target.pathname).toBe(expected.pathname);
					expect(Object.fromEntries(target.searchParams)).toEqual({
						...Object.fromEntries(expected.searchParams),
						error: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
						error_description: "User already exists. Use another email.",
					});
				}
			}
			expect(
				(
					await database.query(
						`SELECT id FROM "${schema}"."user" WHERE email=$1
				 UNION ALL SELECT id FROM "${schema}"."account" WHERE "providerId"=$2`,
						[email, provider],
					)
				).rows,
			).toEqual([]);
			await database.query(
				`INSERT INTO "${schema}"."account"(id,"accountId","providerId","userId","updatedAt")
				 VALUES ($1,$2,$3,$4,statement_timestamp())`,
				[randomUUID(), subject, provider, decoy],
			);
			for (const dispatch of [legacy.handler, candidate.dispatch]) {
				const response = await complete(dispatch);
				expect(response.headers.get("location")).toBe(destination);
				const session = await legacy.api.getSession({
					headers: new Headers({ cookie: cookies(response) }),
					query: { disableRefresh: true },
				});
				expect(session?.user).toMatchObject({ id: decoy, email: decoyEmail });
			}
		});

		it("uses the configured private key for signed Redirect AuthnRequests", async () => {
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "samlConfig" = $1 WHERE "providerId" = $2`,
				[
					JSON.stringify({
						...configuration(),
						authnRequestsSigned: true,
						privateKey: fixtureKeys.privateKey,
					}),
					providerId,
				],
			);
			try {
				const started = await owned().start(startRequest(), body);
				const state = await pending(started.clone());
				const { url } = (await started.json()) as { url: string };
				const wire = new URL(url);
				const signature = wire.searchParams.get("Signature");
				expect(signature).toBeTruthy();
				const parameters = wire.search
					.slice(1)
					.split("&")
					.filter((value) => !value.startsWith("Signature="));
				expect(parameters.map((value) => value.split("=")[0])).toEqual([
					"SAMLRequest",
					"RelayState",
					"SigAlg",
				]);
				expect(
					createVerify("RSA-SHA256")
						.update(parameters.join("&"))
						.verify(fixtureKeys.certificate, signature!, "base64"),
				).toBe(true);
				await assertSession(
					await native.handler(
						callback(signedResponse(state.requestId).encoded, state.relay),
					),
				);
			} finally {
				await database.query(
					`UPDATE "${schema}"."ssoProvider" SET "samlConfig" = $1 WHERE "providerId" = $2`,
					[JSON.stringify(configuration()), providerId],
				);
			}
		});

		it("publishes saved custom SP metadata and completes signed requests across native and owned writers", async () => {
			const entity = "urn:allauth:fixture:custom-service-provider";
			const rawMetadata = saml
				.SPMetadata({
					entityID: entity,
					authnRequestsSigned: true,
					wantAssertionsSigned: true,
					signingCert: fixtureKeys.certificate,
					nameIDFormat: [
						"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					],
					assertionConsumerService: [
						{
							Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: acs,
						},
					],
				})
				.getMetadata()
				.replace(
					"<EntityDescriptor ",
					'<EntityDescriptor ID="_fixture-custom-sp-metadata" ',
				);
			const metadataRoot = "/*[local-name(.)='EntityDescriptor']";
			const metadata = saml.SamlLib.constructSAMLSignature({
				rawSamlMessage: rawMetadata,
				referenceTagXPath: metadataRoot,
				privateKey: fixtureKeys.privateKey,
				signatureAlgorithm,
				signingCert: saml.Utility.normalizeCerString(fixtureKeys.certificate),
				isBase64Output: false,
				signatureConfig: {
					prefix: "ds",
					location: {
						reference: `${metadataRoot}/*[local-name(.)='SPSSODescriptor']`,
						action: "before",
					},
				},
			});
			const custom = {
				...configuration(),
				authnRequestsSigned: true,
				spMetadata: { metadata, privateKey: fixtureKeys.privateKey },
			};
			await storeSamlConfiguration(custom);
			try {
				checkProjectSamlConfiguration({ issuer: sp, samlConfig: custom }, acs);
				expect(() =>
					checkProjectSamlConfiguration(
						{
							issuer: sp,
							samlConfig: {
								...custom,
								spMetadata: {
									...custom.spMetadata,
									privateKey: fixtureEncryptionKeys.privateKey,
								},
							},
						},
						acs,
					),
				).toThrow("outside the candidate transport");
				const metadataRequest = new Request(
					`${origin}/api/auth/sso/saml2/sp/metadata?providerId=${providerId}`,
				);
				const selected = managementEngine();
				for (const response of [
					await native.handler(metadataRequest),
					await selected.dispatch(metadataRequest),
				]) {
					expect(response.status).toBe(200);
					expect(response.headers.get("content-type")).toBe("application/xml");
					expect(await response.text()).toBe(metadata);
				}
				const candidate = owned();
				const started = [
					await native.handler(startRequest()),
					await candidate.start(startRequest(), body),
				];
				for (const [index, response] of started.entries()) {
					const state = await pending(response);
					expect(
						state.document.getElementsByTagNameNS(
							"urn:oasis:names:tc:SAML:2.0:assertion",
							"Issuer",
						)[0]?.textContent,
					).toBe(entity);
					const signature = state.redirect.searchParams.get("Signature");
					const signed = state.redirect.search
						.slice(1)
						.split("&")
						.filter((value) => !value.startsWith("Signature="))
						.join("&");
					expect(
						createVerify("RSA-SHA256")
							.update(signed)
							.verify(fixtureKeys.certificate, signature!, "base64"),
					).toBe(true);
					const assertion = signedResponse(state.requestId, {
						audience: entity,
					});
					const completion = callback(assertion.encoded, state.relay);
					await assertSession(
						await (index === 0
							? candidate.samlCallback(completion, providerId)
							: native.handler(completion)),
					);
				}
				const wrongAudience = await pending(
					await native.handler(startRequest()),
				);
				const denied = await candidate.samlCallback(
					callback(
						signedResponse(wrongAudience.requestId, { audience: sp }).encoded,
						wrongAudience.relay,
					),
					providerId,
				);
				expect(denied.status).toBe(400);
				expect(cookies(denied)).toBe("");
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("preserves saved SingleLogoutService metadata and disabled SLO across both project writers", async () => {
			const slo = `${origin}/api/auth/sso/saml2/sp/slo/${providerId}`;
			const binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
			const metadata = saml
				.SPMetadata({
					entityID: sp,
					authnRequestsSigned: true,
					wantAssertionsSigned: true,
					signingCert: fixtureKeys.certificate,
					singleLogoutService: [{ Binding: binding, Location: slo }],
					assertionConsumerService: [{ Binding: binding, Location: acs }],
				})
				.getMetadata();
			expect(metadata).toContain("SingleLogoutService");
			await storeSamlConfiguration({
				...configuration(),
				authnRequestsSigned: true,
				spMetadata: { metadata, privateKey: fixtureKeys.privateKey },
			});
			try {
				const candidate = managementEngine();
				const dispatches = [native.handler, candidate.dispatch];
				const logout = `${origin}/api/auth/sso/saml2/logout/${providerId}`;
				for (const [index, dispatch] of dispatches.entries()) {
					const other = dispatches[1 - index]!;
					const published = await dispatch(
						new Request(
							`${origin}/api/auth/sso/saml2/sp/metadata?providerId=${providerId}`,
						),
					);
					expect(published.status).toBe(200);
					expect(published.headers.get("content-type")).toBe("application/xml");
					expect(await published.text()).toBe(metadata);
					const state = await pending(await dispatch(startRequest()));
					expect(state.redirect.searchParams.has("Signature")).toBe(true);
					const signedIn = await other(
						callback(signedResponse(state.requestId).encoded, state.relay),
					);
					await assertSession(signedIn);
					const headers = {
						cookie: cookies(signedIn),
						origin,
						"content-type": "application/json",
					};
					for (const request of [
						new Request(slo),
						new Request(slo, {
							method: "POST",
							headers: { origin: idpOrigin },
							body: new URLSearchParams(),
						}),
						new Request(logout, { method: "POST", headers, body: "{}" }),
					]) {
						const disabled = await dispatch(request);
						expect(disabled.status, await disabled.clone().text()).toBe(400);
						expect(await disabled.json()).toEqual({
							code: "SINGLE_LOGOUT_NOT_ENABLED",
							message: "Single Logout is not enabled",
						});
						expect(disabled.headers.getSetCookie()).toEqual([]);
					}
					const anonymous = await dispatch(
						new Request(logout, {
							method: "POST",
							headers: { origin, "content-type": "application/json" },
							body: "{}",
						}),
					);
					expect(anonymous.status).toBe(401);
					expect(await anonymous.json()).toEqual({
						code: "UNAUTHORIZED",
						message: "Unauthorized",
					});
					expect(
						await native.api.getSession({
							headers: new Headers(headers),
							query: { disableRefresh: true },
						}),
					).toMatchObject({ user: { id: managed } });
				}
				expect(
					(
						await database.query(
							`SELECT id FROM "${schema}"."verification"
					 WHERE identifier LIKE 'saml-session:%' OR identifier LIKE 'saml-session-by-id:%'`,
						)
					).rows,
				).toEqual([]);
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("applies native SAML profile and stored-session rules with durable signup velocity", async () => {
			if (!nativeDatabase)
				throw new Error("Expected the scoped fixture database.");
			const signupProvider = "policy-saml-fixture";
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,"providerId",issuer,"samlConfig","userId",domain,"domainVerified")
				 VALUES ($1,$2,$3,$4,$5,'corp.example',TRUE)`,
				[
					randomUUID(),
					signupProvider,
					sp,
					JSON.stringify(configuration()),
					decoy,
				],
			);
			const legacy = await nativeSso(nativeDatabase, true);
			const owned = createOwnedProjectEngine({
				database,
				project: { slug, schemaName: schema },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: (request) => request.headers.get("x-real-ip"),
				sso: { defaultErrorURL, saml: true },
			});
			await checkSsoPolicyFixture({
				database,
				schema,
				secret,
				origin,
				destination,
				defaultErrorURL,
				managedProvider: providerId,
				managedSubject: subject,
				signupProvider,
				async signIn(writer, input) {
					const dispatch =
						writer === "native" ? legacy.handler : owned.dispatch;
					const start = {
						...body,
						providerId: input.providerId,
						errorCallbackURL: input.errorURL,
					};
					const request = startRequest(start);
					request.headers.set("x-real-ip", input.ip);
					const receiver = `${origin}/api/auth/sso/saml2/sp/acs/${input.providerId}`;
					const state = await pending(await dispatch(request), receiver);
					const signed = signedResponse(state.requestId, {
						...input,
						receiver,
					});
					const received = callback(signed.encoded, state.relay, receiver);
					received.headers.set("x-real-ip", input.ip);
					return dispatch(received);
				},
			});
		});

		it("preserves saved IdP callback precedence while both writers refuse IdP-initiated login", async () => {
			const fallback = `${origin}/account?from=saved-saml-fallback`;
			try {
				const candidate = managementEngine();
				const writers = [native.handler, candidate.dispatch];
				for (const [override, callbackUrl, expected] of [
					[fallback, "/account?from=secondary", fallback],
					[
						"/account?from=saved-relative",
						undefined,
						"/account?from=saved-relative",
					],
					[
						"https://untrusted.fixture.example/account",
						"/account?from=secondary",
						"/account?from=secondary",
					],
					[acs, "/account?from=secondary", "/account?from=secondary"],
				] as const) {
					await storeSamlConfiguration({
						...configuration(),
						idpInitiatedCallbackUrl: override,
						callbackUrl,
					});
					for (const [index, writer] of writers.entries()) {
						const other = writers[1 - index]!;
						for (const [returnTo, expectedLocation] of [
							[destination, destination],
							[
								"/account?from=explicit-relative",
								"/account?from=explicit-relative",
							],
							["/%2freturn", expected],
							[acs, expected],
						]) {
							const state = await pending(
								await writer(startRequest({ ...body, callbackURL: returnTo })),
							);
							await assertSession(
								await other(
									callback(
										signedResponse(state.requestId).encoded,
										state.relay,
									),
								),
								expectedLocation,
							);
						}
						const { encoded, assertionId } = signedResponse(undefined);
						const sessions = async () =>
							(
								await database.query(
									`SELECT id FROM "${schema}"."session" WHERE "userId"=$1 ORDER BY id`,
									[managed],
								)
							).rows;
						const before = await sessions();
						const unsolicited = await writer(callback(encoded));
						expect(unsolicited.status).toBe(302);
						expect(cookies(unsolicited)).toBe("");
						const target = new URL(expected, origin);
						target.searchParams.set("error", "unsolicited_response");
						target.searchParams.set(
							"error_description",
							"IdP-initiated SSO not allowed",
						);
						expect(unsolicited.headers.get("location")).toBe(
							expected.startsWith("/")
								? target.pathname + target.search.replaceAll("+", "%20")
								: target.href,
						);
						expect(await sessions()).toEqual(before);
						expect(
							(
								await database.query(
									`SELECT id FROM "${schema}"."verification" WHERE identifier=$1`,
									[`saml-used-assertion:${assertionId}`],
								)
							).rows,
						).toEqual([]);
					}
				}
			} finally {
				await storeSamlConfiguration(configuration());
			}
		});

		it("checks a pinned signed envelope and preserves the configured assertion-signature policy", async () => {
			const strict = await startOwned();
			const responseOnly = signedResponse(strict.requestId, {
				signature: "response",
			});
			expect(
				(
					await owned().samlCallback(
						callback(responseOnly.encoded, strict.relay),
						providerId,
					)
				).status,
			).toBe(400);
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "samlConfig" = $1 WHERE "providerId" = $2`,
				[
					JSON.stringify({ ...configuration(), wantAssertionsSigned: false }),
					providerId,
				],
			);
			try {
				const state = await startOwned();
				await assertSession(
					await owned().samlCallback(
						callback(
							signedResponse(state.requestId, { signature: "response" })
								.encoded,
							state.relay,
						),
						providerId,
					),
				);
				const both = await startOwned();
				await assertSession(
					await owned().samlCallback(
						callback(
							signedResponse(both.requestId, { signature: "both" }).encoded,
							both.relay,
						),
						providerId,
					),
				);
			} finally {
				await database.query(
					`UPDATE "${schema}"."ssoProvider" SET "samlConfig" = $1 WHERE "providerId" = $2`,
					[JSON.stringify(configuration()), providerId],
				);
			}
		});

		it("consumes the matching RelayState and AuthnRequest once across concurrent callbacks", async () => {
			const state = await startOwned();
			const other = await startOwned();
			const signed = signedResponse(state.requestId);
			const mismatched = await owned().samlCallback(
				callback(signed.encoded, other.relay),
				providerId,
			);
			expect(
				new URL(mismatched.headers.get("location")!).searchParams.get("error"),
			).toBe("invalid_state");
			const results = await Promise.all(
				[1, 2].map(() =>
					owned().samlCallback(
						callback(signed.encoded, state.relay),
						providerId,
					),
				),
			);
			expect(
				results.filter(
					(result) => result.headers.get("location") === destination,
				),
			).toHaveLength(1);
			const replay = signedResponse(other.requestId, {
				assertionId: signed.assertionId,
			});
			const rejected = await owned().samlCallback(
				callback(replay.encoded, other.relay),
				providerId,
			);
			expect(
				new URL(rejected.headers.get("location")!).searchParams.get("error"),
			).toBe("replay_detected");
			expect(cookies(rejected)).toBe("");
		});

		it("rejects absent signatures, stale conditions and mismatched recipient, issuer, or audience", async () => {
			const state = await startOwned();
			const invalid = [
				{ signature: "none" },
				{ expired: true },
				{ recipient: `${origin}/wrong-acs` },
				{ issuer: "https://different.fixture.example/metadata" },
				{ audience: "https://different.fixture.example/entity" },
			] as const;
			for (const value of invalid) {
				const result = await owned().samlCallback(
					callback(signedResponse(state.requestId, value).encoded, state.relay),
					providerId,
				);
				expect(result.status).toBe(400);
				expect(cookies(result)).toBe("");
			}
			await assertSession(
				await owned().samlCallback(
					callback(signedResponse(state.requestId).encoded, state.relay),
					providerId,
				),
			);
		});

		it("completes signed JSON ACS requests across both project writers", async () => {
			const engine = managementEngine();
			const jsonCallback = (payload: unknown) =>
				new Request(acs, {
					method: "POST",
					headers: {
						origin: idpOrigin,
						"content-type": "application/json; charset=utf-8",
						"sec-fetch-site": "cross-site",
						"sec-fetch-mode": "navigate",
					},
					body: JSON.stringify(payload),
				});

			const ownedState = await pending(await engine.dispatch(startRequest()));
			await assertSession(
				await native.handler(
					jsonCallback({
						SAMLResponse: signedResponse(ownedState.requestId).encoded,
						RelayState: ownedState.relay,
					}),
				),
			);
			const nativeState = await pending(await native.handler(startRequest()));
			const assertion = {
				SAMLResponse: signedResponse(nativeState.requestId).encoded,
				RelayState: nativeState.relay,
			};
			for (const invalid of [
				{ ...assertion, RelayState: [nativeState.relay] },
				{ ...assertion, padding: " ".repeat(3 * 256 * 1024 + 4096) },
			]) {
				const denied = await engine.dispatch(jsonCallback(invalid));
				expect(denied.status).toBe(400);
				expect(await denied.json()).toMatchObject({
					code: "INVALID_SAML_RESPONSE",
				});
				expect(cookies(denied)).toBe("");
			}
			await assertSession(await engine.dispatch(jsonCallback(assertion)));
		});

		it("dispatches SAML sign-in and ACS through the realm security and native-readable session hooks", async () => {
			const ip = "203.0.113.83";
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => ip,
				sso: { defaultErrorURL: `${origin}/auth-error`, saml: true },
			});
			const state = await pending(await engine.dispatch(startRequest()));
			const signed = signedResponse(state.requestId);
			const rule = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."allauthSecurityRule"(id,type,value,reason) VALUES ($1,'ip',$2,'fixture')`,
				[rule, ip],
			);
			try {
				const blocked = await engine.dispatch(
					callback(signed.encoded, state.relay),
				);
				expect(blocked.status).toBe(429);
				expect(await blocked.json()).toMatchObject({
					code: "ALLAUTH_SECURITY_BLOCKED",
				});
				expect(cookies(blocked)).toBe("");
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthSecurityRule" WHERE id=$1`,
					[rule],
				);
			}
			await assertSession(
				await engine.dispatch(callback(signed.encoded, state.relay)),
			);
			const audit = await database.query(
				`SELECT type,outcome FROM "${schema}"."allauthEvent" WHERE "userId"=$1 AND metadata->>'path'=$2 ORDER BY type`,
				[managed, "/sso/saml2/sp/acs/:providerId"],
			);
			expect(audit.rows).toContainEqual({
				type: "session.created",
				outcome: "success",
			});
		});

		it("serves native SP metadata for the configured transport before domain verification", async () => {
			const metadataPath = "/sso/saml2/sp/metadata";
			const provider = "metadata-pending";
			const id = randomUUID();
			const configured = configuration();
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider" (id,"providerId",issuer,"samlConfig","userId",domain,"domainVerified")
				VALUES ($1,$2,$3,$4,$5,'corp.example',FALSE)`,
				[id, provider, sp, JSON.stringify(configured), decoy],
			);
			const engine = (baseURL: string, basePath: string, saml = true) =>
				createOwnedProjectEngine({
					database,
					project: { schemaName: schema, slug },
					baseURL,
					basePath,
					trustedOrigins: [],
					signingSecret: secret,
					policy: defaultAuthPolicy,
					trustedIP: () => "192.0.2.31",
					sso: { defaultErrorURL: `${baseURL}/auth-error`, saml },
				});
			const path = `${metadataPath}?providerId=${provider}`;
			const hostedRequest = () => new Request(`${origin}/api/auth${path}`);
			const hosted = engine(origin, "/api/auth");
			const directOrigin = "https://api.saml-fixture.example";
			const directBasePath = `/api/projects/${slug}/auth`;
			const direct = engine(directOrigin, directBasePath);
			const directRequest = () =>
				new Request(`${directOrigin}${directBasePath}${path}`);
			const nativeMetadata = await native.handler(hostedRequest());
			const hostedMetadata = await hosted.dispatch(hostedRequest());
			expect(nativeMetadata.status).toBe(200);
			expect(hostedMetadata.status, await hostedMetadata.clone().text()).toBe(
				200,
			);
			expect(hostedMetadata.headers.get("content-type")).toBe(
				"application/xml",
			);
			expect(await hostedMetadata.text()).toBe(await nativeMetadata.text());
			const directMetadata = await direct.dispatch(directRequest());
			expect(directMetadata.status, await directMetadata.clone().text()).toBe(
				200,
			);
			const directXML = await directMetadata.text();
			expect(directXML).toContain(
				`Location="${directOrigin}${directBasePath}/sso/saml2/sp/acs/${provider}"`,
			);
			expect(directXML).toContain(`entityID="${sp}"`);
			expect(directXML).toContain('WantAssertionsSigned="true"');
			expect(
				(
					await hosted.dispatch(
						new Request(`${origin}/api/auth${metadataPath}?providerId=missing`),
					)
				).status,
			).toBe(404);
			expect(
				(await engine(origin, "/api/auth", false).dispatch(hostedRequest()))
					.status,
			).not.toBe(200);

			const differentTransport = saml
				.SPMetadata({
					entityID: sp,
					assertionConsumerService: [
						{
							Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: `${origin}/api/auth/sso/saml2/sp/acs/${provider}`,
						},
					],
					wantAssertionsSigned: true,
				})
				.getMetadata();
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "samlConfig"=$1 WHERE id=$2`,
				[
					JSON.stringify({
						...configured,
						spMetadata: { metadata: differentTransport },
					}),
					id,
				],
			);
			expect((await hosted.dispatch(hostedRequest())).status).toBe(200);
			expect((await direct.dispatch(directRequest())).status).toBe(400);
			await database.query(
				`UPDATE "${schema}"."ssoProvider" SET "samlConfig"=$1 WHERE id=$2`,
				[
					JSON.stringify({
						...configured,
						spMetadata: { isAssertionEncrypted: true },
					}),
					id,
				],
			);
			expect((await hosted.dispatch(hostedRequest())).status).toBe(400);
		});

		it("qualifies only transport-bound plaintext SAML with validated signing material", () => {
			const samlConfig = configuration();
			expect(() =>
				checkProjectSamlConfiguration({ issuer: sp, samlConfig }, acs),
			).not.toThrow();
			expect(() =>
				checkProjectSamlConfiguration(
					{
						issuer: sp,
						samlConfig: { ...samlConfig, idpInitiatedCallbackUrl: "/account" },
					},
					acs,
				),
			).not.toThrow();
			expect(() =>
				checkProjectSamlConfiguration(
					{
						issuer: sp,
						samlConfig: {
							...samlConfig,
							authnRequestsSigned: true,
							privateKey: fixtureKeys.privateKey,
						},
					},
					acs,
				),
			).not.toThrow();
			for (const change of [
				{ issuer },
				{ cert: "bad-fixture-certificate" },
				{ authnRequestsSigned: true, privateKey: "invalid fixture key" },
				{ spMetadata: { isAssertionEncrypted: true } },
			]) {
				expect(() =>
					checkProjectSamlConfiguration(
						{ issuer: sp, samlConfig: { ...samlConfig, ...change } },
						acs,
					),
				).toThrow(
					"This configured SAML provider is outside the candidate transport.",
				);
			}
			const customMetadata = saml
				.SPMetadata({
					entityID: sp,
					assertionConsumerService: [
						{
							Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
							Location: acs,
						},
					],
					wantAssertionsSigned: true,
				})
				.getMetadata();
			const saved = {
				issuer: sp,
				samlConfig: { ...samlConfig, spMetadata: { metadata: customMetadata } },
			};
			expect(() => checkProjectSamlConfiguration(saved, acs)).not.toThrow();
			expect(() =>
				checkProjectSamlConfiguration(
					saved,
					acs.replace("/api/auth", `/api/projects/${slug}/auth`),
				),
			).toThrow();
		});

		it("registers native-readable signed SAML with the existing DNS proof and credential response", async () => {
			const { cookie } = await samlAdministrator();
			const ownedEngine = managementEngine();
			const { issuer: _spEntity, ...samlConfig } = configuration();
			const input = {
				providerId: "allauth-registered-saml",
				issuer: sp,
				domain: "corp.example",
				samlConfig: {
					...samlConfig,
					authnRequestsSigned: true,
					privateKey: fixtureKeys.privateKey,
					idpInitiatedCallbackUrl: "/account?from=registration",
					signatureAlgorithm: "sha256",
					digestAlgorithm: "sha256",
					mapping: { email: "corpEmail", name: "displayName" },
				},
			};
			const disabled = await managementEngine(false).dispatch(
				managementRequest("register", cookie, input),
			);
			expect(disabled.status).toBe(400);
			const registered = await ownedEngine.dispatch(
				managementRequest("register", cookie, input),
			);
			expect(registered.status, await registered.clone().text()).toBe(200);
			expect(registered.headers.get("cache-control")).toBe("no-store");
			const result = (await registered.json()) as {
				domainVerificationToken: string;
			};
			expect(result).toMatchObject({
				providerId: input.providerId,
				issuer: sp,
				domain: input.domain,
				domainVerified: false,
				oidcConfig: null,
				samlConfig: { ...input.samlConfig, issuer: sp },
				redirectURI: `${origin}/api/auth/sso/callback/${input.providerId}`,
			});
			const proof = await native.handler(
				managementRequest("request-domain-verification", cookie, {
					providerId: input.providerId,
				}),
			);
			expect(proof.status).toBe(201);
			expect(await proof.json()).toEqual({
				domainVerificationToken: result.domainVerificationToken,
			});
			const nativeView = await native.handler(
				managementRequest(
					`get-provider?providerId=${input.providerId}`,
					cookie,
				),
			);
			expect(nativeView.status, await nativeView.clone().text()).toBe(200);
			expect(await nativeView.clone().json()).toEqual(
				await (
					await ownedEngine.dispatch(
						managementRequest(
							`get-provider?providerId=${input.providerId}`,
							cookie,
						),
					)
				).json(),
			);
			expect(await nativeView.text()).not.toContain("BEGIN PRIVATE KEY");
			const cross = await ownedEngine.dispatch(
				managementRequest(
					"register",
					cookie,
					{ ...input, providerId: "saml-cross-origin" },
					"https://saml-application.fixture.example",
				),
			);
			expect(cross.status, await cross.clone().text()).toBe(200);
			expect(await cross.text()).not.toContain("BEGIN PRIVATE KEY");

			const nativeId = "native-registered-saml";
			const idpMetadata = saml
				.IdPMetadata({
					entityID: issuer,
					signingCert: fixtureKeys.certificate,
					singleSignOnService: [
						{
							Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
							Location: `${idpOrigin}/redirect`,
						},
					],
				})
				.getMetadata();
			const nativeRegistration = await native.handler(
				managementRequest("register", cookie, {
					...input,
					providerId: nativeId,
					samlConfig: {
						...input.samlConfig,
						cert: undefined,
						idpMetadata: { metadata: idpMetadata },
					},
				}),
			);
			expect(
				nativeRegistration.status,
				await nativeRegistration.clone().text(),
			).toBe(200);
			const nativeUpdate = await native.handler(
				managementRequest("update-provider", cookie, {
					providerId: input.providerId,
					samlConfig: {
						identifierFormat:
							"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
						idpInitiatedCallbackUrl: `${origin}/account?from=native-update`,
					},
				}),
			);
			expect(nativeUpdate.status, await nativeUpdate.clone().text()).toBe(200);
			expect(await nativeUpdate.json()).toEqual(
				await (
					await ownedEngine.dispatch(
						managementRequest(
							`get-provider?providerId=${input.providerId}`,
							cookie,
						),
					)
				).json(),
			);
			const ownedUpdate = await ownedEngine.dispatch(
				managementRequest("update-provider", cookie, {
					providerId: nativeId,
					domain: "corp.new.example",
					samlConfig: {
						mapping: { email: "corpEmail", name: "fullName" },
						idpInitiatedCallbackUrl: "/account?from=owned-update",
					},
				}),
			);
			expect(ownedUpdate.status, await ownedUpdate.clone().text()).toBe(200);
			expect(await ownedUpdate.clone().json()).toEqual(
				await (
					await native.handler(
						managementRequest(`get-provider?providerId=${nativeId}`, cookie),
					)
				).json(),
			);
			expect(await ownedUpdate.text()).not.toContain("BEGIN PRIVATE KEY");
			const cleared = await ownedEngine.dispatch(
				managementRequest("update-provider", cookie, {
					providerId: nativeId,
					samlConfig: { idpInitiatedCallbackUrl: null },
				}),
			);
			expect(cleared.status).toBe(200);
			const legacyCleared = await native.handler(
				managementRequest(`get-provider?providerId=${nativeId}`, cookie),
			);
			const clearedProvider = (await legacyCleared.json()) as {
				samlConfig: unknown;
			};
			expect(clearedProvider.samlConfig).not.toHaveProperty(
				"idpInitiatedCallbackUrl",
			);
			const freshProof = await native.handler(
				managementRequest("request-domain-verification", cookie, {
					providerId: nativeId,
				}),
			);
			expect(await freshProof.json()).not.toEqual({
				domainVerificationToken: (
					(await nativeRegistration.json()) as {
						domainVerificationToken: string;
					}
				).domainVerificationToken,
			});
		});

		it("guards linked SAML identities, SCIM bindings, and the signed plaintext policy", async () => {
			const { id, cookie } = await samlAdministrator();
			const ownedEngine = managementEngine();
			const idToChange = "saml-managed-guard";
			const { issuer: _spEntity, ...samlConfig } = configuration();
			const input = {
				providerId: idToChange,
				issuer: sp,
				domain: "corp.example",
				samlConfig: {
					...samlConfig,
					mapping: { email: "corpEmail", name: "displayName" },
				},
			};
			expect(
				(
					await ownedEngine.dispatch(
						managementRequest("register", cookie, {
							...input,
							samlConfig: {
								...input.samlConfig,
								spMetadata: { isAssertionEncrypted: true },
							},
						}),
					)
				).status,
			).toBe(400);
			expect(
				(
					await ownedEngine.dispatch(
						managementRequest("register", cookie, {
							...input,
							samlConfig: { ...input.samlConfig, signatureAlgorithm: "sha1" },
						}),
					)
				).status,
			).toBe(400);
			const registered = await ownedEngine.dispatch(
				managementRequest("register", cookie, input),
			);
			expect(registered.status, await registered.clone().text()).toBe(200);
			await database.query(
				`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,$3,$4,now())`,
				[randomUUID(), subject, idToChange, id],
			);
			const authorityChange = {
				providerId: idToChange,
				samlConfig: {
					idpMetadata: {
						entityID: "https://different-idp.fixture.example/entity",
					},
				},
			};
			expect(
				(
					await native.handler(
						managementRequest("update-provider", cookie, authorityChange),
					)
				).status,
			).toBe(409);
			const linked = await ownedEngine.dispatch(
				managementRequest("update-provider", cookie, authorityChange),
			);
			expect(linked.status, await linked.clone().text()).toBe(409);
			expect(await linked.json()).toMatchObject({
				message:
					"Cannot change SSO provider identity fields while linked accounts exist",
			});
			await database.query(
				`INSERT INTO "${schema}"."allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$2,$3,$4,now())`,
				[randomUUID(), idToChange, organization, randomUUID()],
			);
			const bound = await ownedEngine.dispatch(
				managementRequest("update-provider", cookie, authorityChange),
			);
			expect(bound.status, await bound.clone().text()).toBe(409);
			expect(await bound.json()).toMatchObject({
				code: "SSO_PROVIDER_MUTATION_REJECTED",
			});
			const benign = await ownedEngine.dispatch(
				managementRequest("update-provider", cookie, {
					providerId: idToChange,
					samlConfig: { mapping: { email: "corpEmail", name: "fullName" } },
				}),
			);
			expect(benign.status, await benign.clone().text()).toBe(200);
		});

		it("requires an active directory identity and consumes a valid denied assertion without email fallback", async () => {
			const state = await startOwned();
			const signed = signedResponse(state.requestId);
			await database.query(
				`UPDATE "${schema}"."scimUser" SET active = FALSE WHERE id = $1`,
				[source],
			);
			try {
				const response = await owned().samlCallback(
					callback(signed.encoded, state.relay),
					providerId,
				);
				expect(
					new URL(response.headers.get("location")!).searchParams.get("error"),
				).toBe("directory_identity_inactive");
				expect(cookies(response)).toBe("");
			} finally {
				await database.query(
					`UPDATE "${schema}"."scimUser" SET active = TRUE WHERE id = $1`,
					[source],
				);
			}
			const retry = await owned().samlCallback(
				callback(signed.encoded, state.relay),
				providerId,
			);
			expect(
				new URL(retry.headers.get("location")!).searchParams.get("error"),
			).toBe("invalid_saml_response");
		});
	},
);
