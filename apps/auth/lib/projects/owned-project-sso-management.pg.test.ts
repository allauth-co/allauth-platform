import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { sso } from "@better-auth/sso";
import { organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { SsoProvider } from "./owned-project-sso-store";
import { ssoProviderReference } from "./owned-project-sso-store";

const { resolveTxt } = vi.hoisted(() => ({
	resolveTxt: vi.fn<(name: string) => Promise<string[][]>>(),
}));
vi.mock("node:dns/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:dns/promises")>();
	function FixtureResolver() {
		return { resolveTxt };
	}
	return { ...actual, resolveTxt, Resolver: FixtureResolver };
});

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://management.sso-fixture.example";
const slug = "sso-management-fixture";
const prefix = `allauth_project_${slug}`;
const secret = "isolated-project-sso-management-fixture-signing-secret";
const issuer = "https://idp.sso-fixture.example";
const oidcConfig = {
	issuer,
	discoveryEndpoint: `${issuer}/.well-known/openid-configuration`,
	clientId: "private-client-ABC9",
	clientSecret: "synthetic-private-client-secret",
	pkce: true,
	authorizationEndpoint: `${issuer}/authorize`,
	tokenEndpoint: `${issuer}/token`,
	userInfoEndpoint: `${issuer}/userinfo`,
	jwksEndpoint: `${issuer}/jwks`,
	scopes: ["openid", "profile"],
	tokenEndpointAuthentication: "client_secret_basic",
	mapping: { email: "synthetic-private-email-claim" },
};
const samlConfig = {
	entryPoint: `${issuer}/saml`,
	callbackUrl: `${origin}/api/auth/sso/saml2/callback/org-saml`,
	audience: origin,
	wantAssertionsSigned: true,
	authnRequestsSigned: false,
	idpMetadata: {
		cert: ["fixture-bad-certificate"],
		metadata: "synthetic-private-metadata",
	},
	spMetadata: { privateKey: "synthetic-private-signing-key" },
};
type Actor = { id: string; cookie: string };
type LegacyDatabase = Kysely<Record<string, Record<string, unknown>>>;

function request(
	path: string,
	actor?: Actor,
	body?: object,
	requestOrigin = origin,
) {
	return new Request(`${origin}/api/auth/sso/${path}`, {
		method: body ? "POST" : "GET",
		headers: {
			origin: requestOrigin,
			...(actor ? { cookie: actor.cookie } : {}),
			...(body ? { "content-type": "application/json" } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
}

describe.skipIf(!existsSync(fixture))(
	"project SSO provider management against PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const sibling = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const organizationId = randomUUID();
		const siblingSecret = `${secret}-sibling`;
		let administrator: Pool | undefined;
		let legacyDatabase: LegacyDatabase | undefined;
		let database: Pool;
		let created = false;
		let native: (request: Request) => Promise<Response>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let other: ReturnType<typeof createOwnedProjectEngine>;
		let owner: Actor;
		let orgAdmin: Actor;
		let orgMember: Actor;
		let realmAdmin: Actor;
		let siblingOwner: Actor;

		async function actor(
			realm = schema,
			signingSecret = secret,
			role = "user",
		): Promise<Actor> {
			const id = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${realm}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'SSO Fixture',$2,true,$3)`,
				[id, `${id}@fixture.example`, role],
			);
			await database.query(
				`INSERT INTO "${realm}"."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
				[randomUUID(), token, id],
			);
			const signature = createHmac("sha256", signingSecret)
				.update(token)
				.digest("base64");
			return {
				id,
				cookie: `__Secure-${prefix}.session_token=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function provider(
			providerId: string,
			creator: Actor,
			input: {
				realm?: string;
				org?: string;
				saml?: boolean;
				domain?: string;
				verified?: boolean;
			} = {},
		) {
			await database.query(
				`INSERT INTO "${input.realm ?? schema}"."ssoProvider" (id,"providerId",issuer,domain,"userId","organizationId","oidcConfig","samlConfig","domainVerified")
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				[
					randomUUID(),
					providerId,
					issuer,
					input.domain ?? "corp.example",
					creator.id,
					input.org ?? null,
					input.saml ? null : JSON.stringify(oidcConfig),
					input.saml ? JSON.stringify(samlConfig) : null,
					input.verified ?? null,
				],
			);
		}

		function engine(schemaName = schema, signingSecret = secret) {
			return createOwnedProjectEngine({
				database,
				project: { schemaName, slug },
				baseURL: origin,
				basePath: "/api/auth",
				trustedOrigins: [],
				trustedIP: () => "192.0.2.38",
				signingSecret,
				policy: defaultAuthPolicy,
				sso: { defaultErrorURL: `${origin}/auth-error` },
			});
		}

		beforeAll(async () => {
			const local = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(local.DATABASE_URL);
			if (
				local.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"SSO management requires an isolated local PostgreSQL fixture.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 6 });
			const client = await database.connect();
			try {
				for (const realm of [schema, sibling]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth",
						"002-control-plane",
						"005-free-plugins",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${migration}.sql`, import.meta.url),
								"utf8",
							),
						);
				}
				await client.query("RESET search_path");
			} finally {
				client.release();
			}
			legacyDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.href,
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const { auth } = await getTestInstance(
				{
					baseURL: origin,
					secret,
					database: { db: legacyDatabase, type: "postgres", transaction: true },
					advanced: { cookiePrefix: prefix },
					logger: { disabled: true },
					plugins: [
						organization(),
						sso({ domainVerification: { enabled: true } }),
					],
				},
				{ disableTestUser: true },
			);
			native = auth.handler;
			owned = engine();
			other = engine(sibling, siblingSecret);
			owner = await actor();
			orgAdmin = await actor();
			orgMember = await actor();
			realmAdmin = await actor(schema, secret, "admin");
			siblingOwner = await actor(sibling, siblingSecret);
			await database.query(
				`INSERT INTO "${schema}"."organization" (id,name,slug,"createdAt") VALUES ($1,'SSO Fixture',$1,now())`,
				[organizationId],
			);
			for (const [member, role] of [
				[owner, "owner"],
				[orgAdmin, "member, admin"],
				[orgMember, "member"],
			] as const) {
				await database.query(
					`INSERT INTO "${schema}"."member" (id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,$4,now())`,
					[randomUUID(), organizationId, member.id, role],
				);
			}
			await provider("personal-oidc", owner, { verified: true });
			await provider("org-saml", orgMember, {
				org: organizationId,
				saml: true,
			});
			await provider("personal-oidc", siblingOwner, {
				realm: sibling,
				domain: "sibling.example",
			});
		});

		afterAll(async () => {
			await Promise.all([database?.end(), legacyDatabase?.destroy()]);
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		it("reads the native catalog and detail shape without disclosing stored credentials or metadata", async () => {
			const redacted = await owned.dispatch(request("providers", owner));
			const expected = await native(request("providers", owner));
			expect(redacted.status).toBe(200);
			expect(expected.status).toBe(200);
			expect(await redacted.clone().json()).toEqual(await expected.json());
			const raw = await redacted.text();
			for (const privateValue of [
				oidcConfig.clientId,
				oidcConfig.clientSecret,
				oidcConfig.mapping.email,
				samlConfig.idpMetadata.metadata,
				samlConfig.spMetadata.privateKey,
				samlConfig.idpMetadata.cert[0],
				orgMember.id,
			])
				expect(raw).not.toContain(privateValue);
			const detail = "get-provider?providerId=org-saml";
			const expectedDetail = await native(request(detail, orgAdmin));
			const actualDetail = await owned.dispatch(request(detail, orgAdmin));
			expect(actualDetail.status).toBe(200);
			expect(expectedDetail.status).toBe(200);
			expect(await actualDetail.clone().json()).toEqual(
				await expectedDetail.json(),
			);
			expect(await actualDetail.json()).toMatchObject({
				samlConfig: { certificate: [{ error: "Failed to parse certificate" }] },
			});
		});

		it("checks live organization membership and the realm of a signed project session", async () => {
			const detail = "get-provider?providerId=org-saml";
			for (const handler of [native, (req: Request) => owned.dispatch(req)]) {
				expect((await handler(request(detail, orgMember))).status).toBe(403);
				expect((await handler(request(detail, realmAdmin))).status).toBe(403);
				expect((await handler(request(detail))).status).toBe(401);
				expect(
					(await handler(request("get-provider?providerId=absent", owner)))
						.status,
				).toBe(404);
				expect(
					await (await handler(request("providers", orgMember))).json(),
				).toEqual({ providers: [] });
				expect(
					(
						await handler(
							request("get-provider?providerId=personal-oidc", orgAdmin),
						)
					).status,
				).toBe(403);
			}
			expect((await other.dispatch(request("providers", owner))).status).toBe(
				401,
			);
			expect(
				(await owned.dispatch(request("providers", siblingOwner))).status,
			).toBe(401);
			expect(
				await (
					await other.dispatch(
						request("get-provider?providerId=personal-oidc", siblingOwner),
					)
				).json(),
			).toMatchObject({
				providerId: "personal-oidc",
				domain: "sibling.example",
			});
		});

		it("deletes an authorized provider atomically and preserves bound directories and other accounts", async () => {
			await provider("owned-delete", orgMember, { org: organizationId });
			await provider("native-delete", owner);
			await provider("scim-bound", orgMember, {
				org: organizationId,
				verified: true,
			});
			const byProvider = (providerId: string) =>
				database.query(
					`SELECT id FROM "${schema}"."account" WHERE "providerId"=$1`,
					[providerId],
				);
			for (const providerId of [
				"owned-delete",
				"native-delete",
				"scim-bound",
				"credential",
			]) {
				await database.query(
					`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,$3,$2,now())`,
					[randomUUID(), orgMember.id, providerId],
				);
			}
			await database.query(
				`INSERT INTO "${schema}"."allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,'scim-bound',$2,$3,now())`,
				[randomUUID(), organizationId, randomUUID()],
			);
			await database.query(
				`INSERT INTO "${schema}"."verification" (id,identifier,value,"expiresAt") VALUES ($1,'_better-auth-token-owned-delete','stale-fixture-proof',now()+interval '1 day')`,
				[randomUUID()],
			);
			expect(
				(
					await owned.dispatch(
						request(
							"delete-provider",
							orgAdmin,
							{ providerId: "owned-delete" },
							"https://untrusted.fixture.example",
						),
					)
				).status,
			).toBe(403);
			expect(
				(
					await owned.dispatch(
						request("delete-provider", orgMember, {
							providerId: "owned-delete",
						}),
					)
				).status,
			).toBe(403);
			const bound = await owned.dispatch(
				request("delete-provider", orgAdmin, { providerId: "scim-bound" }),
			);
			expect(bound.status, await bound.clone().text()).toBe(409);
			expect(await bound.json()).toMatchObject({
				code: "SSO_PROVIDER_MUTATION_REJECTED",
			});
			expect((await byProvider("scim-bound")).rowCount).toBe(1);
			const deleted = await owned.dispatch(
				request("delete-provider", orgAdmin, { providerId: "owned-delete" }),
			);
			expect(deleted.status, await deleted.clone().text()).toBe(200);
			expect(await deleted.json()).toEqual({ success: true });
			expect(
				(
					await native(
						request("get-provider?providerId=owned-delete", orgAdmin),
					)
				).status,
			).toBe(404);
			expect((await byProvider("owned-delete")).rowCount).toBe(0);
			expect((await byProvider("credential")).rowCount).toBe(1);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "${schema}"."verification" WHERE identifier='_better-auth-token-owned-delete'`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT "actorId","targetId" FROM "${schema}"."allauthAudit" WHERE action='/sso/delete-provider'`,
					)
				).rows,
			).toEqual([{ actorId: orgAdmin.id, targetId: "owned-delete" }]);
			const nativeDelete = await native(
				request("delete-provider", owner, { providerId: "native-delete" }),
			);
			expect(nativeDelete.status, await nativeDelete.clone().text()).toBe(200);
			expect(await nativeDelete.json()).toEqual({ success: true });
			expect(
				(
					await owned.dispatch(
						request("get-provider?providerId=native-delete", owner),
					)
				).status,
			).toBe(404);
			expect((await byProvider("native-delete")).rowCount).toBe(0);
		});

		it("uses native DNS challenge rows and verifies every configured domain before activation", async () => {
			await provider("native-proof", orgMember, {
				org: organizationId,
				domain: "one.corp.example,two.corp.example",
			});
			const body = { providerId: "native-proof" };
			const identifier = "_better-auth-token-native-proof";
			expect(
				(await owned.dispatch(request("verify-domain", orgAdmin, body))).status,
			).toBe(404);
			expect(
				(
					await owned.dispatch(
						request("request-domain-verification", orgMember, body),
					)
				).status,
			).toBe(403);
			const issued = await native(
				request("request-domain-verification", orgAdmin, body),
			);
			expect(issued.status, await issued.clone().text()).toBe(201);
			const { domainVerificationToken: token } = (await issued.json()) as {
				domainVerificationToken: string;
			};
			const reread = await owned.dispatch(
				request("request-domain-verification", orgAdmin, body),
			);
			expect(reread.status).toBe(201);
			expect(await reread.json()).toEqual({ domainVerificationToken: token });
			resolveTxt.mockImplementation(async (name) =>
				name === `${identifier}.one.corp.example.` ? [[token]] : [["no-match"]],
			);
			const mismatch = await owned.dispatch(
				request("verify-domain", orgAdmin, body),
			);
			expect(mismatch.status, await mismatch.clone().text()).toBe(502);
			expect(await mismatch.json()).toMatchObject({
				code: "DOMAIN_VERIFICATION_FAILED",
			});
			expect(
				await (
					await native(
						request("get-provider?providerId=native-proof", orgAdmin),
					)
				).json(),
			).toMatchObject({ domainVerified: false });
			resolveTxt.mockImplementation(async (name) =>
				name === `${identifier}.one.corp.example.`
					? [[token]]
					: [[`${identifier}=`, token]],
			);
			expect(
				(await owned.dispatch(request("verify-domain", orgAdmin, body))).status,
			).toBe(204);
			expect(
				await (
					await native(
						request("get-provider?providerId=native-proof", orgAdmin),
					)
				).json(),
			).toMatchObject({ domainVerified: true });
			expect(
				(await native(request("request-domain-verification", orgAdmin, body)))
					.status,
			).toBe(409);
			const audit = await database.query(
				`SELECT "actorId","targetId","organizationId" FROM "${schema}"."allauthAudit" WHERE action='/sso/verify-domain' AND "targetId"=$1`,
				[body.providerId],
			);
			expect(audit.rows).toEqual([
				{ actorId: orgAdmin.id, targetId: body.providerId, organizationId },
			]);
		});

		it("allows native rollback to finish an owned DNS challenge and rechecks scope after DNS", async () => {
			await provider("owned-proof", orgMember, { org: organizationId });
			const body = { providerId: "owned-proof" };
			const issued = await owned.dispatch(
				request("request-domain-verification", orgAdmin, body),
			);
			expect(issued.status, await issued.clone().text()).toBe(201);
			const { domainVerificationToken: token } = (await issued.json()) as {
				domainVerificationToken: string;
			};
			const nativeRead = await native(
				request("request-domain-verification", orgAdmin, body),
			);
			expect(nativeRead.status).toBe(201);
			expect(await nativeRead.json()).toEqual({
				domainVerificationToken: token,
			});

			resolveTxt.mockImplementationOnce(async () => {
				await database.query(
					`UPDATE "${schema}"."ssoProvider" SET domain='changed.corp.example' WHERE "providerId"=$1`,
					[body.providerId],
				);
				return [[token]];
			});
			const stale = await owned.dispatch(
				request("verify-domain", orgAdmin, body),
			);
			expect(stale.status, await stale.clone().text()).toBe(409);
			expect(await stale.json()).toMatchObject({
				code: "SSO_PROVIDER_CHANGED",
			});
			resolveTxt.mockImplementationOnce(async () => {
				await database.query(
					`UPDATE "${schema}"."member" SET role='member' WHERE "userId"=$1 AND "organizationId"=$2`,
					[orgAdmin.id, organizationId],
				);
				return [[token]];
			});
			try {
				expect(
					(await owned.dispatch(request("verify-domain", orgAdmin, body)))
						.status,
				).toBe(403);
			} finally {
				await database.query(
					`UPDATE "${schema}"."member" SET role='admin' WHERE "userId"=$1 AND "organizationId"=$2`,
					[orgAdmin.id, organizationId],
				);
			}
			expect(
				await (
					await native(request("get-provider?providerId=owned-proof", orgAdmin))
				).json(),
			).toMatchObject({ domainVerified: false });
			resolveTxt.mockImplementation(async (name) =>
				name === "_better-auth-token-owned-proof.changed.corp.example"
					? [[token]]
					: [],
			);
			const rollback = await native(request("verify-domain", orgAdmin, body));
			expect(rollback.status, await rollback.clone().text()).toBe(204);
			expect(
				await (
					await owned.dispatch(
						request("get-provider?providerId=owned-proof", orgAdmin),
					)
				).json(),
			).toMatchObject({ domainVerified: true });
		});

		it("updates native OIDC settings, preserves secret-only fingerprints and clears old domain proofs", async () => {
			const providerId = "editable-oidc";
			const detail = `get-provider?providerId=${providerId}`;
			await provider(providerId, orgMember, {
				org: organizationId,
				verified: true,
			});
			async function readProvider() {
				const { rows } = await database.query<SsoProvider>(
					`SELECT id,"providerId",issuer,domain,"domainVerified","organizationId","oidcConfig"::jsonb AS "oidcConfig" FROM "${schema}"."ssoProvider" WHERE "providerId"=$1`,
					[providerId],
				);
				return rows[0];
			}
			const original = ssoProviderReference(await readProvider());
			const nextSecret = "synthetic-rotated-provider-secret";
			const rotated = await owned.dispatch(
				request("update-provider", orgAdmin, {
					providerId,
					oidcConfig: { clientSecret: nextSecret },
				}),
			);
			expect(rotated.status, await rotated.clone().text()).toBe(200);
			expect(await rotated.clone().json()).toEqual(
				await (await native(request(detail, orgAdmin))).json(),
			);
			expect(await rotated.text()).not.toContain(nextSecret);
			const persisted = await readProvider();
			expect(persisted.oidcConfig?.clientSecret).toBe(nextSecret);
			expect(ssoProviderReference(persisted)).toEqual(original);

			const nativeUpdated = await native(
				request("update-provider", orgAdmin, {
					providerId,
					oidcConfig: { scopes: ["openid", "email"] },
				}),
			);
			expect(nativeUpdated.status, await nativeUpdated.clone().text()).toBe(
				200,
			);
			expect(await nativeUpdated.json()).toEqual(
				await (await owned.dispatch(request(detail, orgAdmin))).json(),
			);
			expect(ssoProviderReference(await readProvider())).not.toEqual(original);

			await database.query(
				`INSERT INTO "${schema}"."verification" (id,identifier,value,"expiresAt") VALUES ($1,$2,'stale-dns-proof',now()+interval '1 day')`,
				[randomUUID(), `_better-auth-token-${providerId}`],
			);
			const changedDomain = await owned.dispatch(
				request("update-provider", orgAdmin, {
					providerId,
					domain: "new.corp.example",
				}),
			);
			expect(changedDomain.status, await changedDomain.clone().text()).toBe(
				200,
			);
			expect(await changedDomain.json()).toMatchObject({
				domain: "new.corp.example",
				domainVerified: false,
			});
			const renewed = await native(
				request("request-domain-verification", orgAdmin, { providerId }),
			);
			expect(renewed.status).toBe(201);
			expect(await renewed.json()).not.toEqual({
				domainVerificationToken: "stale-dns-proof",
			});
		});

		it("protects linked provider identities, bound SCIM directories, and supported OIDC settings", async () => {
			const providerId = "linked-oidc";
			await provider(providerId, orgMember, {
				org: organizationId,
				verified: true,
			});
			await database.query(
				`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId","updatedAt") VALUES ($1,$2,$3,$2,now())`,
				[randomUUID(), orgMember.id, providerId],
			);
			const changeId = {
				providerId,
				oidcConfig: { clientId: "replacement-client" },
			};
			const blocked = await owned.dispatch(
				request("update-provider", orgAdmin, changeId),
			);
			expect(blocked.status, await blocked.clone().text()).toBe(409);
			expect(await blocked.json()).toMatchObject({
				message:
					"Cannot change SSO provider identity fields while linked accounts exist",
			});
			expect(
				(await native(request("update-provider", orgAdmin, changeId))).status,
			).toBe(409);
			const before = await (
				await owned.dispatch(
					request(`get-provider?providerId=${providerId}`, orgAdmin),
				)
			).json();
			await database.query(
				`INSERT INTO "${schema}"."allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$2,$3,$4,now())`,
				[randomUUID(), providerId, organizationId, randomUUID()],
			);
			const bound = await owned.dispatch(
				request("update-provider", orgAdmin, changeId),
			);
			expect(bound.status).toBe(409);
			expect(await bound.json()).toMatchObject({
				code: "SSO_PROVIDER_MUTATION_REJECTED",
			});
			for (const oidcConfig of [
				{ tokenEndpoint: "http://idp.sso-fixture.example/token" },
				{ tokenEndpointAuthentication: "private_key_jwt" },
			]) {
				const invalid = await owned.dispatch(
					request("update-provider", orgAdmin, { providerId, oidcConfig }),
				);
				expect(invalid.status, await invalid.clone().text()).toBe(400);
			}
			expect(
				(
					await owned.dispatch(
						request("update-provider", orgMember, {
							providerId,
							domain: "new.corp.example",
						}),
					)
				).status,
			).toBe(403);
			expect(
				await (
					await native(
						request(`get-provider?providerId=${providerId}`, orgAdmin),
					)
				).json(),
			).toEqual(before);
		});
	},
);
