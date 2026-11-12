import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { symmetricEncrypt } from "better-auth/crypto";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { securitySubject } from "../control/security-policy";
import { newWebhookSigningSecret } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks } from "../control/webhooks";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://callback-security.fixture.example";
const slug = "callback-security-fixture";
const basePath = "/api/auth";
const secret = "synthetic-realm-provider-callback-security-key";
const ip = "192.0.2.176";
const userAgent = "Synthetic provider callback fixture";
const rawUserAgent = "Synthetic provider\t callback fixture";
const submitted = "private-callback-value@fixture.example";
const assertion = "synthetic-unusable-assertion";
const issuer = "https://callback-idp.fixture.example";
const oidc = "fixture-enterprise-oidc";
const saml = "fixture-enterprise-saml";
const google = {
	clientId: "synthetic-google-id",
	clientSecret: "synthetic-google-secret",
};
const broker = {
	clientId: "synthetic-broker-id",
	clientSecret: "synthetic-broker-secret",
};
type Dispatch = (request: Request) => Promise<Response>;
type ScopedDB = Kysely<Record<string, Record<string, unknown>>>;

function native(database: ScopedDB) {
	const options = createAuthOptions(
		{ db: database, type: "postgres", transaction: true },
		{
			ALLAUTH_AUTH_URL: origin,
			ALLAUTH_AUTH_SECRET: secret,
			AUTH_RUNTIME: "node",
			SCIM_CREDENTIAL_HASH_SECRET:
				"synthetic-provider-callback-scim-fixture-key",
		},
		{
			name: "Synthetic callback fixture",
			slug,
			basePath,
			cookiePrefix: `allauth_project_${slug}`,
			primaryOrigin: origin,
			publicOrigin: origin,
			origins: [],
			google,
			broker,
			authorizeAdmin: async () => null,
			management: { id: "callback-security-fixture-management" },
		},
	);
	return betterAuth({
		...options,
		advanced: { ...options.advanced, disableOriginCheck: false },
		logger: { disabled: true },
	});
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated project provider callback security webhooks",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const sibling = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const scope = `"${schema}"`;
		let admin: Pool | undefined;
		let database: Pool;
		let nativeDatabase: ScopedDB;
		let created = false;

		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Provider callback tests require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: url.href, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 4 });
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.href,
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			const connection = await database.connect();
			try {
				for (const realm of [schema, sibling]) {
					await connection.query(`CREATE SCHEMA "${realm}"`);
					await connection.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth",
						"002-control-plane",
						"004-webhooks",
						"005-free-plugins",
						"006-analytics",
						"016-invitation-import-provenance",
					])
						await connection.query(
							readFileSync(
								new URL(`../../migrations/${migration}.sql`, import.meta.url),
								"utf8",
							),
						);
				}
				await connection.query("RESET search_path");
			} finally {
				connection.release();
			}
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		it("keeps signed callback failure payloads and counters on the receiving realm", async () => {
			const subscription = newWebhookSigningSecret();
			const recipient =
				"https://callback-security-webhook.fixture.example/events";
			for (const realm of [schema, sibling])
				await database.query(
					`INSERT INTO "${realm}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["security.*"]',$3)`,
					[
						randomUUID(),
						recipient,
						await symmetricEncrypt({ key: secret, data: subscription }),
					],
				);
			await database.query(
				`INSERT INTO ${scope}."user" (id,name,email,"emailVerified") VALUES ('fixture-provider-owner','Fixture owner','fixture-owner@example.test',TRUE)`,
			);
			await database.query(
				`INSERT INTO ${scope}."ssoProvider" (id,"providerId","userId",issuer,domain,"domainVerified","oidcConfig","samlConfig")
			 VALUES ($1,$1,'fixture-provider-owner',$3,'fixture.example',TRUE,$4,NULL),
			        ($2,$2,'fixture-provider-owner',$3,'fixture.example',TRUE,NULL,$5)`,
				[
					oidc,
					saml,
					issuer,
					JSON.stringify({
						issuer,
						clientId: "synthetic-oidc-id",
						clientSecret: "synthetic-oidc-secret",
						authorizationEndpoint: `${issuer}/authorize`,
						tokenEndpoint: `${issuer}/token`,
						jwksEndpoint: `${issuer}/jwks`,
						pkce: true,
					}),
					JSON.stringify({
						issuer,
						entryPoint: `${issuer}/saml`,
						callbackUrl: `${origin}${basePath}/sso/saml2/sp/acs/${saml}`,
						cert: "synthetic-certificate",
					}),
				],
			);
			const discovery = `${origin}/.well-known/openid-configuration`;
			const observedRequests: string[] = [];
			const network = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) => {
					const url = input instanceof Request ? input.url : String(input);
					observedRequests.push(url);
					if (url === discovery)
						return Response.json({
							issuer: origin,
							authorization_endpoint: `${origin}${basePath}/oauth2/authorize`,
							token_endpoint: `${origin}${basePath}/oauth2/token`,
							jwks_uri: `${origin}${basePath}/jwks`,
						});
					throw new Error(
						"Unexpected external traffic in callback security fixture.",
					);
				});
			try {
				const stock = native(nativeDatabase);
				const candidate = createOwnedProjectEngine({
					database,
					project: { schemaName: schema, slug },
					baseURL: origin,
					basePath,
					trustedOrigins: [],
					signingSecret: secret,
					trustedIP: (request) => request.headers.get("x-real-ip"),
					policy: defaultAuthPolicy,
					oauth: {
						defaultErrorURL: `${origin}/auth-error`,
						google: {
							...google,
							redirectURI: `${origin}${basePath}/callback/google`,
						},
						broker: {
							...broker,
							issuer,
							discoveryURL: `${issuer}/.well-known/openid-configuration`,
							redirectURI: `${origin}${basePath}/callback/allauth`,
						},
					},
					sso: { defaultErrorURL: `${origin}/auth-error`, saml: true },
				});
				const callbacks = [
					{ path: "/callback/google", template: "/callback/:id" },
					{ path: "/callback/allauth", template: "/callback/:id" },
					{
						path: `/sso/callback/${oidc}`,
						template: "/sso/callback/:providerId",
					},
					{
						path: `/sso/saml2/sp/acs/${saml}`,
						template: "/sso/saml2/sp/acs/:providerId",
						body: new URLSearchParams({
							SAMLResponse: assertion,
							RelayState: submitted,
						}),
					},
				];
				const incoming = ({ path, body }: (typeof callbacks)[number]) => {
					const url = new URL(`${basePath}${path}`, origin);
					url.searchParams.set("login_hint", submitted);
					url.searchParams.set("error_description", submitted);
					return new Request(url, {
						method: body ? "POST" : "GET",
						headers: {
							"x-real-ip": ip,
							"x-forwarded-for": "192.0.2.88",
							"user-agent": rawUserAgent,
						},
						body,
					});
				};
				const countFailures = async () =>
					(
						await database.query<{ count: number }>(
							`SELECT count(*)::integer AS count FROM ${scope}."allauthEvent" WHERE type='security.sign-in-failed'`,
						)
					).rows[0]?.count;
				const failureKey = await securitySubject(secret, "fail-ip", ip);
				const ruleId = randomUUID();
				const failures = callbacks.length + 1;
				async function exercise(dispatch: Dispatch) {
					for (const callback of callbacks) {
						const response = await dispatch(incoming(callback));
						expect([302, 400]).toContain(response.status);
						expect(
							response.headers
								.getSetCookie()
								.some((value) => value.includes("session_token=")),
						).toBe(false);
					}
					const started = await dispatch(
						new Request(`${origin}${basePath}/sign-in/social`, {
							method: "POST",
							headers: {
								origin,
								"content-type": "application/json",
								"x-real-ip": ip,
							},
							body: JSON.stringify({
								provider: "google",
								callbackURL: `${origin}/account`,
							}),
						}),
					);
					expect(started.status, await started.clone().text()).toBe(200);
					const { url: authorization } = (await started.json()) as {
						url: string;
					};
					const state = new URL(authorization).searchParams.get("state");
					if (!state)
						throw new Error("The configured provider did not issue a state.");
					const canceled = incoming(callbacks[0]!);
					const callback = new URL(canceled.url);
					callback.searchParams.set("state", state);
					callback.searchParams.set("error", "access_denied");
					canceled.headers.set(
						"cookie",
						started.headers
							.getSetCookie()
							.map((header) => header.split(";", 1)[0])
							.join("; "),
					);
					const declined = await dispatch(
						new Request(callback, { headers: canceled.headers }),
					);
					expect(declined.status).toBe(302);
					expect(
						new URL(declined.headers.get("location")!).searchParams.has(
							"error",
						),
					).toBe(true);
					const { rows } = await database.query(
						`SELECT key,count,scope FROM ${scope}."allauthSecurityCounter"`,
					);
					expect(rows).toEqual([
						{ key: failureKey, count: failures, scope: "fail-ip" },
					]);
					const initialFailures = await countFailures();
					await database.query(
						`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'ip',$2,'Synthetic callback policy')`,
						[ruleId, ip],
					);
					try {
						const response = await dispatch(incoming(callbacks[0]!));
						expect(response.status).toBe(429);
						expect(await response.json()).toMatchObject({
							code: "ALLAUTH_SECURITY_BLOCKED",
						});
						expect(await countFailures()).toBe(initialFailures);
					} finally {
						await database.query(
							`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=$1`,
							[ruleId],
						);
					}
					const envelopes: Omit<
						ControlWebhookEnvelope["data"]["event"],
						"id" | "createdAt"
					>[] = [];
					const delivered = await deliverPendingWebhooks({
						database: nativeDatabase,
						secret,
						now: () => new Date(Date.now() + 2_000),
						maxDeliveries: 10,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						async transport({ destination, body, headers }) {
							expect(destination.url.href).toBe(recipient);
							expect(headers["webhook-signature"]).toBe(
								`v1,${createHmac(
									"sha256",
									Buffer.from(subscription.slice(6), "base64"),
								)
									.update(
										`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.${body}`,
									)
									.digest("base64")}`,
							);
							expect(body).not.toContain(submitted);
							expect(body).not.toContain(assertion);
							expect(body).not.toContain(state);
							expect(body).not.toContain("192.0.2.88");
							const envelope = JSON.parse(body) as ControlWebhookEnvelope;
							const { id, createdAt, ...event } = envelope.data.event;
							expect(envelope).toEqual({
								id,
								type: event.type,
								timestamp: createdAt,
								data: { event: { id, createdAt, ...event } },
							});
							envelopes.push(event);
							return 204;
						},
					});
					expect(delivered).toEqual({
						claimed: failures + 1,
						delivered: failures + 1,
						retried: 0,
						failed: 0,
					});
					await database.query(`DELETE FROM ${scope}."allauthSecurityCounter"`);
					return envelopes.sort((left, right) =>
						JSON.stringify(left).localeCompare(JSON.stringify(right)),
					);
				}
				const expected = await exercise(stock.handler);
				expect(expected).toEqual(
					expect.arrayContaining(
						callbacks.map(({ template }) => ({
							type: "security.sign-in-failed",
							outcome: "failure",
							ipAddress: ip,
							userAgent,
							metadata: { path: template, method: template.split("/").pop() },
						})),
					),
				);
				expect(await exercise(candidate.dispatch)).toEqual(expected);
				expect(observedRequests).toEqual([discovery]);
				for (const table of [
					"allauthEvent",
					"allauthWebhookDelivery",
					"allauthSecurityCounter",
					"session",
				])
					expect(
						(await database.query(`SELECT 1 FROM "${sibling}"."${table}"`))
							.rowCount,
					).toBe(0);
				expect(
					(await database.query(`SELECT id FROM ${scope}."session"`)).rowCount,
				).toBe(0);
			} finally {
				network.mockRestore();
			}
		});
	},
);
