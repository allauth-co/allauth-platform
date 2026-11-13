import { createHash, createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import type { Statements } from "better-auth/plugins/access";
import {
	defaultRoles,
	defaultStatements,
} from "better-auth/plugins/organization/access";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAuthOptions } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { defaultApplicationBranding } from "../branding/validation";
import { allauthControl } from "../control";
import { newWebhookSigningSecret, webhookSignature } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhook-delivery";
import { deliverPendingWebhooks } from "../control/webhook-delivery";
import { sealLegacyUnversionedRecord } from "../legacy-encrypted-record";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { createOwnedProjectEngine } from "./owned-project-engine";
import type { OwnedProjectOrganizationOptions } from "./owned-project-organization";
import { createOwnedProjectOrganizationHttp } from "./owned-project-organization";
import { createOwnedProjectInvitationEmail } from "./owned-project-organization-email";
import type { InvitationRecord } from "./owned-project-organization-store";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.organization-fixture.example";
const appOrigin = "https://app.organization-fixture.example";
const basePath = "/api/auth";
const secret = "isolated-owned-project-organization-fixture-secret";
const cookieName =
	"__Secure-allauth_project_organization-fixture.session_token";

function request(
	endpoint: string,
	cookie = "",
	body?: object,
	caller = appOrigin,
) {
	return new Request(`${origin}${basePath}/organization/${endpoint}`, {
		method: body ? "POST" : "GET",
		headers: {
			cookie,
			origin: caller,
			"x-real-ip": "192.0.2.38",
			"user-agent": "organization-rehearsal",
			...(body ? { "content-type": "application/json" } : {}),
		},
		...(body ? { body: JSON.stringify(body) } : {}),
	});
}

async function nativeFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			trustedOrigins: [appOrigin],
			secret,
			database: { db: database, type: "postgres", transaction: true },
			session: { cookieCache: { enabled: false } },
			advanced: { cookiePrefix: "allauth_project_organization-fixture" },
			plugins: [
				allauthControl({ ipHeader: "x-real-ip" }),
				organization({
					ac: createAccessControl<Statements>(defaultStatements),
					roles: defaultRoles,
					dynamicAccessControl: { enabled: true },
					teams: { enabled: true },
					requireEmailVerificationOnInvitation: true,
					allowUserToCreateOrganization: (user) => user.emailVerified,
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth.handler;
}

type Org = {
	id: string;
	slug: string;
	name: string;
	members: { id: string; userId: string; role: string }[];
	teams: { id: string }[];
};
type Account = { id: string; email: string; sessionId: string; cookie: string };

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned organization transport",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let legacyDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let native: Awaited<ReturnType<typeof nativeFixture>>;
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
					"Organization tests require the isolated PostgreSQL fixture.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.toString(), max: 8 });
			const client = await database.connect();
			try {
				for (const realm of [schema, other]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					for (const migration of [
						"001-initial-auth.sql",
						"002-control-plane.sql",
						"004-webhooks.sql",
						"005-free-plugins.sql",
					])
						await client.query(
							readFileSync(
								new URL(`../../migrations/${migration}`, import.meta.url),
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
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			native = await nativeFixture(legacyDatabase);
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

		function owned(
			overrides: Partial<OwnedProjectOrganizationOptions> = {},
			namespace = schema,
		) {
			const store = createProjectEngineStore(database, namespace);
			const handler = createOwnedProjectOrganizationHttp({
				database,
				project: { schemaName: namespace },
				policy: defaultAuthPolicy,
				async currentSession(headers, client) {
					const token = readLegacySessionCookie(headers, cookieName, secret);
					if (!token) return null;
					const result = await store.session(token, 0, client);
					return result &&
						!result.user.banned &&
						!result.user.directoryDisabled &&
						!result.session.impersonatedBy
						? { token, ...result }
						: null;
				},
				trustedRequest(headers) {
					return (
						headers.get("origin") === appOrigin && !headers.has("authorization")
					);
				},
				readBody: (input) => input.json().catch(() => null),
				auditContext(input) {
					return {
						ipAddress: input.headers.get("x-real-ip") ?? undefined,
						userAgent: input.headers.get("user-agent") ?? undefined,
					};
				},
				sessionCookies(input) {
					return new Headers({
						"set-cookie": `${input.headers.get("cookie")}; Path=/; HttpOnly; Secure`,
					});
				},
				...overrides,
			});
			return async (
				endpoint: string,
				cookie = "",
				body?: object,
				caller?: string,
			) => {
				const input = request(endpoint, cookie, body, caller);
				const response = await handler(
					new URL(input.url).pathname.slice(basePath.length),
					input,
				);
				if (!response)
					throw new Error(`Unhandled fixture operation ${endpoint}`);
				return response;
			};
		}

		async function account({
			verified = true,
			role = "user",
			namespace = schema,
		} = {}): Promise<Account> {
			const id = randomUUID();
			const email = `${id}@fixture.example`;
			await database.query(
				`INSERT INTO "${namespace}"."user" (id,name,email,"emailVerified",role,"privateMetadata") VALUES ($1,'Fixture user',$2,$3,$4,'{"neverReturn":true}'::jsonb)`,
				[id, email, verified, role],
			);
			const sessionId = randomUUID();
			const token = randomUUID();
			await database.query(
				`INSERT INTO "${namespace}"."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,statement_timestamp() + interval '1 day',statement_timestamp())`,
				[sessionId, token, id],
			);
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			return {
				id,
				email,
				sessionId,
				cookie: `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`,
			};
		}

		async function organizationFixture(
			owner: Account,
			engine = owned(),
		): Promise<Org> {
			const response = await engine("create", owner.cookie, {
				name: "Fixture organization",
				slug: `fixture-${randomUUID()}`,
				metadata: { example: true },
			});
			expect(response.status).toBe(200);
			const created = (await response.json()) as Org;
			const full = await engine(
				`get-full-organization?organizationId=${created.id}`,
				owner.cookie,
			);
			expect(full.status).toBe(200);
			return (await full.json()) as Org;
		}

		async function invite(
			organizationId: string,
			inviter: Account,
			recipient: Account,
			{
				teams,
				expired = false,
				role = "member",
			}: { teams?: string; expired?: boolean; role?: string } = {},
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."invitation" (id,"organizationId",email,role,"teamId",status,"expiresAt","inviterId")
		 VALUES ($1,$2,$3,$4,$5,'pending',statement_timestamp() + $6::int * interval '1 second',$7)`,
				[
					id,
					organizationId,
					recipient.email,
					role,
					teams ?? null,
					expired ? -60 : 3600,
					inviter.id,
				],
			);
			return id;
		}

		function installedOrganizationWriters() {
			const previous = betterAuth({
				...createAuthOptions(
					{ db: legacyDatabase!, type: "postgres", transaction: true },
					{
						ALLAUTH_AUTH_URL: origin,
						ALLAUTH_AUTH_SECRET: secret,
						AUTH_RUNTIME: "node",
						SCIM_CREDENTIAL_HASH_SECRET:
							"synthetic-organization-webhook-fixture-key",
						EMAIL_FROM: "organization@fixture.example",
						EMAIL: { async send() {} },
					},
					{
						name: "Organization webhook fixture",
						basePath,
						cookiePrefix: "allauth_project_organization-fixture",
						primaryOrigin: appOrigin,
						publicOrigin: origin,
						origins: [appOrigin],
						broker: {
							clientId: "fixture-broker",
							clientSecret: "synthetic-broker-secret",
						},
						async authorizeAdmin() {
							return null;
						},
						management: { id: "organization-webhook-fixture" },
					},
				),
				logger: { disabled: true },
			});
			const candidate = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug: "organization-fixture" },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: (request) => request.headers.get("x-real-ip"),
			});
			return { native: previous.handler, owned: candidate.dispatch };
		}

		it("preserves signed invitation events, team context and session renewal across writers", async () => {
			const writers = installedOrganizationWriters();
			const owner = await account();
			const outsider = await account();
			const selected = await organizationFixture(owner);
			const teamId = selected.teams[0]!.id;
			const secondTeam = await writers.owned(
				request("create-team", owner.cookie, {
					organizationId: selected.id,
					name: "Second signed fixture team",
				}),
			);
			expect(secondTeam.status).toBe(200);
			const { id: secondTeamId } = (await secondTeam.json()) as { id: string };
			const cases = [
				{ teams: [], session: "fresh" },
				{ teams: [teamId], session: "fresh" },
				{ teams: [teamId, secondTeamId], session: "fresh" },
				{ teams: [], session: "due" },
				{ teams: [teamId], session: "due" },
				{ teams: [], session: "dont-remember" },
				{ teams: [teamId], session: "dont-remember" },
				{ teams: [], session: "disable-refresh" },
				{ teams: [teamId], session: "disable-refresh" },
			] as const;
			const attempts: {
				writer: keyof typeof writers;
				scenario: (typeof cases)[number];
				recipient: Account;
				id: string;
			}[] = [];
			for (const writer of ["native", "owned"] as const) {
				for (const scenario of cases) {
					const { teams } = scenario;
					const recipient = await account();
					const issue = writers[writer === "native" ? "owned" : "native"];
					const invited = await issue(
						request("invite-member", owner.cookie, {
							organizationId: selected.id,
							email: recipient.email,
							role: "member",
							...(teams.length && { teamId: teams }),
						}),
					);
					expect(invited.status, await invited.clone().text()).toBe(200);
					const { id } = (await invited.json()) as { id: string };
					attempts.push({ writer, scenario, recipient, id });
				}
			}
			// Keep fixture sessions before their ordinary refresh window so the
			// endpoint's single-team cookie reissue is observable on its own.
			await database.query(
				`UPDATE "${schema}"."session" SET "expiresAt"=statement_timestamp() + $2 * interval '1 second' WHERE id=ANY($1::text[])`,
				[
					[
						outsider.sessionId,
						...attempts
							.filter(({ scenario }) => scenario.session === "fresh")
							.map(({ recipient }) => recipient.sessionId),
					],
					defaultAuthPolicy.sessionExpiresInSeconds,
				],
			);
			const endpointId = randomUUID();
			const destination =
				"https://organization-webhooks.fixture.example/receive";
			const signingKey = newWebhookSigningSecret();
			for (const namespace of [schema, other])
				await database.query(
					`INSERT INTO "${namespace}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
					 VALUES ($1,$2,'["organization.*"]',$3)`,
					[
						endpointId,
						destination,
						sealLegacyUnversionedRecord(signingKey, secret),
					],
				);
			try {
				const dontRemember = `${cookieName.replace(".session_token", ".dont_remember")}=${encodeURIComponent(
					`true.${createHmac("sha256", secret).update("true").digest("base64")}`,
				)}`;
				for (const { writer, scenario, recipient, id } of attempts) {
					const { teams, session } = scenario;
					const dispatch = writers[writer];
					if (teams.length === 1 && session === "fresh") {
						const denied = await dispatch(
							request("accept-invitation", outsider.cookie, {
								invitationId: id,
							}),
						);
						expect(denied.status).toBe(403);
						expect(await denied.json()).toMatchObject({
							code: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
						});
						expect(denied.headers.getSetCookie()).toEqual([]);
					}
					const {
						rows: [before],
					} = await database.query<{ token: string; expiresAt: Date }>(
						`SELECT token,"expiresAt" FROM "${schema}"."session" WHERE id=$1`,
						[recipient.sessionId],
					);
					const acceptPath =
						session === "disable-refresh"
							? "accept-invitation?disableRefresh=true"
							: "accept-invitation";
					const cookies =
						session === "dont-remember"
							? `${recipient.cookie}; ${dontRemember}`
							: recipient.cookie;
					const accepted = await dispatch(
						request(acceptPath, cookies, { invitationId: id }),
					);
					expect(accepted.status, await accepted.clone().text()).toBe(200);
					expect(await accepted.json()).toMatchObject({
						invitation: { id, status: "accepted" },
						member: {
							userId: recipient.id,
							role: "member",
							organizationId: selected.id,
						},
					});
					const sessionCookies = accepted.headers
						.getSetCookie()
						.filter((entry) => entry.startsWith(`${cookieName}=`));
					const reissued = teams.length === 1 || session === "due";
					expect(
						sessionCookies.length > 0,
						`${writer}: ${session}, ${teams.length} invited teams`,
					).toBe(reissued);
					for (const entry of sessionCookies) {
						expect(
							readLegacySessionCookie(
								new Headers({ cookie: entry.split(";", 1)[0] }),
								cookieName,
								secret,
							),
						).toBe(before!.token);
						if (session === "dont-remember")
							expect(entry).not.toContain("Max-Age=");
						else
							expect(entry).toContain(
								`Max-Age=${defaultAuthPolicy.sessionExpiresInSeconds}`,
							);
					}
					expect(accepted.headers.has("set-auth-token")).toBe(false);
					const {
						rows: [after],
					} = await database.query<{
						token: string;
						expiresAt: Date;
						activeOrganizationId: string;
						activeTeamId: string | null;
					}>(
						`SELECT token,"expiresAt","activeOrganizationId","activeTeamId" FROM "${schema}"."session" WHERE id=$1`,
						[recipient.sessionId],
					);
					expect(after).toMatchObject({
						token: before!.token,
						activeOrganizationId: selected.id,
						activeTeamId: teams.length === 1 ? teamId : null,
					});
					if (session === "due") {
						expect(after!.expiresAt.getTime()).toBeGreaterThan(
							before!.expiresAt.getTime(),
						);
						expect(
							Math.abs(
								after!.expiresAt.getTime() -
									Date.now() -
									defaultAuthPolicy.sessionExpiresInSeconds * 1000,
							),
						).toBeLessThan(5000);
					} else {
						expect(after!.expiresAt).toEqual(before!.expiresAt);
					}
				}
				const received: { body: string; headers: Record<string, string> }[] =
					[];
				const delivered = await deliverPendingWebhooks({
					database: legacyDatabase!,
					secret,
					maxDeliveries: 20,
					now: () => new Date(Date.now() + 1000),
					resolver: async () => [{ address: "93.184.216.34", family: 4 }],
					async transport({ destination: target, body, headers }) {
						expect(target.url.href).toBe(destination);
						received.push({ body, headers });
						return 204;
					},
				});
				const expectedDeliveries =
					attempts.length +
					attempts.filter(
						({ scenario }) =>
							scenario.teams.length === 1 && scenario.session === "fresh",
					).length;
				expect(delivered).toEqual({
					claimed: expectedDeliveries,
					delivered: expectedDeliveries,
					retried: 0,
					failed: 0,
				});
				const envelopes = [];
				for (const { body, headers } of received) {
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							signingKey,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					const envelope = JSON.parse(body) as ControlWebhookEnvelope;
					expect(envelope.data.event).toMatchObject({
						id: envelope.id,
						type: envelope.type,
						createdAt: envelope.timestamp,
					});
					expect(envelope.data.user).toBeUndefined();
					expect(body).not.toContain(signingKey);
					envelopes.push(envelope);
				}
				expect(new Set(envelopes.map(({ id }) => id)).size).toBe(
					expectedDeliveries,
				);
				for (const {
					writer,
					scenario: { teams, session },
					id,
				} of attempts) {
					const matching = envelopes
						.map(({ data }) => data.event)
						.filter(({ targetId }) => targetId === id);
					const common = {
						type: "organization.invitation.accepted",
						organizationId: selected.id,
						targetId: id,
						ipAddress: "192.0.2.38",
						userAgent: "organization-rehearsal",
					};
					const success = matching.find(({ outcome }) => outcome === "success");
					expect(success, writer).toEqual({
						...common,
						id: expect.any(String),
						createdAt: expect.any(String),
						outcome: "success",
						metadata: { path: "/organization/accept-invitation" },
					});
					const rejected = matching.find(
						({ outcome }) => outcome === "failure",
					);
					if (teams.length === 1 && session === "fresh")
						expect(rejected, writer).toEqual({
							...common,
							id: expect.any(String),
							createdAt: expect.any(String),
							outcome: "failure",
							metadata: {
								path: "/organization/accept-invitation",
								errorCode: "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
							},
						});
					else expect(rejected).toBeUndefined();
				}
				const sibling = await database.query(
					`SELECT 1 FROM "${other}"."allauthWebhookDelivery" WHERE "endpointId"=$1`,
					[endpointId],
				);
				expect(sibling.rows).toEqual([]);
			} finally {
				for (const namespace of [schema, other])
					await database.query(
						`DELETE FROM "${namespace}"."allauthWebhookEndpoint" WHERE id=$1`,
						[endpointId],
					);
			}
		});

		it("signs organization schema validation and unknown invitation role failures across writers", async () => {
			const writers = installedOrganizationWriters();
			const owner = await account();
			const outsider = await account();
			const selected = await organizationFixture(owner);
			const mutations = {
				create: "created",
				update: "updated",
				delete: "deleted",
				"remove-member": "member.removed",
				"update-member-role": "member.role-updated",
				"invite-member": "invitation.created",
				"cancel-invitation": "invitation.cancelled",
				"accept-invitation": "invitation.accepted",
				"reject-invitation": "invitation.rejected",
				leave: "member.left",
				"create-team": "team.created",
				"update-team": "team.updated",
				"remove-team": "team.removed",
				"add-team-member": "team.member-added",
				"remove-team-member": "team.member-removed",
				"create-role": "role.created",
				"update-role": "role.updated",
				"delete-role": "role.deleted",
			};
			const deliveryCount = Object.keys(mutations).length + 2;
			const endpointId = randomUUID();
			const url =
				"https://organization-update-webhooks.fixture.example/receive";
			const signingKey = newWebhookSigningSecret();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
				 VALUES ($1,$2,'["organization.*"]',$3)`,
				[endpointId, url, sealLegacyUnversionedRecord(signingKey, secret)],
			);
			try {
				for (const writer of ["native", "owned"] as const) {
					const dispatch = writers[writer];
					const organizationId = selected.id;
					const name = `Signed valid update from ${writer}`;
					const updated = await dispatch(
						request("update", owner.cookie, {
							organizationId,
							data: { name },
						}),
					);
					expect(updated.status).toBe(200);
					expect(await updated.json()).toMatchObject({
						id: organizationId,
						name,
					});
					for (const endpoint of Object.keys(mutations)) {
						const malformed = await dispatch(
							request(
								endpoint,
								owner.cookie,
								endpoint === "update" ? { organizationId } : {},
							),
						);
						expect(malformed.status, `${writer} ${endpoint}`).toBe(400);
						expect(await malformed.json()).toMatchObject({
							code: writer === "native" ? "VALIDATION_ERROR" : "BAD_REQUEST",
						});
					}
					const denied = await dispatch(
						request("update", outsider.cookie, {
							organizationId,
							data: { name: "Unauthorized fixture update" },
						}),
					);
					expect(denied.status).toBe(400);
					const denial = "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION";
					expect(await denied.json()).toMatchObject({ code: denial });
					const persisted = await database.query(
						`SELECT name FROM "${schema}"."organization" WHERE id=$1`,
						[organizationId],
					);
					expect(persisted.rows).toEqual([{ name }]);

					const received: ControlWebhookEnvelope["data"]["event"][] = [];
					const deliveryOptions: Parameters<typeof deliverPendingWebhooks>[0] =
						{
							database: legacyDatabase!,
							secret,
							maxDeliveries: deliveryCount,
							now: () => new Date(Date.now() + 1000),
							resolver: async () => [{ address: "93.184.216.34", family: 4 }],
							async transport({ destination, body, headers }) {
								expect(destination.url.href).toBe(url);
								expect(headers["webhook-signature"]).toBe(
									await webhookSignature(
										signingKey,
										headers["webhook-id"],
										headers["webhook-timestamp"],
										body,
									),
								);
								const envelope = JSON.parse(body) as ControlWebhookEnvelope;
								expect(envelope.data.event).toMatchObject({
									id: envelope.id,
									type: envelope.type,
									createdAt: envelope.timestamp,
								});
								expect(envelope.data.user).toBeUndefined();
								expect(body).not.toContain(name);
								expect(body).not.toContain(outsider.email);
								expect(body).not.toContain("unavailable-fixture-role");
								received.push(envelope.data.event);
								return 204;
							},
						};
					expect(await deliverPendingWebhooks(deliveryOptions)).toEqual({
						claimed: deliveryCount,
						delivered: deliveryCount,
						retried: 0,
						failed: 0,
					});
					const path = "/organization/update";
					const common = {
						id: expect.any(String),
						createdAt: expect.any(String),
						ipAddress: "192.0.2.38",
						userAgent: "organization-rehearsal",
					};
					const update = {
						...common,
						type: "organization.updated",
						organizationId,
					};
					expect(received, writer).toEqual(
						expect.arrayContaining([
							{ ...update, outcome: "success", metadata: { path } },
							{
								...update,
								outcome: "failure",
								metadata: { path, errorCode: denial },
							},
							...Object.entries(mutations).map(([endpoint, suffix]) => ({
								...common,
								type: `organization.${suffix}`,
								...(endpoint === "update" && { organizationId }),
								outcome: "failure",
								metadata: {
									path: `/organization/${endpoint}`,
									errorCode: "VALIDATION_ERROR",
								},
							})),
						]),
					);
					received.length = 0;
					const invitation = await dispatch(
						request("invite-member", owner.cookie, {
							organizationId,
							email: outsider.email,
							role: "unavailable-fixture-role",
						}),
					);
					expect(invitation.status).toBe(400);
					expect(await invitation.json()).toEqual({
						message: `${writer === "native" ? "ROLE_NOT_FOUND" : "Role not found"}: unavailable-fixture-role`,
						...(writer === "owned" && { code: "BAD_REQUEST" }),
					});
					expect(
						(
							await database.query(
								`SELECT id FROM "${schema}"."invitation" WHERE "organizationId"=$1 AND email=$2`,
								[organizationId, outsider.email],
							)
						).rows,
					).toEqual([]);
					expect(await deliverPendingWebhooks(deliveryOptions)).toEqual({
						claimed: 1,
						delivered: 1,
						retried: 0,
						failed: 0,
					});
					expect(received, writer).toEqual([
						{
							...common,
							type: "organization.invitation.created",
							organizationId,
							outcome: "failure",
							metadata: {
								path: "/organization/invite-member",
								errorCode: "AUTHENTICATION_FAILED",
							},
						},
					]);
				}
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
		});

		it.each([
			"native",
			"owned",
		] as const)("signs successful membership, team, role and deletion events with the %s writer", async (writer) => {
			const dispatch = installedOrganizationWriters()[writer];
			const owner = await account();
			const removed = await account();
			const leaving = await account();
			const { id: organizationId } = await organizationFixture(owner);
			const memberId = await member(organizationId, removed.id, "member");
			await member(organizationId, leaving.id, "member");
			const endpointId = randomUUID();
			const url =
				"https://organization-lifecycle-webhooks.fixture.example/receive";
			const signingKey = newWebhookSigningSecret();
			await database.query(
				`INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
					 VALUES ($1,$2,'["organization.*"]',$3)`,
				[endpointId, url, sealLegacyUnversionedRecord(signingKey, secret)],
			);
			try {
				type EventScope = Pick<
					ControlWebhookEnvelope["data"]["event"],
					"organizationId" | "targetId" | "userId"
				>;
				const expected = new Map<string, EventScope & { type: string }>();
				async function mutate(
					endpoint: string,
					suffix: string,
					body: object,
					fields: EventScope = {},
					caller = owner,
				) {
					const response = await dispatch(
						request(endpoint, caller.cookie, body),
					);
					expect(response.status, `${writer} ${endpoint}`).toBe(200);
					expected.set(`/organization/${endpoint}`, {
						type: `organization.${suffix}`,
						...fields,
					});
					return response;
				}
				const scope = { organizationId };
				const team = await mutate(
					"create-team",
					"team.created",
					{
						...scope,
						name: "Webhook fixture team",
					},
					scope,
				);
				const { id: teamId } = (await team.json()) as { id: string };
				const teamMember = { teamId, userId: removed.id };
				const teamMemberEvent = { userId: removed.id, targetId: removed.id };
				await mutate(
					"add-team-member",
					"team.member-added",
					{ ...scope, ...teamMember },
					{ ...scope, ...teamMemberEvent },
				);
				await mutate(
					"remove-team-member",
					"team.member-removed",
					teamMember,
					teamMemberEvent,
				);
				await mutate(
					"update-team",
					"team.updated",
					{
						teamId,
						data: { name: "Renamed webhook fixture team" },
					},
					{ ...scope, targetId: teamId },
				);
				await mutate(
					"remove-team",
					"team.removed",
					{ teamId },
					{ targetId: teamId },
				);
				await mutate(
					"update-member-role",
					"member.role-updated",
					{ memberId, role: "admin" },
					{ ...scope, targetId: memberId },
				);
				await mutate("remove-member", "member.removed", {
					memberIdOrEmail: removed.email,
				});
				await mutate("leave", "member.left", scope, scope, leaving);
				const role = await mutate(
					"create-role",
					"role.created",
					{
						...scope,
						role: "fixture-reporter",
						permission: { team: ["create"] },
					},
					scope,
				);
				const {
					roleData: { id: roleId },
				} = (await role.json()) as { roleData: { id: string } };
				await mutate(
					"update-role",
					"role.updated",
					{
						...scope,
						roleId,
						data: { permission: { team: ["create", "update"] } },
					},
					scope,
				);
				await mutate(
					"delete-role",
					"role.deleted",
					{ ...scope, roleId },
					scope,
				);
				await mutate("delete", "deleted", scope, scope);

				const received: {
					url: string;
					body: string;
					headers: Record<string, string>;
				}[] = [];
				const delivered = await deliverPendingWebhooks({
					database: legacyDatabase!,
					secret,
					maxDeliveries: expected.size,
					now: () => new Date(Date.now() + 1000),
					resolver: async () => [{ address: "93.184.216.34", family: 4 }],
					async transport({ destination, body, headers }) {
						received.push({ url: destination.url.href, body, headers });
						return 204;
					},
				});
				expect(delivered).toEqual({
					claimed: expected.size,
					delivered: expected.size,
					retried: 0,
					failed: 0,
				});
				const ids = new Set<string>();
				for (const delivery of received) {
					const { body, headers } = delivery;
					expect(delivery.url).toBe(url);
					expect(headers["content-type"]).toBe("application/json");
					const digest = createHmac(
						"sha256",
						Buffer.from(signingKey.slice(6), "base64"),
					)
						.update(
							`${headers["webhook-id"]}.${headers["webhook-timestamp"]}.${body}`,
						)
						.digest("base64");
					expect(headers["webhook-signature"]).toBe(`v1,${digest}`);
					const envelope = JSON.parse(body) as ControlWebhookEnvelope;
					const path = String(envelope.data.event.metadata.path);
					const event = expected.get(path);
					expect(event, `${writer} ${path}`).toBeDefined();
					expect(envelope).toEqual({
						id: expect.any(String),
						type: event?.type,
						timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
						data: {
							event: {
								...event,
								id: envelope.id,
								createdAt: envelope.timestamp,
								outcome: "success",
								ipAddress: "192.0.2.38",
								userAgent: "organization-rehearsal",
								metadata: { path },
							},
						},
					});
					ids.add(envelope.id);
					expected.delete(path);
				}
				expect(expected.size).toBe(0);
				expect(ids.size).toBe(received.length);
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
		});

		it("delivers the same organization mutation outbox as the native writer", async () => {
			const owner = await account();
			const recipient = await account();
			const secondRecipient = await account();
			const outsider = await account();
			const candidate = owned();
			const organization = await organizationFixture(owner);
			await member(organization.id, secondRecipient.id, "member");
			const endpointId = randomUUID();
			for (const namespace of [schema, other])
				await database.query(
					`INSERT INTO "${namespace}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret")
					 VALUES ($1,'https://webhooks.fixture.example/organizations','["organization.*"]','fixture-ciphertext')`,
					[endpointId],
				);
			const controlEvents = async (namespace = schema) =>
				(
					await database.query<{ event: Record<string, unknown> }>(
						`SELECT (payload->'data'->'event') - 'id' - 'createdAt' AS event
					 FROM "${namespace}"."allauthWebhookDelivery"
					 WHERE "endpointId"=$1 ORDER BY "createdAt", id`,
						[endpointId],
					)
				).rows.map(({ event }) => event);
			const operations = async (dispatch: typeof candidate) => {
				const created = await dispatch("create", owner.cookie, {
					name: "Webhook example",
					slug: `webhook-${randomUUID()}`,
					keepCurrentActiveOrganization: true,
				});
				expect(created.status).toBe(200);
				const updated = await dispatch("update", owner.cookie, {
					organizationId: organization.id,
					data: { name: "Webhook change" },
				});
				expect(updated.status).toBe(200);
				const denied = await dispatch("update", outsider.cookie, {
					organizationId: organization.id,
					data: { name: "Denied change" },
				});
				expect(denied.status).toBe(400);
				const invited = await dispatch("invite-member", owner.cookie, {
					organizationId: organization.id,
					email: recipient.email,
					role: "member",
					resend: true,
				});
				expect(invited.status).toBe(200);
				const cancelled = await dispatch("cancel-invitation", owner.cookie, {
					invitationId: ((await invited.json()) as { id: string }).id,
				});
				expect(cancelled.status).toBe(200);
				const inviteId = await invite(organization.id, owner, secondRecipient);
				const rejected = await dispatch(
					"reject-invitation",
					secondRecipient.cookie,
					{
						invitationId: inviteId,
					},
				);
				expect(rejected.status).toBe(200);
				const team = await dispatch("create-team", owner.cookie, {
					organizationId: organization.id,
					name: `Webhook team ${randomUUID()}`,
				});
				expect(team.status).toBe(200);
				const { id: teamId } = (await team.json()) as { id: string };
				const addTeamMember = await dispatch("add-team-member", owner.cookie, {
					organizationId: organization.id,
					teamId,
					userId: secondRecipient.id,
				});
				expect(addTeamMember.status).toBe(200);
				const removeTeamMember = await dispatch(
					"remove-team-member",
					owner.cookie,
					{
						teamId,
						userId: secondRecipient.id,
					},
				);
				expect(removeTeamMember.status).toBe(200);
			};
			const nativeDispatch = (endpoint: string, cookie = "", body?: object) =>
				native(request(endpoint, cookie, body));
			await operations(nativeDispatch);
			const byType = (events: Awaited<ReturnType<typeof controlEvents>>) =>
				events
					.sort(
						(a, b) =>
							String(a.type).localeCompare(String(b.type)) ||
							String(a.outcome).localeCompare(String(b.outcome)),
					)
					.map((event) => ({
						...event,
						...(event.targetId &&
						String(event.type).startsWith("organization.invitation.")
							? { targetId: "invitation-id" }
							: {}),
					}));
			const expected = byType(await controlEvents());
			expect(expected).toHaveLength(9);
			await database.query(
				`DELETE FROM "${schema}"."allauthWebhookDelivery" WHERE "endpointId"=$1`,
				[endpointId],
			);
			await operations(candidate);
			expect(byType(await controlEvents())).toEqual(expected);
			expect(await controlEvents(other)).toEqual([]);
		});

		it("reads native organizations and writes native-readable ownership, default team and active selection", async () => {
			const owner = await account();
			const otherUser = await account();
			const engine = owned();
			const createdNative = await native(
				request("create", owner.cookie, {
					name: "Legacy org",
					slug: "legacy-org",
					logo: null,
					metadata: { order: 1 },
				}),
			);
			expect(createdNative.status).toBe(200);
			const legacy = (await createdNative.json()) as Org;
			for (const endpoint of [
				"list",
				"get-full-organization",
				"get-active-member",
				"get-active-member-role",
			]) {
				const original = await native(request(endpoint, owner.cookie));
				const replacement = await engine(endpoint, owner.cookie);
				expect(replacement.status).toBe(original.status);
				expect(await replacement.json()).toEqual(await original.json());
			}
			const newlyCreated = await engine("create", owner.cookie, {
				name: "Owned org",
				slug: "owned-org",
				metadata: { order: 2 },
				userId: otherUser.id,
				keepCurrentActiveOrganization: true,
			});
			expect(newlyCreated.status).toBe(200);
			const created = (await newlyCreated.json()) as Org;
			expect(created.members).toMatchObject([
				{ userId: owner.id, role: "owner" },
			]);
			expect(
				await (await engine("get-full-organization", owner.cookie)).json(),
			).toMatchObject({ id: legacy.id });
			const legacyRead = await native(
				request(
					`get-full-organization?organizationId=${created.id}`,
					owner.cookie,
				),
			);
			expect(legacyRead.status).toBe(200);
			const full = (await legacyRead.json()) as Org;
			expect(full).toMatchObject({
				id: created.id,
				slug: "owned-org",
				members: [{ userId: owner.id, role: "owner" }],
			});
			const teamId = full.teams[0]!.id;
			const team = await database.query(
				`SELECT t."memberCount", tm."membershipKey" FROM "${schema}".team t JOIN "${schema}"."teamMember" tm ON t.id = tm."teamId" WHERE t.id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([
				{
					memberCount: 1,
					membershipKey: createHash("sha256")
						.update(JSON.stringify([teamId, owner.id]))
						.digest("base64url"),
				},
			]);
			const picked = await engine("set-active", owner.cookie, {
				organizationSlug: "owned-org",
			});
			expect(picked.headers.getSetCookie()).toEqual([
				`${owner.cookie}; Path=/; HttpOnly; Secure`,
			]);
			expect(await picked.json()).toMatchObject({ id: created.id });
			expect(
				await (
					await native(request("get-full-organization", owner.cookie))
				).json(),
			).toMatchObject({ id: created.id });
			expect(
				await (
					await engine("set-active", owner.cookie, { organizationId: null })
				).json(),
			).toBeNull();
			expect(
				await (
					await native(request("get-full-organization", owner.cookie))
				).json(),
			).toBeNull();
			expect(
				(await engine("check-slug", owner.cookie, { slug: "owned-org" }))
					.status,
			).toBe(400);
			expect(
				(
					await engine("create", owner.cookie, {
						name: "Duplicate",
						slug: "owned-org",
					})
				).status,
			).toBe(400);
		});

		it("checks creation policy, exact origin, membership and realm before exposing or modifying organizations", async () => {
			const owner = await account();
			const stranger = await account();
			const unverified = await account({ verified: false });
			const admin = await account({ role: "user,admin" });
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			expect(
				(
					await engine(
						`get-full-organization?organizationId=${selected.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			expect(
				(
					await engine("set-active", stranger.cookie, {
						organizationId: selected.id,
					})
				).status,
			).toBe(403);
			expect(
				(
					await engine(
						`get-active-member-role?organizationId=${selected.id}&userId=${owner.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			expect(
				(
					await engine(
						"set-active",
						owner.cookie,
						{ organizationId: selected.id },
						"https://foreign.fixture.example",
					)
				).status,
			).toBe(403);
			expect((await owned({}, other)("list", owner.cookie)).status).toBe(401);
			const foreign = await account({ namespace: other });
			expect(
				await (await owned({}, other)("list", foreign.cookie)).json(),
			).toEqual([]);
			const data = { name: "Policy", slug: `policy-${randomUUID()}` };
			expect((await engine("create", unverified.cookie, data)).status).toBe(
				403,
			);
			expect(
				(
					await owned({ policy: { organizationCreation: "disabled" } })(
						"create",
						owner.cookie,
						data,
					)
				).status,
			).toBe(403);
			const adminsOnly = owned({
				policy: { organizationCreation: "admins-only" },
			});
			expect((await adminsOnly("create", owner.cookie, data)).status).toBe(403);
			expect((await adminsOnly("create", admin.cookie, data)).status).toBe(200);
		});

		it("accepts a native invitation once, preserves the role, and writes active organization and team", async () => {
			const owner = await account();
			const recipient = await account();
			const stranger = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			const nativeInvite = await native(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "admin",
					organizationId: selected.id,
					teamId,
				}),
			);
			expect(nativeInvite.status).toBe(200);
			const { id } = (await nativeInvite.json()) as { id: string };
			const read = await engine(`get-invitation?id=${id}`, recipient.cookie);
			const legacyRead = await native(
				request(`get-invitation?id=${id}`, recipient.cookie),
			);
			expect(read.status).toBe(200);
			expect(await read.json()).toEqual(await legacyRead.json());
			expect(
				(await engine(`get-invitation?id=${id}`, stranger.cookie)).status,
			).toBe(403);
			expect(
				await (await engine("list-user-invitations", recipient.cookie)).json(),
			).toMatchObject([{ id, organizationName: selected.name }]);
			expect(
				(
					await engine(
						`list-user-invitations?email=${recipient.email}`,
						stranger.cookie,
					)
				).status,
			).toBe(400);
			expect(
				(
					await engine(
						`list-invitations?organizationId=${selected.id}`,
						stranger.cookie,
					)
				).status,
			).toBe(403);
			const actions = await Promise.all([
				engine("accept-invitation", recipient.cookie, {
					invitationId: id,
					role: "owner",
				}),
				engine("accept-invitation", recipient.cookie, {
					invitationId: id,
					role: "owner",
				}),
			]);
			expect(actions.map((response) => response.status).sort()).toEqual([
				200, 400,
			]);
			const accepted = actions.find((response) => response.ok)!;
			expect(await accepted.json()).toMatchObject({
				invitation: { id, status: "accepted", role: "admin" },
				member: { role: "admin", userId: recipient.id },
			});
			expect(accepted.headers.getSetCookie()).toEqual([
				`${recipient.cookie}; Path=/; HttpOnly; Secure`,
			]);
			expect(
				await (
					await native(request("get-active-member-role", recipient.cookie))
				).json(),
			).toEqual({ role: "admin" });
			const persisted = await database.query(
				`SELECT "activeOrganizationId", "activeTeamId" FROM "${schema}".session WHERE id = $1`,
				[recipient.sessionId],
			);
			expect(persisted.rows).toEqual([
				{ activeOrganizationId: selected.id, activeTeamId: teamId },
			]);
			const team = await database.query(
				`SELECT "memberCount" FROM "${schema}".team WHERE id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([{ memberCount: 2 }]);
			expect(
				await (await engine("list-user-invitations", recipient.cookie)).json(),
			).toEqual([]);
		});

		it("enforces invitation ownership, verification, expiration and team realm, and preserves rejected state", async () => {
			const owner = await account();
			const recipient = await account();
			const unverified = await account({ verified: false });
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const another = await organizationFixture(owner, engine);
			const unverifiedId = await invite(selected.id, owner, unverified);
			expect(
				(await engine("list-user-invitations", unverified.cookie)).status,
			).toBe(403);
			expect(
				(
					await engine("accept-invitation", unverified.cookie, {
						invitationId: unverifiedId,
					})
				).status,
			).toBe(403);
			expect(
				(
					await engine("reject-invitation", unverified.cookie, {
						invitationId: unverifiedId,
					})
				).status,
			).toBe(403);
			const expired = await invite(selected.id, owner, recipient, {
				expired: true,
			});
			expect(
				(await engine(`get-invitation?id=${expired}`, recipient.cookie)).status,
			).toBe(400);
			expect(
				(
					await engine("accept-invitation", recipient.cookie, {
						invitationId: expired,
					})
				).status,
			).toBe(400);
			const rejected = await engine("reject-invitation", recipient.cookie, {
				invitationId: expired,
			});
			expect(await rejected.json()).toMatchObject({
				invitation: { id: expired, status: "rejected" },
				member: null,
			});
			const mismatched = await invite(selected.id, owner, recipient, {
				teams: another.teams[0]!.id,
			});
			const invalid = await engine("accept-invitation", recipient.cookie, {
				invitationId: mismatched,
			});
			expect(invalid.status).toBe(400);
			expect(await invalid.json()).toMatchObject({ code: "TEAM_NOT_FOUND" });
			expect(
				await (
					await engine(`get-invitation?id=${mismatched}`, recipient.cookie)
				).json(),
			).toMatchObject({ status: "pending" });
			expect(await (await engine("list", recipient.cookie)).json()).toEqual([]);
		});

		it("serializes entitlement checks for competing invitations without spending the losing invitation", async () => {
			const owner = await account();
			const first = await account();
			const second = await account();
			const engine = owned({ membershipLimit: async () => 2 });
			const selected = await organizationFixture(owner, engine);
			const firstId = await invite(selected.id, owner, first);
			const secondId = await invite(selected.id, owner, second);
			const results = await Promise.all([
				engine("accept-invitation", first.cookie, { invitationId: firstId }),
				engine("accept-invitation", second.cookie, { invitationId: secondId }),
			]);
			expect(results.map((response) => response.status).sort()).toEqual([
				200, 403,
			]);
			const denied = results[0]!.ok
				? { recipient: second, id: secondId }
				: { recipient: first, id: firstId };
			expect(
				await results.find((response) => !response.ok)!.json(),
			).toMatchObject({ code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED" });
			expect(
				await (
					await engine(
						`get-invitation?id=${denied.id}`,
						denied.recipient.cookie,
					)
				).json(),
			).toMatchObject({ status: "pending" });
			const unlimited = owned({ membershipLimit: async () => null });
			expect(
				(
					await unlimited("accept-invitation", denied.recipient.cookie, {
						invitationId: denied.id,
					})
				).status,
			).toBe(200);
		});

		it("dispatches the organization routes through the owned signed-cookie engine", async () => {
			const owner = await account();
			const recipient = await account();
			const delivered: string[] = [];
			const engine = createOwnedProjectEngine({
				database,
				project: { schemaName: schema, slug: "organization-fixture" },
				baseURL: origin,
				basePath,
				trustedOrigins: [appOrigin],
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedIP: () => "203.0.113.20",
				organization: {
					invitationEmail: {
						async send({ invitation }) {
							delivered.push(invitation.id);
						},
					},
				},
			});
			const created = await engine.dispatch(
				request("create", owner.cookie, {
					name: "Integrated",
					slug: "integrated-organization",
				}),
			);
			expect(created.status).toBe(200);
			const { id } = (await created.json()) as Org;
			expect(
				await (
					await engine.dispatch(request("get-full-organization", owner.cookie))
				).json(),
			).toMatchObject({ id, slug: "integrated-organization" });
			const permission = await engine.dispatch(
				request("has-permission", owner.cookie, {
					permissions: { invitation: ["create", "cancel"] },
				}),
			);
			expect(await permission.json()).toEqual({ success: true, error: null });
			const invited = await engine.dispatch(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "member",
				}),
			);
			expect(invited.status).toBe(200);
			const invitation = (await invited.json()) as InvitationRecord;
			expect(delivered).toEqual([invitation.id]);
			const canceled = await engine.dispatch(
				request("cancel-invitation", owner.cookie, {
					invitationId: invitation.id,
				}),
			);
			expect(await canceled.json()).toMatchObject({
				id: invitation.id,
				status: "canceled",
			});

			const cleared = await engine.dispatch(
				request("set-active", owner.cookie, { organizationId: null }),
			);
			expect(cleared.status).toBe(200);
			expect(cleared.headers.getSetCookie()[0]).toContain(owner.cookie);
			expect(
				await (
					await engine.dispatch(request("get-full-organization", owner.cookie))
				).json(),
			).toBeNull();
			expect(
				(
					await engine.dispatch(
						request(
							"list",
							owner.cookie,
							undefined,
							"https://foreign.fixture.example",
						),
					)
				).status,
			).toBe(403);
		});

		it("rolls back membership, team counters and session when the durable commercial guard declines the write", async () => {
			const owner = await account();
			const recipient = await account();
			const engine = owned({ membershipLimit: async () => null });
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			await database.query(`CREATE FUNCTION "${schema}".fixture_commercial_guard() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.role = 'fixture-commercial-block' THEN RAISE EXCEPTION 'fixture limit' USING ERRCODE = 'PAA01'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER fixture_commercial_guard AFTER INSERT ON "${schema}".member FOR EACH ROW EXECUTE FUNCTION "${schema}".fixture_commercial_guard()`);
			const id = await invite(selected.id, owner, recipient, {
				teams: teamId,
				role: "fixture-commercial-block",
			});
			const refused = await engine("accept-invitation", recipient.cookie, {
				invitationId: id,
			});
			expect(refused.status).toBe(403);
			expect(await refused.json()).toMatchObject({
				code: "ORGANIZATION_MEMBER_LIMIT_REACHED",
			});
			expect(
				await (
					await engine(`get-invitation?id=${id}`, recipient.cookie)
				).json(),
			).toMatchObject({ status: "pending" });
			expect(
				await (await engine("get-full-organization", recipient.cookie)).json(),
			).toBeNull();
			const team = await database.query(
				`SELECT "memberCount" FROM "${schema}".team WHERE id = $1`,
				[teamId],
			);
			expect(team.rows).toEqual([{ memberCount: 1 }]);
			const rows = await database.query(
				`SELECT id FROM "${schema}"."teamMember" WHERE "teamId" = $1 AND "userId" = $2`,
				[teamId, recipient.id],
			);
			expect(rows.rows).toEqual([]);
		});

		async function role(
			organizationId: string,
			name: string,
			permissions: Record<string, string[]>,
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."organizationRole" (id, "organizationId", role, permission) VALUES ($1, $2, $3, $4)`,
				[id, organizationId, name, JSON.stringify(permissions)],
			);
			return id;
		}

		async function member(
			organizationId: string,
			userId: string,
			roleName: string,
		) {
			const id = randomUUID();
			await database.query(
				`INSERT INTO "${schema}".member (id, "organizationId", "userId", role, "createdAt") VALUES ($1, $2, $3, $4, statement_timestamp())`,
				[id, organizationId, userId, roleName],
			);
			return id;
		}

		async function organizationGrant(organizationId: string, user: Account) {
			const id = randomUUID();
			const code = createHash("sha256")
				.update(randomUUID())
				.digest("base64url");
			await database.query(
				`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[id],
			);
			const values = [id, user.id, user.sessionId, organizationId];
			await database.query(
				`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","sessionId","referenceId","expiresAt","createdAt",scopes,"rotationReplayResponse","rotationReplayExpiresAt")
				 VALUES ($1,$1,$1,$2,$3,$4,now()+interval '1 hour',now(),'["organization:read","offline_access"]','fixture-encrypted-replay',now()+interval '1 minute')`,
				values,
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthAccessToken"(id,token,"clientId","userId","sessionId","referenceId","refreshId","expiresAt","createdAt",scopes)
				 VALUES ($1,$1,$1,$2,$3,$4,$1,now()+interval '1 hour',now(),'["organization:read"]')`,
				values,
			);
			await database.query(
				`INSERT INTO "${schema}"."oauthConsent"(id,"clientId","userId","referenceId","createdAt","updatedAt",scopes)
				 VALUES ($1,$1,$2,$3,now(),now(),'["organization:read"]')`,
				[id, user.id, organizationId],
			);
			await database.query(
				`INSERT INTO "${schema}".verification(id,identifier,value,"expiresAt")
				 VALUES ($1,$1,$2,now()+interval '1 minute')`,
				[
					code,
					JSON.stringify({
						type: "authorization_code",
						referenceId: organizationId,
						userId: user.id,
					}),
				],
			);
			return { id, code };
		}

		async function grantState(grant: { id: string; code: string }) {
			const { rows } = await database.query(
				`SELECT a.revoked IS NOT NULL AS "accessRevoked", r.revoked IS NOT NULL AS "refreshRevoked",
				 r."rotationReplayResponse" IS NOT NULL AS replay,
				 EXISTS (SELECT 1 FROM "${schema}"."oauthConsent" WHERE id = $1) AS consent,
				 EXISTS (SELECT 1 FROM "${schema}".verification WHERE id = $2) AS code
				 FROM "${schema}"."oauthAccessToken" a JOIN "${schema}"."oauthRefreshToken" r ON a."refreshId" = r.id
				 WHERE a.id = $1`,
				[grant.id, grant.code],
			);
			return rows[0];
		}

		const activeGrant = {
			accessRevoked: false,
			refreshRevoked: false,
			replay: true,
			consent: true,
			code: true,
		};
		const revokedGrant = {
			accessRevoked: true,
			refreshRevoked: true,
			replay: false,
			consent: false,
			code: false,
		};

		it("lists only authorized organization members with native pagination, filters and projection", async () => {
			const engine = owned();
			const owner = await account();
			const editor = await account();
			const reader = await account();
			const outsider = await account();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(outsider, engine);
			await member(selected.id, editor.id, "admin,member");
			await member(selected.id, reader.id, "member");
			await engine("set-active", reader.cookie, {
				organizationId: selected.id,
			});
			const filtered = `list-members?organizationId=${foreign.id}&organizationSlug=${selected.slug}&filterField=role&filterOperator=contains&filterValue=member&sortBy=role&sortDirection=desc&limit=1&offset=1`;
			const legacy = await native(request(filtered, reader.cookie));
			expect(legacy.status).toBe(200);
			const result = await engine(filtered, reader.cookie);
			expect(result.status).toBe(200);
			const page = (await result.json()) as { members: { user: object }[] };
			expect(page).toEqual(await legacy.json());
			expect(page).toMatchObject({
				total: 2,
				members: [
					{
						userId: editor.id,
						user: { id: editor.id, email: editor.email, image: null },
					},
				],
			});
			expect(Object.keys(page.members[0]!.user).sort()).toEqual([
				"email",
				"id",
				"image",
				"name",
			]);
			const active = await engine(
				`list-members?filterField=userId&filterValue=${reader.id}`,
				reader.cookie,
			);
			expect(await active.json()).toMatchObject({
				total: 1,
				members: [{ userId: reader.id }],
			});
			const date = new URLSearchParams({
				filterField: "createdAt",
				filterOperator: "gte",
				filterValue: "2000-01-01T00:00:00Z",
			});
			expect(
				await (await engine(`list-members?${date}`, reader.cookie)).json(),
			).toMatchObject({ total: 3 });
			const values = new URLSearchParams({
				filterField: "role",
				filterOperator: "in",
			});
			values.append("filterValue", "owner");
			values.append("filterValue", "member");
			expect(
				await (await engine(`list-members?${values}`, reader.cookie)).json(),
			).toMatchObject({ total: 2 });
			const denied = await engine(
				`list-members?organizationId=${selected.id}`,
				outsider.cookie,
			);
			expect(denied.status).toBe(403);
			expect(await denied.json()).toEqual(
				await (
					await native(
						request(
							`list-members?organizationId=${selected.id}`,
							outsider.cookie,
						),
					)
				).json(),
			);
			expect(
				(
					await owned({}, other)(
						`list-members?organizationId=${selected.id}`,
						owner.cookie,
					)
				).status,
			).toBe(401);
			expect(
				(await engine("list-members?sortBy=privateMetadata", reader.cookie))
					.status,
			).toBe(400);
		});

		it("interchanges native and owned team CRUD, role predicates and scoped team selection", async () => {
			const engine = owned();
			const owner = await account();
			const manager = await account();
			const reader = await account();
			const outsider = await account();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(outsider, engine);
			await role(selected.id, "team-manager", {
				team: ["create", "update"],
				member: ["update"],
			});
			await member(selected.id, manager.id, "team-manager");
			await member(selected.id, reader.id, "member");
			const deniedCreate = { organizationId: selected.id, name: "Denied team" };
			const denied = await engine("create-team", reader.cookie, deniedCreate);
			expect(denied.status).toBe(403);
			expect(await denied.json()).toEqual(
				await (
					await native(request("create-team", reader.cookie, deniedCreate))
				).json(),
			);
			const created = await engine("create-team", manager.cookie, {
				organizationId: selected.id,
				name: "Owned team",
			});
			expect(created.status).toBe(200);
			const first = (await created.json()) as { id: string };
			expect(Object.keys(first).sort()).toEqual([
				"createdAt",
				"id",
				"name",
				"organizationId",
				"updatedAt",
			]);
			const createdNative = await native(
				request("create-team", owner.cookie, { name: "Native team" }),
			);
			expect(createdNative.status).toBe(200);
			const second = (await createdNative.json()) as { id: string };
			const changed = await engine("update-team", manager.cookie, {
				teamId: second.id,
				data: { organizationId: selected.id, name: "Shared team" },
			});
			expect(changed.status).toBe(200);
			expect(await changed.json()).toEqual({ ...second, name: "Shared team" });
			const legacyChanged = await native(
				request("update-team", owner.cookie, {
					teamId: first.id,
					data: { name: "Legacy update" },
				}),
			);
			expect(legacyChanged.status).toBe(200);
			const list = `list-teams?organizationId=${selected.id}`;
			const currentList = await (await engine(list, reader.cookie)).json();
			const legacyList = (await (
				await native(request(list, reader.cookie))
			).json()) as unknown[];
			expect(currentList).toHaveLength(3);
			expect(currentList).toEqual(expect.arrayContaining(legacyList));
			expect(currentList).toContainEqual(await legacyChanged.json());
			const wrongOrg = await engine("update-team", owner.cookie, {
				teamId: foreign.teams[0]!.id,
				data: { organizationId: selected.id, name: "Wrong scope" },
			});
			expect(await wrongOrg.json()).toMatchObject({ code: "TEAM_NOT_FOUND" });
			const noRoster = await engine(
				`list-team-members?teamId=${first.id}`,
				owner.cookie,
			);
			expect(noRoster.status).toBe(400);
			expect(await noRoster.json()).toMatchObject({
				code: "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
			});
			const body = {
				organizationId: selected.id,
				teamId: first.id,
				userId: reader.id,
			};
			const nativeAdded = await native(
				request("add-team-member", owner.cookie, body),
			);
			expect(nativeAdded.status).toBe(200);
			const nativeMembership = (await nativeAdded.json()) as object;
			const duplicate = await engine("add-team-member", manager.cookie, body);
			expect(duplicate.status).toBe(200);
			expect(await duplicate.json()).toEqual(nativeMembership);
			expect(Object.keys(nativeMembership).sort()).toEqual([
				"createdAt",
				"id",
				"teamId",
				"userId",
			]);
			const added = await engine("add-team-member", manager.cookie, {
				...body,
				userId: manager.id,
			});
			expect(added.status).toBe(200);
			const rosterPath = `list-team-members?teamId=${first.id}`;
			const roster = (await (
				await engine(rosterPath, reader.cookie)
			).json()) as unknown[];
			const nativeRoster = (await (
				await native(request(rosterPath, reader.cookie))
			).json()) as unknown[];
			expect(roster).toHaveLength(2);
			expect(roster).toEqual(expect.arrayContaining(nativeRoster));
			expect(roster).toContainEqual(await added.json());
			const lookup = `list-user-teams?userId=${reader.id}&organizationId=${selected.id}`;
			const lookupOwned = await engine(lookup, manager.cookie);
			expect(lookupOwned.status).toBe(200);
			expect(await lookupOwned.json()).toEqual(
				await (await native(request(lookup, manager.cookie))).json(),
			);
			const forbiddenLookup = await engine(
				`list-user-teams?userId=${manager.id}&organizationId=${selected.id}`,
				reader.cookie,
			);
			expect(forbiddenLookup.status).toBe(403);
			expect(await forbiddenLookup.json()).toMatchObject({
				code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
			});
			const removeDenied = await engine(
				"remove-team-member",
				manager.cookie,
				body,
			);
			expect(removeDenied.status).toBe(403);
			expect(await removeDenied.json()).toEqual(
				await (
					await native(request("remove-team-member", manager.cookie, body))
				).json(),
			);
			await engine("set-active", reader.cookie, {
				organizationId: selected.id,
			});
			const select = await engine("set-active-team", reader.cookie, {
				teamId: first.id,
			});
			expect(select.status).toBe(200);
			expect(select.headers.get("set-cookie")).toContain(reader.cookie);
			expect(await select.json()).toMatchObject({ id: first.id });
			const nativeActiveRoster = await native(
				request("list-team-members", reader.cookie),
			);
			expect(nativeActiveRoster.status).toBe(200);
			expect(await nativeActiveRoster.json()).toEqual(
				expect.arrayContaining(roster),
			);
			const foreignSelection = await engine("set-active-team", reader.cookie, {
				teamId: foreign.teams[0]!.id,
			});
			expect(foreignSelection.status).toBe(400);
			expect(await foreignSelection.json()).toMatchObject({
				code: "TEAM_NOT_FOUND",
			});
			const clear = await engine("set-active-team", reader.cookie, {
				teamId: null,
			});
			expect(clear.headers.get("set-cookie")).toContain(reader.cookie);
			expect(await clear.json()).toBeNull();
			const empty = await engine("set-active-team", reader.cookie, {
				teamId: null,
			});
			expect(empty.headers.has("set-cookie")).toBe(false);
			expect(await empty.json()).toBeNull();
		});

		it("revokes exact team selections and preserves live organization grants and pending invitations", async () => {
			const engine = owned();
			const owner = await account();
			const target = await account();
			const otherMember = await account();
			const firstInvite = await account();
			const secondInvite = await account();
			const selected = await organizationFixture(owner, engine);
			const retained = selected.teams[0]!.id;
			await member(selected.id, target.id, "member");
			await member(selected.id, otherMember.id, "member");
			const created = await native(
				request("create-team", owner.cookie, { name: "To remove" }),
			);
			expect(created.status).toBe(200);
			const { id: teamId } = (await created.json()) as { id: string };
			const grant = await organizationGrant(selected.id, target);
			for (const user of [owner, target, otherMember]) {
				expect(
					(
						await engine("add-team-member", owner.cookie, {
							teamId,
							userId: user.id,
						})
					).status,
				).toBe(200);
				await engine("set-active", user.cookie, {
					organizationId: selected.id,
				});
				expect(
					(await engine("set-active-team", user.cookie, { teamId })).status,
				).toBe(200);
			}
			const activeTeam = async (account: Account) =>
				(
					await database.query(
						`SELECT "activeOrganizationId", "activeTeamId" FROM "${schema}".session WHERE id=$1`,
						[account.sessionId],
					)
				).rows[0];
			const activeDeletion = await engine("remove-team", owner.cookie, {
				teamId,
			});
			expect(activeDeletion.status).toBe(403);
			expect(await activeDeletion.json()).toMatchObject({
				code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
			});
			await engine("set-active-team", owner.cookie, { teamId: retained });
			const removed = await engine("remove-team-member", owner.cookie, {
				teamId,
				userId: target.id,
			});
			expect(await removed.json()).toEqual({
				message: "Team member removed successfully.",
			});
			expect(await activeTeam(target)).toEqual({
				activeOrganizationId: selected.id,
				activeTeamId: null,
			});
			expect(await activeTeam(otherMember)).toEqual({
				activeOrganizationId: selected.id,
				activeTeamId: teamId,
			});
			expect(await grantState(grant)).toEqual(activeGrant);
			const tally = await database.query(
				`SELECT "memberCount" FROM "${schema}".team WHERE id=$1`,
				[teamId],
			);
			expect(tally.rows).toEqual([{ memberCount: 2 }]);
			const combined = await invite(selected.id, owner, firstInvite, {
				teams: `${teamId},${retained}`,
			});
			const single = await invite(selected.id, owner, secondInvite, {
				teams: teamId,
			});
			const expired = await invite(selected.id, owner, secondInvite, {
				teams: teamId,
				expired: true,
			});
			const deletion = await engine("remove-team", owner.cookie, { teamId });
			expect(await deletion.json()).toEqual({
				message: "Team removed successfully.",
			});
			expect(await activeTeam(owner)).toEqual({
				activeOrganizationId: selected.id,
				activeTeamId: retained,
			});
			expect(await activeTeam(otherMember)).toEqual({
				activeOrganizationId: selected.id,
				activeTeamId: null,
			});
			expect(await grantState(grant)).toEqual(activeGrant);
			const invites = await database.query(
				`SELECT id,"teamId" FROM "${schema}".invitation WHERE id=ANY($1::text[])`,
				[[combined, single, expired]],
			);
			expect(
				Object.fromEntries(invites.rows.map((row) => [row.id, row.teamId])),
			).toEqual({ [combined]: retained, [single]: null, [expired]: teamId });
			const legacyAcceptance = await native(
				request("accept-invitation", firstInvite.cookie, {
					invitationId: combined,
				}),
			);
			expect(legacyAcceptance.status).toBe(200);
			const ownedAcceptance = await engine(
				"accept-invitation",
				secondInvite.cookie,
				{ invitationId: single },
			);
			expect(ownedAcceptance.status).toBe(200);
			const events = await database.query(
				`SELECT type,"targetId" FROM "${schema}"."allauthEvent"
				 WHERE ("organizationId"=$1 AND type='organization.team.removed')
				    OR ("targetId"=$2 AND type='organization.team.member-removed' AND "organizationId" IS NULL)`,
				[selected.id, target.id],
			);
			expect(events.rows).toEqual(
				expect.arrayContaining([
					{ type: "organization.team.member-removed", targetId: target.id },
					{ type: "organization.team.removed", targetId: teamId },
				]),
			);
		});

		it("serializes same-organization deletions and preserves the last team", async () => {
			const engine = owned();
			const owner = await account();
			const administrator = await account();
			const selected = await organizationFixture(owner, engine);
			await member(selected.id, administrator.id, "admin");
			const retained = selected.teams[0]!.id;
			const created = await engine("create-team", owner.cookie, {
				name: "Concurrent deletion",
			});
			expect(created.status).toBe(200);
			const { id } = (await created.json()) as { id: string };
			await engine("set-active-team", owner.cookie, { teamId: null });
			const results = await Promise.all([
				engine("remove-team", owner.cookie, {
					organizationId: selected.id,
					teamId: retained,
				}),
				engine("remove-team", administrator.cookie, {
					organizationId: selected.id,
					teamId: id,
				}),
			]);
			expect(results.map((response) => response.status).sort()).toEqual([
				200, 400,
			]);
			expect(
				await results.find((response) => !response.ok)!.json(),
			).toMatchObject({ code: "UNABLE_TO_REMOVE_LAST_TEAM" });
			const remaining = await (
				await native(request("list-teams", owner.cookie))
			).json();
			expect(remaining).toHaveLength(1);
		});

		it("updates organization data with the native dynamic permissions and duplicate-slug response", async () => {
			const engine = owned();
			const owner = await account();
			const editor = await account();
			const outsider = await account();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(outsider, engine);
			await member(selected.id, editor.id, "editor");
			await role(selected.id, "editor", { organization: ["update"] });
			const input = {
				organizationId: selected.id,
				data: {
					name: "Updated name",
					logo: null,
					metadata: { profile: { visible: true } },
				},
			};
			const old = await native(request("update", editor.cookie, input));
			expect(old.status).toBe(200);
			const updated = await engine("update", editor.cookie, input);
			expect(updated.status).toBe(200);
			expect(await updated.json()).toEqual(await old.json());
			expect((await engine("update", outsider.cookie, input)).status).toBe(400);
			const conflict = {
				organizationId: selected.id,
				data: { slug: foreign.slug },
			};
			const legacyConflict = await native(
				request("update", editor.cookie, conflict),
			);
			const ownedConflict = await engine("update", editor.cookie, conflict);
			expect(ownedConflict.status).toBe(legacyConflict.status);
			expect(await ownedConflict.json()).toEqual(await legacyConflict.json());
			const audit = await database.query(
				`SELECT "actorId","organizationId",outcome FROM "${schema}"."allauthEvent"
				 WHERE type='organization.updated' AND "organizationId"=$1 ORDER BY "createdAt"`,
				[selected.id],
			);
			expect(audit.rows).toEqual(
				["success", "success", "failure", "failure", "failure"].map(
					(outcome) => ({
						actorId: null,
						organizationId: selected.id,
						outcome,
					}),
				),
			);
		});

		it("updates roles and removes members using legacy response shapes and scoped revocation", async () => {
			const engine = owned();
			const owner = await account();
			const target = await account();
			const other = await account();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(other, engine);
			const targetId = await member(selected.id, target.id, "member");
			const foreignId = await member(foreign.id, target.id, "member");
			const teamId = selected.teams[0]!.id;
			await database.query(
				`INSERT INTO "${schema}"."teamMember"(id,"teamId","userId","createdAt") VALUES ($1,$2,$3,now())`,
				[randomUUID(), teamId, target.id],
			);
			await database.query(
				`UPDATE "${schema}".team SET "memberCount"=2 WHERE id=$1`,
				[teamId],
			);
			await database.query(
				`UPDATE "${schema}".session SET "activeOrganizationId"=$2,"activeTeamId"=$3 WHERE id=$1`,
				[target.sessionId, selected.id, teamId],
			);
			const scoped = await organizationGrant(selected.id, target);
			const unrelatedOrganization = await organizationGrant(foreign.id, target);
			const unrelatedMember = await organizationGrant(selected.id, owner);
			await role(selected.id, "editor", { organization: ["update"] });
			const denied = await engine("update-member-role", owner.cookie, {
				organizationId: selected.id,
				memberId: foreignId,
				role: "admin",
			});
			expect(denied.status).toBe(403);
			const roleChange = {
				organizationId: selected.id,
				memberId: targetId,
				role: [" editor ", "member"],
			};
			const expected = await native(
				request("update-member-role", owner.cookie, roleChange),
			);
			expect(expected.status).toBe(200);
			await database.query(
				`UPDATE "${schema}".member SET role='member' WHERE id=$1`,
				[targetId],
			);
			const updated = await engine(
				"update-member-role",
				owner.cookie,
				roleChange,
			);
			expect(updated.status, await updated.clone().text()).toBe(200);
			expect(await updated.json()).toEqual(await expected.json());
			expect(await grantState(scoped)).toEqual(revokedGrant);
			expect(await grantState(unrelatedOrganization)).toEqual(activeGrant);
			expect(await grantState(unrelatedMember)).toEqual(activeGrant);

			const newlyGranted = await organizationGrant(selected.id, target);
			const pending = await invite(selected.id, owner, other);
			const removed = await engine("remove-member", owner.cookie, {
				organizationId: selected.id,
				memberIdOrEmail: target.email.toUpperCase(),
			});
			expect(removed.status, await removed.clone().text()).toBe(200);
			expect(await removed.json()).toMatchObject({
				member: {
					id: targetId,
					role: "editor,member",
					user: { id: target.id, email: target.email },
				},
			});
			expect(await grantState(newlyGranted)).toEqual(revokedGrant);
			expect(await grantState(unrelatedOrganization)).toEqual(activeGrant);
			expect(await grantState(unrelatedMember)).toEqual(activeGrant);
			const records = await database.query(
				`SELECT s."activeOrganizationId",s."activeTeamId",t."memberCount",i.status
				 FROM "${schema}".session s CROSS JOIN "${schema}".team t CROSS JOIN "${schema}".invitation i
				 WHERE s.id=$1 AND t.id=$2 AND i.id=$3`,
				[target.sessionId, teamId, pending],
			);
			expect(records.rows).toEqual([
				{
					activeOrganizationId: null,
					activeTeamId: null,
					memberCount: 1,
					status: "pending",
				},
			]);
			expect(
				(
					await native(
						request(
							`get-full-organization?organizationId=${selected.id}`,
							target.cookie,
						),
					)
				).status,
			).toBe(403);
			expect(
				(
					await native(
						request(
							`get-full-organization?organizationId=${foreign.id}`,
							target.cookie,
						),
					)
				).status,
			).toBe(200);
		});

		it("serializes concurrent departures and demotions without losing the last owner", async () => {
			const engine = owned();
			const first = await account();
			const second = await account();
			const selected = await organizationFixture(first, engine);
			const secondId = await member(selected.id, second.id, "owner,admin");
			const results = await Promise.all([
				engine("leave", first.cookie, { organizationId: selected.id }),
				engine("update-member-role", second.cookie, {
					organizationId: selected.id,
					memberId: secondId,
					role: "admin",
				}),
			]);
			expect(results.map((response) => response.status).sort()).toEqual([
				200, 400,
			]);
			const owners = await database.query(
				`SELECT "userId" FROM "${schema}".member WHERE "organizationId"=$1 AND 'owner'=ANY(string_to_array(role,','))`,
				[selected.id],
			);
			expect(owners.rows).toHaveLength(1);
			const last = owners.rows[0]?.userId === first.id ? first : second;
			const expected = await native(
				request("leave", last.cookie, { organizationId: selected.id }),
			);
			const replacement = await engine("leave", last.cookie, {
				organizationId: selected.id,
			});
			expect(replacement.status).toBe(expected.status);
			expect(await replacement.json()).toEqual(await expected.json());
		});

		it("deletes only the selected organization's data and preserves configured enterprise authority", async () => {
			const engine = owned();
			const owner = await account();
			const invited = await account();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(owner, engine);
			await engine("set-active", owner.cookie, { organizationId: selected.id });
			const invitation = await invite(selected.id, owner, invited);
			const otherInvitation = await invite(foreign.id, owner, invited);
			const grant = await organizationGrant(selected.id, owner);
			const otherGrant = await organizationGrant(foreign.id, owner);
			const provider = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."ssoProvider"(id,issuer,"providerId","userId","organizationId",domain)
				 VALUES ($1,'https://sso.fixture.example',$1,$2,$3,'fixture.example')`,
				[provider, owner.id, selected.id],
			);
			const guarded = await engine("delete", owner.cookie, {
				organizationId: selected.id,
			});
			expect(guarded.status).toBe(409);
			expect(await guarded.json()).toMatchObject({
				code: "ORGANIZATION_ENTERPRISE_CONFIGURATION_ACTIVE",
			});
			expect(await grantState(grant)).toEqual(activeGrant);
			await database.query(
				`DELETE FROM "${schema}"."ssoProvider" WHERE id=$1`,
				[provider],
			);
			const deleted = await engine("delete", owner.cookie, {
				organizationId: selected.id,
			});
			expect(deleted.status, await deleted.clone().text()).toBe(200);
			expect(await deleted.json()).toMatchObject({
				id: selected.id,
				slug: selected.slug,
				metadata: '{"example":true}',
			});
			expect(await grantState(grant)).toEqual(revokedGrant);
			expect(await grantState(otherGrant)).toEqual(activeGrant);
			const rows = await database.query(
				`SELECT id FROM "${schema}".invitation WHERE id=ANY($1::text[])`,
				[[invitation, otherInvitation]],
			);
			expect(rows.rows).toEqual([{ id: otherInvitation }]);
			expect(
				await (await native(request("list", owner.cookie))).json(),
			).toMatchObject([{ id: foreign.id }]);
			const session = await database.query(
				`SELECT "activeOrganizationId","activeTeamId" FROM "${schema}".session WHERE id=$1`,
				[owner.sessionId],
			);
			expect(session.rows).toEqual([
				{ activeOrganizationId: null, activeTeamId: null },
			]);
		});

		it("matches native static and dynamic permission composition, scoping and immediate revocation", async () => {
			const owner = await account();
			const subject = await account();
			const stranger = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(owner, engine);
			await member(selected.id, subject.id, "operator,reporter");
			await role(selected.id, "operator", { invitation: ["create"] });
			const editable = await role(selected.id, "operator", {
				organization: ["update"],
			});
			await role(selected.id, "reporter", { team: ["delete"] });
			await role(foreign.id, "operator", { organization: ["delete"] });
			for (const { actor, input, allowed } of [
				{
					actor: subject,
					input: {
						permissions: { invitation: ["create"], organization: ["update"] },
					},
					allowed: true,
				},
				{
					actor: subject,
					input: { permissions: { invitation: ["create"], team: ["delete"] } },
					allowed: false,
				},
				{
					actor: subject,
					input: { permissions: { organization: ["delete"] } },
					allowed: false,
				},
				{
					actor: subject,
					input: { permissions: { organization: [] } },
					allowed: false,
				},
				{
					actor: owner,
					input: { permissions: { organization: ["update", "delete"] } },
					allowed: true,
				},
				{
					actor: owner,
					input: { permission: { invitation: ["create"] } },
					allowed: false,
				},
			]) {
				const body = { organizationId: selected.id, ...input };
				const legacy = await native(
					request("has-permission", actor.cookie, body),
				);
				const replacement = await engine("has-permission", actor.cookie, body);
				expect(replacement.status).toBe(200);
				expect(await replacement.json()).toEqual({
					success: allowed,
					error: null,
				});
				expect(await legacy.json()).toEqual({ success: allowed, error: null });
			}
			const foreignPermission = {
				organizationId: foreign.id,
				permissions: { organization: ["delete"] },
			};
			expect(
				(await engine("has-permission", subject.cookie, foreignPermission))
					.status,
			).toBe(401);
			expect(
				(await engine("has-permission", stranger.cookie, { permissions: {} }))
					.status,
			).toBe(400);
			await database.query(
				`UPDATE "${schema}"."organizationRole" SET permission = '{}' WHERE id = $1`,
				[editable],
			);
			expect(
				await (
					await engine("has-permission", subject.cookie, {
						organizationId: selected.id,
						permissions: { organization: ["update"] },
					})
				).json(),
			).toEqual({ success: false, error: null });
		});

		it("sends the existing hosted email after commit and lets the native engine accept the new invitation", async () => {
			const owner = await account();
			const inviter = await account();
			const recipient = await account();
			const messages: { to: string; text: string; subject: string }[] = [];
			const send = createOwnedProjectInvitationEmail({
				env: {
					EMAIL_PROVIDER: "cloudflare",
					EMAIL_FROM: "security@fixture.example",
					EMAIL: {
						async send(message) {
							messages.push(message);
						},
					},
				},
				project: { slug: "organization-fixture", primaryOrigin: appOrigin },
				publicOrigin: origin,
				async readBranding() {
					return defaultApplicationBranding("Branded fixture");
				},
			});
			const engine = owned({
				invitationEmail: {
					async send(notification) {
						const committed = await database.query(
							`SELECT status FROM "${schema}".invitation WHERE id = $1`,
							[notification.invitation.id],
						);
						expect(committed.rows).toEqual([{ status: "pending" }]);
						await send.send(notification);
					},
					onFailure() {
						throw new Error("Fixture mail should succeed");
					},
				},
			});
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			await role(selected.id, "inviter", { invitation: ["create"] });
			await role(selected.id, "editor", { organization: ["update"] });
			await member(selected.id, inviter.id, "inviter");
			const created = await engine("invite-member", inviter.cookie, {
				email: recipient.email.toUpperCase(),
				role: ["editor", "member"],
				teamId: [teamId],
				organizationId: selected.id,
				inviterId: owner.id,
			});
			expect(created.status).toBe(200);
			const invitation = (await created.json()) as InvitationRecord;
			expect(invitation).toMatchObject({
				email: recipient.email,
				role: "editor,member",
				teamId,
				inviterId: inviter.id,
				status: "pending",
			});
			expect(messages).toHaveLength(1);
			expect(messages[0]).toMatchObject({
				to: recipient.email,
				subject: `You've been invited to ${selected.name} on Branded fixture`,
			});
			expect(messages[0]!.text).toContain(
				`${origin}/accept-invitation/${invitation.id}`,
			);
			const accepted = await native(
				request("accept-invitation", recipient.cookie, {
					invitationId: invitation.id,
				}),
			);
			expect(accepted.status).toBe(200);
			expect(await accepted.json()).toMatchObject({
				invitation: { status: "accepted" },
				member: { role: "editor,member", userId: recipient.id },
			});
			expect(
				(
					await engine("cancel-invitation", owner.cookie, {
						invitationId: invitation.id,
					})
				).status,
			).toBe(400);
			const committed = await database.query(
				`SELECT status FROM "${schema}".invitation WHERE id = $1`,
				[invitation.id],
			);
			expect(committed.rows).toEqual([{ status: "accepted" }]);
		});

		it("renews a native invitation without changing its grant and cancels it only with live permission", async () => {
			const owner = await account();
			const operator = await account();
			const recipient = await account();
			const deliveries: { inviter: string; id: string }[] = [];
			let deliveryFailures = 0;
			const engine = owned({
				invitationEmail: {
					async send({ inviter, invitation }) {
						deliveries.push({ inviter: inviter.email, id: invitation.id });
						throw new Error("Fixture transport unavailable");
					},
					onFailure() {
						deliveryFailures++;
					},
				},
			});
			const selected = await organizationFixture(owner, engine);
			const teamId = selected.teams[0]!.id;
			const custom = await role(selected.id, "invitation-operator", {
				invitation: ["create"],
			});
			await member(selected.id, operator.id, "invitation-operator");
			const nativeInvite = await native(
				request("invite-member", owner.cookie, {
					email: recipient.email,
					role: "member",
					organizationId: selected.id,
					teamId,
				}),
			);
			expect(nativeInvite.status).toBe(200);
			const original = (await nativeInvite.json()) as InvitationRecord;
			await database.query(
				`UPDATE "${schema}".invitation SET "expiresAt" = statement_timestamp() + interval '1 hour' WHERE id = $1`,
				[original.id],
			);
			const payload = {
				email: recipient.email,
				role: "admin",
				organizationId: selected.id,
			};
			const duplicate = await engine("invite-member", operator.cookie, payload);
			expect(await duplicate.json()).toMatchObject({
				code: "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
			});
			const renewed = await engine("invite-member", operator.cookie, {
				...payload,
				resend: true,
			});
			expect(renewed.status).toBe(200);
			const persisted = (await renewed.json()) as InvitationRecord;
			expect(persisted).toMatchObject({
				id: original.id,
				inviterId: owner.id,
				role: "member",
				teamId,
				status: "pending",
			});
			expect(
				new Date(persisted.expiresAt).getTime() - Date.now(),
			).toBeGreaterThan(47 * 3600 * 1000);
			expect(deliveries).toEqual([
				{ inviter: operator.email, id: original.id },
			]);
			expect(deliveryFailures).toBe(1);
			const cancel = { invitationId: original.id };
			expect(
				(await engine("cancel-invitation", operator.cookie, cancel)).status,
			).toBe(403);
			await database.query(
				`UPDATE "${schema}"."organizationRole" SET permission = '{"invitation":["cancel"]}' WHERE id = $1`,
				[custom],
			);
			const canceled = await engine(
				"cancel-invitation",
				operator.cookie,
				cancel,
			);
			expect(canceled.status).toBe(200);
			expect(await canceled.json()).toMatchObject({
				id: original.id,
				status: "canceled",
			});
			expect(
				(await native(request("accept-invitation", recipient.cookie, cancel)))
					.status,
			).toBe(400);
		});

		it("serializes the native pending invitation quota and enforces the owner and team boundaries", async () => {
			const owner = await account();
			const admin = await account();
			const first = await account();
			const second = await account();
			const engine = owned();
			const selected = await organizationFixture(owner, engine);
			const foreign = await organizationFixture(owner, engine);
			await member(selected.id, admin.id, "admin");
			const invalidOwner = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: " owner",
			});
			expect(invalidOwner.status).toBe(403);
			const invalidTeam = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: "member",
				teamId: foreign.teams[0]!.id,
			});
			expect(await invalidTeam.json()).toMatchObject({
				code: "TEAM_NOT_FOUND",
			});
			const separatedTeams = await engine("invite-member", admin.cookie, {
				organizationId: selected.id,
				email: first.email,
				role: "member",
				teamId: "fixture,foreign",
			});
			expect(await separatedTeams.json()).toMatchObject({
				code: "INVALID_TEAM_ID",
			});
			await database.query(
				`INSERT INTO "${schema}".invitation (id,"organizationId",email,role,status,"expiresAt","inviterId")
			 SELECT $1 || n::text,$2,n::text || '@quota.fixture.example','member','pending',statement_timestamp() + interval '1 day',$3 FROM generate_series(1,99) n`,
				[randomUUID(), selected.id, owner.id],
			);
			await invite(selected.id, owner, first, { expired: true });
			const both = await Promise.all([
				engine("invite-member", owner.cookie, {
					organizationId: selected.id,
					email: first.email,
					role: "member",
				}),
				engine("invite-member", admin.cookie, {
					organizationId: selected.id,
					email: second.email,
					role: "member",
				}),
			]);
			expect(both.map((response) => response.status).sort()).toEqual([
				200, 403,
			]);
			expect(await both.find((response) => !response.ok)!.json()).toMatchObject(
				{ code: "INVITATION_LIMIT_REACHED" },
			);
			const count = await database.query(
				`SELECT count(*)::int AS total FROM "${schema}".invitation WHERE "organizationId" = $1 AND status = 'pending' AND "expiresAt" > statement_timestamp()`,
				[selected.id],
			);
			expect(count.rows).toEqual([{ total: 100 }]);
		});
	},
);
