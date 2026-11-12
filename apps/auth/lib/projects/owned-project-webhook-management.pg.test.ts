import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { oauthProvider } from "@better-auth/oauth-provider";
import { APIError, betterAuth } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import {
	admin,
	anonymous,
	haveIBeenPwned,
	jwt,
	multiSession,
	organization,
} from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuthOptions } from "../auth";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { recordControlEvent } from "../control/events";
import { defaultSecurityPolicy } from "../control/security-policy";
import type { ControlPrincipal } from "../control/types";
import type {
	ControlWebhookDelivery,
	ControlWebhookEndpoint,
} from "../control/webhook-contract";
import {
	webhookDeliveryInput,
	webhookEndpointInput,
	webhookEventTypes,
	webhookSignature,
} from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import {
	createControlWebhooks,
	deliverPendingWebhooks,
} from "../control/webhooks";
import type { EmailEnvironment } from "../email/send";
import {
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "../enterprise";
import { featureBoundaries } from "../features/server";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { projectManagement } from "./management-plugin";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";
import { checkProjectOidcConfiguration } from "./owned-project-sso-oidc";
import { checkProjectSamlConfiguration } from "./owned-project-sso-saml-eligibility";
import { projectSecret } from "./runtime";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://webhook-management.fixture.example";
const password = "Disposable-webhook-management-7!";
const platformSecret = "disposable-webhook-management-platform-secret";
const rootId = "fixture-webhook-owner";
const userId = "fixture-webhook-user";
const ownerEmail = "owner@webhook-management.fixture.example";
const userEmail = "account@webhook-management.fixture.example";
const eventUserId = "fixture-webhook-event-user";
const eventEmail = "event-account@webhook-management.fixture.example";
const resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const base = "/control/webhooks";
const migrations = [
	"001-initial-auth",
	"002-control-plane",
	"004-webhooks",
	"005-free-plugins",
	"006-analytics",
];

function realm(slug: string, workspaceId = randomUUID()) {
	const id = randomUUID();
	return {
		id,
		slug,
		workspaceId,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		path: `/api/projects/${slug}/auth`,
		secret: projectSecret({ ALLAUTH_AUTH_SECRET: platformSecret }, id),
	};
}

const alpha = realm("fixture-webhook-management");
const beta = realm(
	"fixture-webhook-control",
	"00000000-0000-4000-8000-000000000001",
);

it("accepts persisted delivery identifiers independently of endpoint UUIDs", () => {
	const id = "aaaaaaaa-aaaa-daaa-0aaa-aaaaaaaaaaaa";
	expect(webhookDeliveryInput.safeParse({ id }).success).toBe(true);
	expect(webhookEndpointInput.safeParse({ id }).success).toBe(false);
});

function request(
	path: string,
	body?: object,
	cookie?: string,
	caller = origin,
) {
	return new Request(`${origin}${path}`, {
		method: body ? "POST" : "GET",
		headers: {
			origin: caller,
			"user-agent": "webhook-management-fixture",
			"x-real-ip": "192.0.2.46",
			...(body ? { "content-type": "application/json" } : {}),
			...(cookie ? { cookie } : {}),
		},
		body: body ? JSON.stringify(body) : undefined,
	});
}

type NativeDatabase = Kysely<Record<string, Record<string, unknown>>>;
async function native(
	database: NativeDatabase,
	realm?: typeof alpha,
	readRoot?: (headers: Headers) => Promise<ControlPrincipal | null>,
) {
	const control = allauthControl({
		ipHeader: "x-real-ip",
		...(realm && readRoot
			? {
					database,
					authorizeAdmin: readRoot,
					async onRevokeUser(adapter, id) {
						await revokeUserGrants(adapter, id);
						await revokeAuthenticationChallenges(adapter, id);
					},
				}
			: {}),
	});
	const webhooks =
		realm &&
		createControlWebhooks({
			database,
			secret: realm.secret,
			baseURL: origin,
			resolver,
			async requireAdmin(ctx) {
				const actor = await readRoot?.(ctx.headers ?? new Headers());
				if (!actor) throw new APIError("FORBIDDEN");
				return actor;
			},
			recordEvent: (ctx, event) => recordControlEvent(ctx, event, "x-real-ip"),
		});
	const { auth } = await getTestInstance(
		{
			database: { db: database, type: "postgres", transaction: true },
			baseURL: origin,
			basePath: realm?.path ?? "/api/auth",
			secret: realm?.secret ?? platformSecret,
			logger: { disabled: true },
			advanced: {
				cookiePrefix: realm ? `allauth_project_${realm.slug}` : "better-auth",
				disableOriginCheck: false,
			},
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			plugins: [
				admin(),
				...(realm
					? [
							featureBoundaries(),
							haveIBeenPwned({ paths: ["/change-password"] }),
							organization(),
							projectManagement({
								projectId: realm.id,
								baseURL: origin,
								async requirePlatformAdmin(ctx) {
									const actor = await readRoot?.(ctx.headers ?? new Headers());
									if (!actor) throw new APIError("FORBIDDEN");
									return actor;
								},
								async onRevokeUser(adapter, id) {
									await revokeUserGrants(adapter, id);
									await revokeAuthenticationChallenges(adapter, id);
								},
							}),
							jwt({ disableSettingJwtHeader: true }),
							oauthProvider({
								loginPage: "/sign-in",
								consentPage: "/oauth/consent",
							}),
						]
					: []),
				{
					...control,
					endpoints: { ...control.endpoints, ...webhooks?.endpoints },
				},
				...(realm
					? [
							anonymous(),
							authPolicyPlugin(defaultAuthPolicy),
							multiSession({ maximumSessions: 5 }),
						]
					: []),
			],
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixture))(
	"isolated PostgreSQL project webhook management",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const pools: Pool[] = [];
		let administrator: Pool;
		let database: Pool;
		let projectDatabase: NativeDatabase;
		let platform: Awaited<ReturnType<typeof native>>;
		let legacy: Awaited<ReturnType<typeof native>>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let other: ReturnType<typeof createOwnedProjectEngine>;
		let rotatedAuthSigningKey: ReturnType<typeof createOwnedProjectEngine>;
		let rootCookie: string;
		let created = false;

		function installedNative(
			policy = defaultAuthPolicy,
			authorizeAdmin = readRoot,
			email?: EmailEnvironment["EMAIL"],
		) {
			const options = createAuthOptions(
				{ db: projectDatabase, type: "postgres", transaction: true },
				{
					ALLAUTH_AUTH_URL: origin,
					ALLAUTH_AUTH_SECRET: alpha.secret,
					AUTH_RUNTIME: "node",
					SCIM_CREDENTIAL_HASH_SECRET: "synthetic-webhook-mutation-fixture-key",
					EMAIL_PROVIDER: "cloudflare",
					CLOUDFLARE_ACCOUNT_ID: "",
					CLOUDFLARE_EMAIL_API_TOKEN: "",
					...(email
						? { EMAIL_FROM: "security@webhook-management.fixture.example", EMAIL: email }
						: {}),
				},
				{
					name: "Webhook project fixture",
					basePath: alpha.path,
					cookiePrefix: `allauth_project_${alpha.slug}`,
					primaryOrigin: origin,
					publicOrigin: origin,
					origins: [],
					broker: {
						clientId: "fixture-broker",
						clientSecret: "synthetic-broker-secret",
					},
					authorizeAdmin,
					management: { id: "webhook-project-fixture" },
				},
				policy,
			);
			return betterAuth({ ...options, logger: { disabled: true } });
		}

		async function readRoot(
			headers: Headers,
		): Promise<ControlPrincipal | null> {
			const value = await runWithAdapter(
				(await platform.$context).adapter,
				() =>
					platform.api.getSession({
						headers,
						query: { disableCookieCache: true },
					}),
			);
			if (!value) return null;
			return {
				user: {
					...value.user,
					role: value.user.role ?? undefined,
					banned: value.user.banned ?? undefined,
				},
				session: {
					id: value.session.id,
					userId: value.session.userId,
					impersonatedBy: value.session.impersonatedBy ?? undefined,
				},
			};
		}

		beforeAll(async () => {
			const config = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(config.DATABASE_URL);
			if (
				config.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Webhook management requires isolated fixture PostgreSQL.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			pools.push(database);
			const migrate = (migration: string) =>
				readFileSync(
					new URL(`../../migrations/${migration}.sql`, import.meta.url),
					"utf8",
				);
			const client = await database.connect();
			try {
				for (const migration of [
					...migrations,
					"003-projects",
					"008-application-environments",
					"009-workspaces",
				])
					await client.query(migrate(migration));
				for (const project of [alpha, beta]) {
					await client.query(`CREATE SCHEMA "${project.schemaName}"`);
					await client.query(`SET search_path TO "${project.schemaName}"`);
					for (const migration of [
						...migrations,
						"016-invitation-import-provenance",
					])
						await client.query(migrate(migration));
				}
				await client.query("SET search_path TO public");
			} finally {
				client.release();
			}
			const hash = await clerkCompatiblePasswords.hash(password);
			for (const [schema, user, email] of [
				["public", rootId, ownerEmail],
				[alpha.schemaName, userId, userEmail],
				[alpha.schemaName, eventUserId, eventEmail],
			]) {
				await database.query(
					`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role)
				 VALUES ($1,$1,$2,true,'user')`,
					[user, email],
				);
				await database.query(
					`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt")
				 VALUES ($1,$2,'credential',$2,$3,now())`,
					[randomUUID(), user, hash],
				);
			}
			await database.query(
				`INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") VALUES ($1,'Webhook workspace','webhook-management-workspace',$2)`,
				[alpha.workspaceId, rootId],
			);
			await database.query(
				`INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,'owner')`,
				[randomUUID(), alpha.workspaceId, rootId],
			);
			for (const project of [alpha, beta])
				await database.query(
					`INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId")
				 VALUES ($1,$2,$2,$3,$4,'fixture','fixture','1',$5,$1,'development',$6)`,
					[
						project.id,
						project.slug,
						project.schemaName,
						origin,
						rootId,
						project.workspaceId,
					],
				);
			const rootPool = new Pool({
				connectionString: url.href,
				max: 2,
				options: "-c search_path=public",
			});
			const projectPool = new Pool({
				connectionString: url.href,
				max: 3,
				options: `-c search_path=${alpha.schemaName}`,
			});
			pools.push(rootPool, projectPool);
			platform = await native(
				new Kysely({ dialect: new PostgresDialect({ pool: rootPool }) }),
			);
			projectDatabase = new Kysely({
				dialect: new PostgresDialect({ pool: projectPool }),
			});
			legacy = await native(projectDatabase, alpha, readRoot);
			const signed = await platform.handler(
				request("/api/auth/sign-in/email", { email: ownerEmail, password }),
			);
			expect(signed.status).toBe(200);
			rootCookie = signed.headers
				.getSetCookie()
				.map((value) => value.split(";", 1)[0])
				.join("; ");
			expect(
				await readRoot(new Headers({ cookie: rootCookie })),
			).not.toBeNull();
			const engine = (project: typeof alpha, signingSecret = project.secret) =>
				createOwnedProjectEngine({
					database,
					project,
					baseURL: origin,
					basePath: project.path,
					signingSecret,
					policy: defaultAuthPolicy,
					trustedOrigins: [],
					trustedIP: () => "192.0.2.46",
					adminDeletion: {
						id: project.id,
						workspaceId: project.workspaceId,
						platformOrigin: origin,
						readWorkspacePrincipal: readRoot,
					},
					webhookManagement: {
						resolver,
						encryptionSecret: project.secret,
						supportedEventTypes: webhookEventTypes,
					},
					passwordChange: {
						checkPasswordSafety: createOwnedProjectPasswordSafety(),
					},
				});
			owned = engine(alpha);
			other = engine(beta);
			rotatedAuthSigningKey = engine(
				alpha,
				"synthetic-rotated-project-auth-signing-key",
			);
		});

		afterAll(async () => {
			try {
				await Promise.all(pools.map((pool) => pool.end()));
				if (created) await dropClosedFixtureDatabase(administrator, name);
			} finally {
				await administrator?.end();
			}
		});

		function send(
			engine: "legacy" | "owned",
			path = base,
			body?: object,
			cookie = rootCookie,
			caller = origin,
		) {
			const input = request(alpha.path + path, body, cookie, caller);
			return engine === "legacy"
				? legacy.handler(input)
				: owned.dispatch(input);
		}
		it("preserves workspace, self and organization access to the project control read routes", async () => {
			const signedIn = await legacy.handler(
				request(`${alpha.path}/sign-in/email`, {
					email: userEmail,
					password,
				}),
			);
			expect(signedIn.status).toBe(200);
			const projectCookie = signedIn.headers
				.getSetCookie()
				.map((cookie) => cookie.split(";", 1)[0])
				.join("; ");
			const organizationId = "fixture-control-read-organization";
			const eventId = "fixture-control-read-event";
			await database.query(
				`INSERT INTO "${alpha.schemaName}".organization (id,name,slug,"createdAt")
				 VALUES ($1,'Control read fixture','control-read-fixture',now())`,
				[organizationId],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}".member (id,"organizationId","userId",role,"createdAt")
				 VALUES ($1,$2,$3,'owner',now()),($4,$2,$5,'member',now())`,
				[randomUUID(), organizationId, userId, randomUUID(), eventUserId],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."allauthEvent"(id,type,outcome,"userId","organizationId","createdAt",metadata)
				 VALUES ($1,'fixture.control-read','success',$2,$3,now(),'{"path":"/fixture"}')`,
				[eventId, userId, organizationId],
			);
			const catalog = [
				["/control/overview", rootCookie],
				[`/control/sessions?userId=${userId}`, rootCookie],
				["/control/events?scope=admin&type=fixture.control-read", rootCookie],
				["/control/events?type=fixture.control-read", projectCookie],
				[
					`/control/logs?scope=organization&organizationId=${organizationId}&q=fixture.control-read`,
					projectCookie,
				],
				[`/control/logs/detail?id=${eventId}`, projectCookie],
			] as const;
			for (const [path, cookie] of catalog) {
				const nativeResult = await send("legacy", path, undefined, cookie);
				const ownedResult = await send("owned", path, undefined, cookie);
				expect(nativeResult.status, await nativeResult.clone().text()).toBe(
					200,
				);
				expect(ownedResult.status, await ownedResult.clone().text()).toBe(200);
				expect(ownedResult.headers.get("cache-control")).toBe("no-store");
				const body = await ownedResult.text();
				expect(JSON.parse(body)).toEqual(await nativeResult.json());
				expect(body).not.toContain('"token"');
			}

			for (const [path, cookie, expected] of [
				["/control/overview", projectCookie, 403],
				[`/control/events?userId=${eventUserId}`, projectCookie, 403],
				[
					`/control/logs/detail?id=${eventId}&organizationId=${organizationId}`,
					projectCookie,
					400,
				],
				["/control/logs/detail?id=missing-fixture-event", projectCookie, 404],
				["/control/events?type=fixture.control-read", "", 401],
			] as const) {
				expect((await send("legacy", path, undefined, cookie)).status).toBe(
					expected,
				);
				expect((await send("owned", path, undefined, cookie)).status).toBe(
					expected,
				);
			}
			expect(
				(
					await other.dispatch(
						request(`${beta.path}/control/overview`, undefined, rootCookie),
					)
				).status,
			).toBe(403);
			await database.query(
				`UPDATE "${alpha.schemaName}".member SET role='member' WHERE "organizationId"=$1 AND "userId"=$2`,
				[organizationId, userId],
			);
			for (const writer of ["legacy", "owned"] as const)
				expect(
					(await send(writer, catalog[4][0], undefined, projectCookie)).status,
				).toBe(403);
		});

		it("revokes one console session, associated user grants and challenges with native event parity", async () => {
			const path = "/control/revoke-session";
			const id = "fixture-control-revoked-session";
			const sibling = "fixture-control-surviving-session";
			const clientId = "fixture-control-revoke-client";
			const grantId = "fixture-control-revoke-grant";
			const realm = `"${alpha.schemaName}"`;
			await database.query(
				`INSERT INTO ${realm}."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
				[clientId],
			);
			const seed = async () => {
				await database.query(
					`INSERT INTO ${realm}.session(id,token,"userId","expiresAt","updatedAt")
					 VALUES ($1,$2,$3,now()+interval '1 hour',now()),
					        ($4,$5,$3,now()+interval '1 hour',now())`,
					[id, randomUUID(), userId, sibling, randomUUID()],
				);
				await database.query(
					`INSERT INTO ${realm}."oauthRefreshToken"(id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
					 VALUES ($1,$2,$3,$4,$5,now()+interval '1 hour',now(),'["offline_access"]')`,
					[grantId, randomUUID(), clientId, sibling, userId],
				);
				await database.query(
					`INSERT INTO ${realm}.verification(id,identifier,value,"expiresAt")
					 VALUES ($1,'trust-device-fixture',$2,now()+interval '1 hour')`,
					[grantId, userId],
				);
			};
			const events = async () =>
				(
					await database.query(
						`SELECT id,type,outcome,"actorId","userId","targetId","ipAddress","userAgent",metadata
				 FROM ${realm}."allauthEvent" WHERE "targetId"=$1 ORDER BY type,id`,
						[id],
					)
				).rows;
			const state = async () =>
				(
					await database.query(
						`SELECT EXISTS(SELECT 1 FROM ${realm}.session WHERE id=$1) AS target,
				        EXISTS(SELECT 1 FROM ${realm}.session WHERE id=$2) AS sibling,
				        EXISTS(SELECT 1 FROM ${realm}."oauthRefreshToken" WHERE id=$3) AS grant,
				        EXISTS(SELECT 1 FROM ${realm}.verification WHERE id=$3) AS challenge`,
						[id, sibling, grantId],
					)
				).rows[0];

			const run = async (writer: "legacy" | "owned") => {
				await seed();
				const prior = new Set((await events()).map((event) => event.id));
				expect(
					(
						await send(
							writer,
							path,
							{ id },
							rootCookie,
							"https://other.fixture.example",
						)
					).status,
				).toBe(403);
				const response = await send(writer, path, { id });
				expect(response.status, await response.clone().text()).toBe(200);
				expect(await response.json()).toEqual({ success: true });
				expect(await state()).toEqual({
					target: false,
					sibling: true,
					grant: false,
					challenge: false,
				});
				expect((await send(writer, path, { id })).status).toBe(404);
				await database.query(`DELETE FROM ${realm}.session WHERE id=$1`, [
					sibling,
				]);
				return (await events())
					.filter((event) => !prior.has(event.id))
					.map(({ id, ...event }) => event);
			};
			const nativeEvents = await run("legacy");
			expect(nativeEvents).toHaveLength(2);
			expect(await run("owned")).toEqual(nativeEvents);
			await seed();
			await database.query(
				`ALTER TABLE ${realm}."allauthEvent" ADD CONSTRAINT reject_console_revoke_fixture CHECK (type <> 'session.revoked') NOT VALID`,
			);
			try {
				await expect(send("owned", path, { id })).rejects.toMatchObject({
					code: "23514",
				});
				expect(await state()).toEqual({
					target: true,
					sibling: true,
					grant: true,
					challenge: true,
				});
			} finally {
				await database.query(
					`ALTER TABLE ${realm}."allauthEvent" DROP CONSTRAINT reject_console_revoke_fixture`,
				);
				await database.query(`DELETE FROM ${realm}."oauthClient" WHERE id=$1`, [
					clientId,
				]);
				await database.query(
					`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
					[[id, sibling]],
				);
				await database.query(`DELETE FROM ${realm}.verification WHERE id=$1`, [
					grantId,
				]);
			}
		});

		it("preserves signed console revocation and logout for the selected session's connected apps", async () => {
			const path = "/control/revoke-session";
			const realm = `"${alpha.schemaName}"`;
			const logoutURL = "https://console-logout.fixture.example/backchannel";
			const hasWorkspaceAuthority = async (headers: Headers) => {
				const actor = await readRoot(headers);
				if (!actor) return null;
				const membership = await database.query(
					`SELECT 1 FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2 AND role='owner'`,
					[alpha.workspaceId, actor.user.id],
				);
				return membership.rowCount ? actor : null;
			};
			const installed = installedNative(
				defaultAuthPolicy,
				hasWorkspaceAuthority,
			);
			async function exercise(writer: "legacy" | "owned") {
				const target = await browserSession(eventEmail);
				const sibling = await browserSession(eventEmail);
				const foreign = await browserSession(userEmail);
				const clientId = randomUUID();
				const siblingClientId = randomUUID();
				const delivered: string[] = [];
				const grants = [
					{
						sessionId: target.id,
						userId: eventUserId,
						clientId,
						scopes: ["openid"],
						table: "oauthAccessToken",
					},
					{
						sessionId: target.id,
						userId: eventUserId,
						clientId,
						scopes: ["openid"],
						table: "oauthRefreshToken",
					},
					{
						sessionId: target.id,
						userId: eventUserId,
						clientId,
						scopes: ["openid", "offline_access"],
						table: "oauthRefreshToken",
					},
					{
						sessionId: sibling.id,
						userId: eventUserId,
						clientId: siblingClientId,
						scopes: ["openid", "offline_access"],
						table: "oauthRefreshToken",
					},
					{
						sessionId: foreign.id,
						userId,
						clientId,
						scopes: ["openid", "offline_access"],
						table: "oauthRefreshToken",
					},
				];
				const subscription = await endpoint(
					"legacy",
					`console-revoke-${writer}`,
					["session.deleted"],
				);
				const verifyDelivery = async (url: string, body: URLSearchParams) => {
					expect(url).toBe(logoutURL);
					expect(
						(
							await database.query(
								`SELECT id FROM ${realm}.session WHERE id=$1`,
								[target.id],
							)
						).rowCount,
					).toBe(0);
					const token = body.get("logout_token");
					if (!token)
						throw new Error("Expected a signed connected-app logout.");
					delivered.push(token);
				};
				const candidate = createOwnedProjectEngine({
					database,
					project: alpha,
					baseURL: origin,
					basePath: alpha.path,
					signingSecret: alpha.secret,
					policy: defaultAuthPolicy,
					trustedOrigins: [],
					trustedIP: () => "192.0.2.127",
					adminDeletion: {
						id: alpha.id,
						workspaceId: alpha.workspaceId,
						platformOrigin: origin,
						readWorkspacePrincipal: readRoot,
					},
					backchannelLogout: {
						async post(url, body) {
							await verifyDelivery(url.href, body);
							return 204;
						},
					},
				});
				const fetch = vi
					.spyOn(globalThis, "fetch")
					.mockImplementation(async (input, init) => {
						if (!(init?.body instanceof URLSearchParams))
							throw new Error("Unexpected fixture transport.");
						await verifyDelivery(String(input), init.body);
						return new Response(null, { status: 204 });
					});
				const revoke = (cookie = rootCookie) => {
					const input = request(
						`${alpha.path}${path}`,
						{ id: target.id },
						cookie,
					);
					input.headers.set("x-real-ip", "192.0.2.127");
					return writer === "legacy"
						? installed.handler(input)
						: candidate.dispatch(input);
				};
				const grantOwners = async () =>
					(
						await database.query<{ userId: string }>(
							`SELECT "userId" FROM ${realm}."oauthAccessToken" WHERE "clientId"=$1
					 UNION ALL SELECT "userId" FROM ${realm}."oauthRefreshToken" WHERE "clientId"=ANY($2::text[])`,
							[clientId, [clientId, siblingClientId]],
						)
					).rows.map((row) => row.userId);
				try {
					for (const id of [clientId, siblingClientId])
						await database.query(
							`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris","backchannelLogoutUri") VALUES ($1,$1,'[]',$2)`,
							[id, logoutURL],
						);
					for (const grant of grants)
						await database.query(
							`INSERT INTO ${realm}."${grant.table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
							[
								randomUUID(),
								grant.sessionId,
								grant.userId,
								grant.clientId,
								JSON.stringify(grant.scopes),
							],
						);
					expect((await revoke(foreign.cookie)).status).toBe(403);
					await database.query(
						`UPDATE public."allauthWorkspaceMember" SET role='member' WHERE "workspaceId"=$1 AND "userId"=$2`,
						[alpha.workspaceId, rootId],
					);
					expect((await revoke()).status).toBe(403);
					expect(await grantOwners()).toHaveLength(grants.length);
					expect(
						(await deliveries("legacy", subscription.endpoint.id)).total,
					).toBe(0);
					expect(delivered).toEqual([]);
					await database.query(
						`UPDATE public."allauthWorkspaceMember" SET role='owner' WHERE "workspaceId"=$1 AND "userId"=$2`,
						[alpha.workspaceId, rootId],
					);
					if (writer === "owned") {
						const withoutTransport = await send("owned", path, {
							id: target.id,
						});
						expect(withoutTransport.status).toBe(501);
						expect(await grantOwners()).toHaveLength(grants.length);
						expect(
							(await deliveries("legacy", subscription.endpoint.id)).total,
						).toBe(0);
					}
					const revoked = await revoke();
					expect(revoked.status).toBe(200);
					expect(await revoked.json()).toEqual({ success: true });
					expect(await grantOwners()).toEqual([userId]);
					const { rows } = await database.query<{ id: string }>(
						`SELECT id FROM ${realm}.session WHERE id=ANY($1::text[]) ORDER BY id`,
						[[target.id, sibling.id, foreign.id]],
					);
					expect(rows.map(({ id }) => id)).toEqual(
						[sibling.id, foreign.id].sort(),
					);
					expect((await revoke()).status).toBe(404);
					expect(delivered).toHaveLength(1);
					const jwks = await installed.handler(request(`${alpha.path}/jwks`));
					const { payload } = await jwtVerify(
						delivered[0]!,
						createLocalJWKSet(await jwks.json()),
						{
							issuer: `${origin}${alpha.path}`,
							audience: clientId,
							typ: "logout+jwt",
						},
					);
					expect(payload).toMatchObject({ sub: eventUserId, sid: target.id });
					return await signedEvents(
						subscription,
						[
							eventEmail,
							target.token,
							sibling.token,
							foreign.token,
							delivered[0]!,
						],
						new Map([[target.id, "selected"]]),
					);
				} finally {
					fetch.mockRestore();
					await database.query(
						`UPDATE public."allauthWorkspaceMember" SET role='owner' WHERE "workspaceId"=$1 AND "userId"=$2`,
						[alpha.workspaceId, rootId],
					);
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=ANY($1::text[])`,
						[[clientId, siblingClientId]],
					);
					await database.query(
						`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[target.id, sibling.id, foreign.id]],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const secondOwner = randomUUID();
			await database.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,'Second fixture owner',$2,true)`,
				[secondOwner, `${secondOwner}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,'owner')`,
				[randomUUID(), alpha.workspaceId, secondOwner],
			);
			try {
				const native = await exercise("legacy");
				expect(native).toEqual([
					{
						event: {
							type: "session.deleted",
							outcome: "success",
							userId: eventUserId,
							targetId: "selected",
							metadata: { path },
						},
					},
				]);
				expect(await exercise("owned")).toEqual(native);
			} finally {
				await database.query(`DELETE FROM public."user" WHERE id=$1`, [
					secondOwner,
				]);
			}
		});

		async function endpoint(
			engine: "legacy" | "owned",
			label: string,
			eventTypes = ["auth.sign-in", "auth.sign-in"],
		) {
			const response = await send(engine, `${base}/create`, {
				url: `https://${label}.webhook.fixture.example/receive?state=1`,
				description: "  Fixture  ",
				eventTypes,
			});
			expect(response.status).toBe(200);
			expect(response.headers.get("cache-control")).toBe("no-store");
			return (await response.json()) as {
				endpoint: ControlWebhookEndpoint;
				secret: string;
			};
		}
		async function listed(engine: "legacy" | "owned") {
			const response = await send(engine);
			expect(response.status).toBe(200);
			return (await response.json()) as {
				endpoints: ControlWebhookEndpoint[];
				deliveryRetentionDays: number;
				maxAttempts: number;
			};
		}
		async function deliveries(engine: "legacy" | "owned", id: string) {
			const response = await send(
				engine,
				`${base}/deliveries?endpointId=${id}&limit=5`,
			);
			expect(response.status).toBe(200);
			return (await response.json()) as {
				deliveries: ControlWebhookDelivery[];
				total: number;
				limit: number;
				offset: number;
				retentionDays: number;
			};
		}

		async function browserSession(email: string) {
			const signedIn = await send(
				"legacy",
				"/sign-in/email",
				{ email, password },
				"",
			);
			expect(signedIn.status).toBe(200);
			const name = `__Secure-allauth_project_${alpha.slug}.session_token`;
			const cookies = signedIn.headers.getSetCookie();
			const cookie =
				cookies
					.find((value) => value.startsWith(`${name}=`))
					?.split(";", 1)[0] ?? "";
			expect(cookie).toBeTruthy();
			const active = await send("legacy", "/get-session", undefined, cookie);
			const { session } = (await active.json()) as {
				session: { id: string; token: string };
			};
			expect(session.id).toBeTruthy();
			const deviceName = `${name}_multi-${session.token.toLowerCase()}`;
			const deviceCookie =
				cookies
					.find((value) => value.startsWith(`${deviceName}=`))
					?.split(";", 1)[0] ?? "";
			return { cookie, id: session.id, token: session.token, deviceCookie };
		}

		async function signedEvents(
			subscription: Awaited<ReturnType<typeof endpoint>>,
			privateValues: string[],
			sessionLabels = new Map<string, string>(),
		) {
			const delivered: Array<{
				body: string;
				headers: Record<string, string>;
			}> = [];
			const result = await deliverPendingWebhooks({
				database: projectDatabase,
				secret: alpha.secret,
				resolver,
				now: () => new Date(Date.now() + 1_000),
				maxDeliveries: 20,
				transport: async ({ destination, body, headers }) => {
					if (destination.url.href === subscription.endpoint.url)
						delivered.push({ body, headers });
					return 204;
				},
			});
			expect(result).toMatchObject({
				claimed: delivered.length,
				delivered: delivered.length,
			});
			const eventIds = new Set<string>();
			const events = [];
			for (const { body, headers } of delivered) {
				const { id, type, timestamp, data } = JSON.parse(
					body,
				) as ControlWebhookEnvelope;
				expect(data.event).toMatchObject({ id, type, createdAt: timestamp });
				expect(headers["webhook-signature"]).toBe(
					await webhookSignature(
						subscription.secret,
						headers["webhook-id"],
						headers["webhook-timestamp"],
						body,
					),
				);
				eventIds.add(id);
				for (const value of privateValues) expect(body).not.toContain(value);
				const { id: _id, createdAt: _timestamp, ...event } = data.event;
				if (event.targetId && sessionLabels.has(event.targetId))
					event.targetId = sessionLabels.get(event.targetId);
				events.push({ event, ...(data.user ? { user: data.user } : {}) });
			}
			expect(eventIds.size).toBe(delivered.length);
			return events.sort((a, b) =>
				JSON.stringify(a).localeCompare(JSON.stringify(b)),
			);
		}

		it("delivers signed new-device and notification failure events across writers after a live session", async () => {
			const owner = randomUUID();
			const email = `${owner}@webhook-management.fixture.example`;
			const backupCode = "test3-67890";
			const realm = `"${alpha.schemaName}"`;
			const sibling = `"${beta.schemaName}"`;
			const deviceName = `__Secure-allauth_project_${alpha.slug}.control_device`;
			const deferred: (() => Promise<void>)[] = [];
			const notifications: string[] = [];
			async function failDelivery(recipient: string) {
				notifications.push(recipient);
				throw new Error("Synthetic new-device delivery failure");
			}
			const stock = installedNative(defaultAuthPolicy, readRoot, {
				send: ({ to }) => failDelivery(to),
			});
			const candidate = createOwnedProjectEngine({
				database,
				project: alpha,
				baseURL: origin,
				basePath: alpha.path,
				signingSecret: alpha.secret,
				policy: defaultAuthPolicy,
				trustedOrigins: [],
				trustedIP: (input) => input.headers.get("x-real-ip"),
				security: {
					newDevice: {
						defer: (work) => deferred.push(work),
						notify: (user) => failDelivery(user.email),
					},
				},
			});
			await database.query(
				`INSERT INTO ${realm}."user" (id,name,email,"emailVerified") VALUES ($1,'New device fixture',$2,TRUE)`,
				[owner, email],
			);
			await database.query(
				`INSERT INTO ${realm}."account" (id,"accountId","providerId","userId",password,"updatedAt") VALUES ($1,$2,'credential',$2,$3,now())`,
				[randomUUID(), owner, await clerkCompatiblePasswords.hash(password)],
			);
			const subscription = await endpoint("legacy", "device-security", [
				"security.*",
			]);
			const cookie = (response: Response, name: string) =>
				response.headers
					.getSetCookie()
					.find((value) => value.startsWith(`${name}=`))
					?.split(";", 1)[0];
			const pairs = (response: Response) =>
				response.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; ");
			function deviceRequest(
				path: string,
				ip: string,
				body?: object,
				cookies?: string,
			) {
				const input = request(`${alpha.path}${path}`, body, cookies);
				input.headers.set("x-real-ip", ip);
				return input;
			}
			const privateValues = [email, password, backupCode];
			const observe = () => signedEvents(subscription, privateValues);
			async function expectNewDeviceEvents(ipAddress: string) {
				const identity = {
					userId: owner,
					ipAddress,
					userAgent: "webhook-management-fixture",
				};
				const events = await observe();
				expect(events).toHaveLength(2);
				expect(events).toEqual(
					expect.arrayContaining([
						{
							event: {
								...identity,
								type: "security.new-device",
								outcome: "success",
								metadata: { newDevice: true },
							},
						},
						{
							event: {
								...identity,
								type: "security.new-device-notification-failed",
								outcome: "failure",
								metadata: {},
							},
						},
					]),
				);
			}
			const drain = async () => {
				for (const work of deferred.splice(0)) await work();
			};
			try {
				for (const [first, second] of [
					[stock.handler, candidate.dispatch],
					[candidate.dispatch, stock.handler],
				] as const) {
					await database.query(
						`UPDATE ${realm}."user" SET "twoFactorEnabled"=FALSE WHERE id=$1`,
						[owner],
					);
					await database.query(
						`DELETE FROM ${realm}."twoFactor" WHERE "userId"=$1`,
						[owner],
					);
					await database.query(
						`DELETE FROM ${realm}."allauthKnownDevice" WHERE "userId"=$1`,
						[owner],
					);
					notifications.length = 0;
					const initial = await first(
						deviceRequest("/sign-in/email", "192.0.2.204", { email, password }),
					);
					expect(initial.status).toBe(200);
					const initialDevice = cookie(initial, deviceName);
					expect(initialDevice).toBeTruthy();
					const repeated = await second(
						deviceRequest(
							"/sign-in/email",
							"192.0.2.205",
							{ email, password },
							initialDevice,
						),
					);
					expect(repeated.status).toBe(200);
					expect(cookie(repeated, deviceName)).toBe(initialDevice);
					await drain();
					expect(await observe()).toEqual([]);
					expect(notifications).toEqual([]);

					const changed = await second(
						deviceRequest("/sign-in/email", "192.0.2.206", { email, password }),
					);
					expect(changed.status).toBe(200);
					expect(cookie(changed, deviceName)).toBeTruthy();
					expect(cookie(changed, deviceName)).not.toBe(initialDevice);
					await drain();
					await expectNewDeviceEvents("192.0.2.206");
					expect(notifications).toEqual([email]);

					await database.query(
						`INSERT INTO ${realm}."twoFactor" (id,secret,"backupCodes","userId",verified) VALUES ($1,$2,$3,$4,TRUE)`,
						[
							randomUUID(),
							await symmetricEncrypt({
								key: alpha.secret,
								data: "fixture-security-totp",
							}),
							await symmetricEncrypt({
								key: alpha.secret,
								data: JSON.stringify([backupCode]),
							}),
							owner,
						],
					);
					await database.query(
						`UPDATE ${realm}."user" SET "twoFactorEnabled"=TRUE WHERE id=$1`,
						[owner],
					);
					const pending = await first(
						deviceRequest("/sign-in/email", "192.0.2.207", { email, password }),
					);
					expect(pending.status).toBe(200);
					expect(await pending.json()).toMatchObject({
						twoFactorRedirect: true,
					});
					expect(cookie(pending, deviceName)).toBeUndefined();
					const pendingSession = await second(
						deviceRequest(
							"/get-session",
							"192.0.2.208",
							undefined,
							pairs(pending),
						),
					);
					expect(await pendingSession.json()).toBeNull();
					await drain();
					expect(await observe()).toEqual([]);
					expect(notifications).toEqual([email]);
					const completed = await second(
						deviceRequest(
							"/two-factor/verify-backup-code",
							"192.0.2.209",
							{ code: backupCode },
							pairs(pending),
						),
					);
					expect(completed.status, await completed.clone().text()).toBe(200);
					expect(cookie(completed, deviceName)).toBeTruthy();
					await drain();
					await expectNewDeviceEvents("192.0.2.209");
					expect(notifications).toEqual([email, email]);
				}
				expect(
					(
						await database.query(
							`SELECT 1 FROM ${sibling}."allauthKnownDevice" WHERE "userId"=$1`,
							[owner],
						)
					).rowCount,
				).toBe(0);
				expect(
					(
						await database.query(
							`SELECT 1 FROM ${sibling}."allauthEvent" WHERE "userId"=$1`,
							[owner],
						)
					).rowCount,
				).toBe(0);
			} finally {
				await database.query(
					`DELETE FROM ${realm}."allauthWebhookEndpoint" WHERE id=$1`,
					[subscription.endpoint.id],
				);
				await database.query(`DELETE FROM ${realm}."user" WHERE id=$1`, [
					owner,
				]);
			}
		});

		it("delivers the same signed policy and rule events for authorized security console mutations", async () => {
			const scope = `"${alpha.schemaName}"`;
			const sibling = `"${beta.schemaName}"`;
			const subscription = await endpoint("legacy", "security-console", [
				"security.*",
			]);
			const previousPolicy = (
				await database.query<{ policy: unknown; updatedAt: Date }>(
					`SELECT policy,"updatedAt" FROM ${scope}."allauthSecurityPolicy" WHERE id='default'`,
				)
			).rows[0];
			const policy = { ...defaultSecurityPolicy, maxFailuresPerIp: 21 };
			const rule = {
				type: "ip",
				value: "192.0.2.221",
				reason: "Synthetic private console rule reason",
			};
			const candidate = createOwnedProjectEngine({
				database,
				project: alpha,
				baseURL: origin,
				basePath: alpha.path,
				signingSecret: alpha.secret,
				policy: defaultAuthPolicy,
				trustedOrigins: [],
				trustedIP: (input) => input.headers.get("x-real-ip"),
				adminDeletion: {
					id: alpha.id,
					workspaceId: alpha.workspaceId,
					platformOrigin: origin,
					readWorkspacePrincipal: readRoot,
				},
				security: { management: true },
			});
			const stock = installedNative();
			const ruleIds: string[] = [];
			const siblingEvents = async () =>
				(
					await database.query(
						`SELECT count(*)::integer AS count FROM ${sibling}."allauthEvent" WHERE type LIKE 'security.%'`,
					)
				).rows[0]?.count;
			const initialSibling = await siblingEvents();
			async function exercise(dispatch: typeof stock.handler) {
				const control = `${alpha.path}/control/security`;
				const denied = await dispatch(
					request(
						`${control}/update`,
						{ policy },
						rootCookie,
						"https://different-origin.fixture.example",
					),
				);
				expect(denied.status).toBe(403);
				const changed = await dispatch(
					request(`${control}/update`, { policy }, rootCookie),
				);
				expect(changed.status).toBe(200);
				expect(await changed.json()).toEqual({ policy });
				const added = await dispatch(
					request(`${control}/rules/add`, rule, rootCookie),
				);
				expect(added.status).toBe(200);
				const { rule: saved } = (await added.json()) as {
					rule: { id: string };
				};
				expect(saved).toMatchObject(rule);
				ruleIds.push(saved.id);
				const removed = await dispatch(
					request(`${control}/rules/remove`, { id: saved.id }, rootCookie),
				);
				expect(removed.status).toBe(200);
				expect(await removed.json()).toEqual({ success: true });
				expect(
					(
						await database.query(
							`SELECT 1 FROM ${scope}."allauthSecurityRule" WHERE id=$1`,
							[saved.id],
						)
					).rowCount,
				).toBe(0);
				return signedEvents(
					subscription,
					[rootCookie, rule.value, rule.reason],
					new Map([[saved.id, "console-rule"]]),
				);
			}
			try {
				const events = await exercise(stock.handler);
				const identity = {
					actorId: rootId,
					outcome: "success",
					ipAddress: "192.0.2.46",
					userAgent: "webhook-management-fixture",
				};
				expect(events).toHaveLength(3);
				expect(events).toEqual(
					expect.arrayContaining([
						{
							event: {
								...identity,
								type: "security.policy.updated",
								metadata: {
									fields: Object.keys(policy).filter(
										(field) => field !== "blockedEmailDomains",
									),
								},
							},
						},
						{
							event: {
								...identity,
								type: "security.rule.added",
								targetId: "console-rule",
								metadata: { ruleType: "ip" },
							},
						},
						{
							event: {
								...identity,
								type: "security.rule.removed",
								targetId: "console-rule",
								metadata: {},
							},
						},
					]),
				);
				expect(await exercise(candidate.dispatch)).toEqual(events);
				expect(await siblingEvents()).toBe(initialSibling);
			} finally {
				await database.query(
					`DELETE FROM ${scope}."allauthWebhookEndpoint" WHERE id=$1`,
					[subscription.endpoint.id],
				);
				await database.query(
					`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=ANY($1::text[])`,
					[ruleIds],
				);
				if (previousPolicy)
					await database.query(
						`UPDATE ${scope}."allauthSecurityPolicy" SET policy=$1,"updatedAt"=$2 WHERE id='default'`,
						[previousPolicy.policy, previousPolicy.updatedAt],
					);
				else
					await database.query(
						`DELETE FROM ${scope}."allauthSecurityPolicy" WHERE id='default'`,
					);
			}
		});

		it("preserves the native password sign-in admission bucket and signed security decisions across writers", async () => {
			const realm = `"${alpha.schemaName}"`;
			const path = "/sign-in/email";
			const incorrectPassword = "Synthetic-incorrect-password-7!";
			const spoofedAddress = "198.51.100.21";
			const subscription = await endpoint("legacy", "security-credentials", [
				"security.*",
			]);
			const stock = installedNative();
			const candidate = createOwnedProjectEngine({
				database,
				project: alpha,
				baseURL: origin,
				basePath: alpha.path,
				signingSecret: alpha.secret,
				policy: defaultAuthPolicy,
				trustedOrigins: [],
				trustedIP: (input) => input.headers.get("x-real-ip"),
				security: { requireTrustedIP: true },
			});
			const previousPolicy = (
				await database.query<{ policy: unknown; updatedAt: Date }>(
					`SELECT policy,"updatedAt" FROM ${realm}."allauthSecurityPolicy" WHERE id='default'`,
				)
			).rows[0];
			const ruleIds: string[] = [];
			const rates: string[] = [];
			async function policy(mode: "enforce" | "monitor") {
				await database.query(
					`INSERT INTO ${realm}."allauthSecurityPolicy" (id,policy,"updatedAt") VALUES ('default',$1,now())
					 ON CONFLICT (id) DO UPDATE SET policy=EXCLUDED.policy,"updatedAt"=EXCLUDED."updatedAt"`,
					[{ ...defaultSecurityPolicy, mode }],
				);
			}
			async function blockAddress(ip: string) {
				const id = randomUUID();
				ruleIds.push(id);
				await database.query(
					`INSERT INTO ${realm}."allauthSecurityRule" (id,type,value,reason) VALUES ($1,'ip',$2,'Synthetic credential policy')`,
					[id, ip],
				);
				return id;
			}
			const attempt = (dispatch: typeof stock.handler, ip: string) => {
				const incoming = request(`${alpha.path}${path}`, {
					email: eventEmail,
					password: incorrectPassword,
				});
				incoming.headers.set("x-real-ip", ip);
				incoming.headers.set("x-forwarded-for", spoofedAddress);
				return dispatch(incoming);
			};
			const observe = () =>
				signedEvents(subscription, [
					eventEmail,
					incorrectPassword,
					spoofedAddress,
				]);
			const failed = (ipAddress: string) => ({
				event: {
					type: "security.sign-in-failed",
					outcome: "failure",
					ipAddress,
					userAgent: "webhook-management-fixture",
					metadata: { method: "email", path },
				},
			});
			const blocked = (
				ipAddress: string,
				ruleId: string,
				monitor: boolean,
			) => ({
				event: {
					type: "security.blocked",
					outcome: monitor ? "success" : "blocked",
					ipAddress,
					userAgent: "webhook-management-fixture",
					metadata: {
						signal: "explicit-rule",
						monitor,
						ruleId,
						ruleType: "ip",
					},
				},
			});
			try {
				await policy("enforce");
				for (const [first, second, ip] of [
					[stock.handler, candidate.dispatch, "192.0.2.230"],
					[candidate.dispatch, stock.handler, "192.0.2.231"],
				] as const) {
					const key = `${ip}|${path}`;
					rates.push(key);
					await database.query(
						`INSERT INTO ${realm}."rateLimit" (id,"key",count,"lastRequest") VALUES ($1,$2,2,$3)`,
						[randomUUID(), key, Date.now()],
					);
					expect((await attempt(first, ip)).status).toBe(401);
					expect(await observe()).toEqual([failed(ip)]);
					await blockAddress(ip);
					const limited = await attempt(second, ip);
					expect(limited.status).toBe(429);
					expect(await limited.json()).toEqual({
						message: "Too many requests. Please try again later.",
					});
					expect(await observe()).toEqual([]);
					const { rows } = await database.query<{ count: number }>(
						`SELECT count FROM ${realm}."rateLimit" WHERE "key"=$1`,
						[key],
					);
					expect(rows[0]?.count).toBe(3);
				}
				for (const [dispatch, ip] of [
					[stock.handler, "192.0.2.232"],
					[candidate.dispatch, "192.0.2.233"],
				] as const) {
					rates.push(`${ip}|${path}`);
					const ruleId = await blockAddress(ip);
					await policy("monitor");
					expect((await attempt(dispatch, ip)).status).toBe(401);
					const observed = await observe();
					expect(observed).toHaveLength(2);
					expect(observed).toEqual(
						expect.arrayContaining([blocked(ip, ruleId, true), failed(ip)]),
					);
					await policy("enforce");
					const denied = await attempt(dispatch, ip);
					expect(denied.status).toBe(429);
					expect(await denied.json()).toMatchObject({
						code: "ALLAUTH_SECURITY_BLOCKED",
					});
					expect(await observe()).toEqual([blocked(ip, ruleId, false)]);
				}
			} finally {
				await database.query(
					`DELETE FROM ${realm}."allauthWebhookEndpoint" WHERE id=$1`,
					[subscription.endpoint.id],
				);
				await database.query(
					`DELETE FROM ${realm}."allauthSecurityRule" WHERE id=ANY($1::text[])`,
					[ruleIds],
				);
				await database.query(
					`DELETE FROM ${realm}."rateLimit" WHERE "key"=ANY($1::text[])`,
					[rates],
				);
				if (previousPolicy)
					await database.query(
						`UPDATE ${realm}."allauthSecurityPolicy" SET policy=$1,"updatedAt"=$2 WHERE id='default'`,
						[previousPolicy.policy, previousPolicy.updatedAt],
					);
				else
					await database.query(
						`DELETE FROM ${realm}."allauthSecurityPolicy" WHERE id='default'`,
					);
			}
		});

		it("signs out users linked to installed SIWE and exact realm SSO providers", async () => {
			const installed = installedNative();
			const realm = `"${alpha.schemaName}"`;
			const otherRealm = `"${beta.schemaName}"`;
			const path = "/sign-out";
			const logoutURL = "https://linked-account-signout.fixture.example/logout";
			const oidcId = "fixture-logout-oidc";
			const samlId = "fixture-logout-saml";
			const unknownId = `${oidcId}-other-realm`;
			const idp = "https://directory.fixture.example";
			const sp = `${origin}${alpha.path}/sso/saml2/sp/metadata?providerId=${samlId}`;
			const oidc = {
				clientId: "fixture-oidc-client",
				clientSecret: "synthetic-fixture-oidc-secret",
			};
			const saml = {
				issuer: sp,
				entryPoint: `${idp}/sso`,
				idpMetadata: { entityID: idp },
				cert: readFileSync(
					new URL("../../../../test/fixtures/cert.pem", import.meta.url),
					"utf8",
				),
				wantAssertionsSigned: true,
			};
			checkProjectOidcConfiguration({ issuer: idp, oidcConfig: oidc });
			checkProjectSamlConfiguration(
				{ issuer: sp, samlConfig: saml },
				`${origin}${alpha.path}/sso/saml2/sp/acs/${samlId}`,
			);
			async function registerProvider(
				scope: string,
				providerId: string,
				user: string,
				kind: "oidc" | "saml" | "empty",
			) {
				await database.query(
					`INSERT INTO ${scope}."ssoProvider" (id,"providerId",issuer,domain,"domainVerified","userId","oidcConfig","samlConfig")
					 VALUES ($1,$1,$2,'directory.fixture.example',true,$3,$4,$5)`,
					[
						providerId,
						kind === "saml" ? sp : idp,
						user,
						kind === "oidc" ? JSON.stringify(oidc) : null,
						kind === "saml" ? JSON.stringify(saml) : null,
					],
				);
			}
			const foreignOwner = randomUUID();
			await database.query(
				`INSERT INTO ${otherRealm}."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
				[foreignOwner, `${foreignOwner}@fixture.example`],
			);
			await registerProvider(otherRealm, unknownId, foreignOwner, "oidc");
			await registerProvider(realm, oidcId, eventUserId, "oidc");
			await registerProvider(realm, samlId, eventUserId, "saml");
			await registerProvider(
				realm,
				"fixture-empty-provider",
				eventUserId,
				"empty",
			);
			async function exercise(writer: "legacy" | "owned") {
				const active = await browserSession(eventEmail);
				const otherBrowser = await browserSession(eventEmail);
				const subscription = await endpoint(
					"legacy",
					`linked-account-signout-${writer}`,
					["session.deleted"],
				);
				const clientId = randomUUID();
				const grants = ["access", "online", "offline", "sibling"].map(
					(kind) => ({ kind, id: randomUUID() }),
				);
				const accountIds: string[] = [];
				const logoutTokens: string[] = [];
				const recordLogout = async (url: string, body: URLSearchParams) => {
					expect(url).toBe(logoutURL);
					expect(
						(
							await database.query(
								`SELECT id FROM ${realm}.session WHERE id=$1`,
								[active.id],
							)
						).rowCount,
					).toBe(0);
					const token = body.get("logout_token");
					if (!token)
						throw new Error("Expected a signed connected-app logout.");
					logoutTokens.push(token);
				};
				const candidate = createOwnedProjectEngine({
					database,
					project: alpha,
					baseURL: origin,
					basePath: alpha.path,
					signingSecret: alpha.secret,
					policy: defaultAuthPolicy,
					trustedOrigins: [],
					trustedIP: () => "192.0.2.139",
					backchannelLogout: {
						async post(url, body) {
							await recordLogout(url.href, body);
							return 204;
						},
					},
				});
				const fetch = vi
					.spyOn(globalThis, "fetch")
					.mockImplementation(async (input, init) => {
						if (!(init?.body instanceof URLSearchParams))
							throw new Error("Unexpected fixture transport.");
						await recordLogout(String(input), init.body);
						return new Response(null, { status: 204 });
					});
				async function link(
					providerId: string,
					subject: string = randomUUID(),
				) {
					const id = randomUUID();
					accountIds.push(id);
					await database.query(
						`INSERT INTO ${realm}."account" (id,"providerId","accountId","userId","updatedAt") VALUES ($1,$2,$3,$4,now())`,
						[id, providerId, subject, eventUserId],
					);
					return id;
				}
				const dispatch = () => {
					const input = request(`${alpha.path}${path}`, {}, active.cookie);
					input.headers.set("x-real-ip", "192.0.2.139");
					return writer === "legacy"
						? installed.handler(input)
						: candidate.dispatch(input);
				};
				const grantState = () =>
					database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthAccessToken" WHERE "clientId"=$1 UNION ALL SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${realm}."oauthRefreshToken" WHERE "clientId"=$1`,
						[clientId],
					);
				try {
					await link("siwe", "0x0000000000000000000000000000000000000001:1");
					await link(oidcId);
					await link(samlId);
					await database.query(
						`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris","backchannelLogoutUri") VALUES ($1,$1,'[]',$2)`,
						[clientId, logoutURL],
					);
					for (const { kind, id } of grants) {
						const table =
							kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
						await database.query(
							`INSERT INTO ${realm}."${table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
							[
								id,
								kind === "sibling" ? otherBrowser.id : active.id,
								eventUserId,
								clientId,
								JSON.stringify(
									kind === "offline"
										? ["openid", "offline_access"]
										: ["openid"],
								),
							],
						);
					}
					if (writer === "legacy") {
						const slo = await installed.handler(
							request(
								`${alpha.path}/sso/saml2/logout/${samlId}`,
								{},
								active.cookie,
							),
						);
						expect(slo.status).toBe(400);
						expect(await slo.json()).toMatchObject({
							code: "SINGLE_LOGOUT_NOT_ENABLED",
						});
					} else {
						for (const provider of [unknownId, "fixture-empty-provider"]) {
							const id = await link(provider);
							expect((await dispatch()).status).toBe(501);
							const unchanged = await grantState();
							expect(unchanged.rows).toHaveLength(grants.length);
							expect(
								unchanged.rows.every(
									(grant) => !grant.revoked && grant.sessionId,
								),
							).toBe(true);
							expect(
								(await deliveries("legacy", subscription.endpoint.id)).total,
							).toBe(0);
							expect(logoutTokens).toEqual([]);
							await database.query(
								`DELETE FROM ${realm}."account" WHERE id=$1`,
								[id],
							);
						}
					}
					const result = await dispatch();
					expect(result.status).toBe(200);
					expect(result.headers.has("location")).toBe(false);
					expect(await result.json()).toEqual({ success: true });
					const { rows } = await database.query(
						`SELECT id FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, otherBrowser.id]],
					);
					expect(rows).toEqual([{ id: otherBrowser.id }]);
					const state = await grantState();
					expect(state.rows).toHaveLength(grants.length);
					for (const { kind, id } of grants)
						expect(state.rows.find((grant) => grant.id === id)).toEqual({
							id,
							revoked: kind === "access" || kind === "online",
							sessionId: kind === "sibling" ? otherBrowser.id : null,
						});
					expect(logoutTokens).toHaveLength(1);
					const jwks = await installed.handler(request(`${alpha.path}/jwks`));
					const { payload } = await jwtVerify(
						logoutTokens[0]!,
						createLocalJWKSet(await jwks.json()),
						{
							issuer: `${origin}${alpha.path}`,
							audience: clientId,
							typ: "logout+jwt",
						},
					);
					expect(payload).toMatchObject({ sub: eventUserId, sid: active.id });
					return await signedEvents(
						subscription,
						[
							eventEmail,
							active.token,
							otherBrowser.token,
							logoutTokens[0]!,
							...grants.map(({ id }) => id),
						],
						new Map([[active.id, "signed-out"]]),
					);
				} finally {
					fetch.mockRestore();
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${realm}."account" WHERE id=ANY($1::text[])`,
						[accountIds],
					);
					await database.query(
						`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, otherBrowser.id]],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			try {
				const native = await exercise("legacy");
				expect(native).toEqual([
					{
						event: {
							type: "session.deleted",
							outcome: "success",
							userId: eventUserId,
							targetId: "signed-out",
							metadata: { path },
						},
					},
				]);
				expect(await exercise("owned")).toEqual(native);
			} finally {
				await database.query(
					`DELETE FROM ${realm}."ssoProvider" WHERE "providerId"=ANY($1::text[])`,
					[[oidcId, samlId, "fixture-empty-provider"]],
				);
				await database.query(`DELETE FROM ${otherRealm}."user" WHERE id=$1`, [
					foreignOwner,
				]);
			}
		});

		it("preserves each management operation and dispatches through the existing signed worker after either writer", async () => {
			expect((await send("owned", base, undefined, "")).status).toBe(403);
			const unapproved = {
				url: "https://invalid.webhook.fixture.example",
				eventTypes: ["auth.sign-in"],
			};
			expect(
				(
					await send(
						"owned",
						`${base}/create`,
						unapproved,
						rootCookie,
						"https://foreign.fixture.example",
					)
				).status,
			).toBe(403);
			expect(
				(
					await other.dispatch(
						request(beta.path + `${base}/create`, unapproved, rootCookie),
					)
				).status,
			).toBe(403);
			expect(
				(
					await send("owned", `${base}/create`, {
						...unapproved,
						url: "http://hooks.fixture.example",
					})
				).status,
			).toBe(400);
			const old = await endpoint("legacy", "legacy");
			expect(old.endpoint).toMatchObject({
				description: "Fixture",
				eventTypes: ["auth.sign-in"],
			});
			expect(await listed("owned")).toEqual({
				endpoints: [old.endpoint],
				supportedEventTypes: webhookEventTypes,
				deliveryRetentionDays: 30,
				maxAttempts: 8,
			});
			expect(
				(
					await legacy.handler(
						request(`${alpha.path}/sign-in/email`, {
							email: userEmail,
							password,
						}),
					)
				).status,
			).toBe(200);
			const queued = await deliveries("owned", old.endpoint.id);
			expect(queued).toMatchObject({
				total: 1,
				limit: 5,
				offset: 0,
				retentionDays: 30,
				deliveries: [{ status: "pending", eventType: "auth.sign-in" }],
			});
			const id = queued.deliveries[0].id;
			expect(JSON.stringify(queued)).not.toContain(userEmail);
			expect(
				await deliverPendingWebhooks({
					database: projectDatabase,
					secret: alpha.secret,
					resolver,
					transport: async () => 400,
				}),
			).toMatchObject({ failed: 1 });
			const failed = await deliveries("owned", old.endpoint.id);
			expect(failed.deliveries[0]).toMatchObject({
				id,
				status: "failed",
				attempts: 1,
				statusCode: 400,
			});
			const retried = await send("owned", `${base}/retry`, { id });
			expect(retried.status).toBe(200);
			expect(await retried.json()).toEqual({ success: true });
			expect(
				(await deliveries("legacy", old.endpoint.id)).deliveries[0],
			).toMatchObject({ id, status: "pending", attempts: 1 });
			const rotated = await rotatedAuthSigningKey.dispatch(
				request(
					`${alpha.path}${base}/rotate`,
					{ id: old.endpoint.id },
					rootCookie,
				),
			);
			expect(rotated.status).toBe(200);
			const { secret: next } = (await rotated.json()) as { secret: string };
			expect(next).not.toBe(old.secret);
			const delivered = await deliverPendingWebhooks({
				database: projectDatabase,
				secret: alpha.secret,
				resolver,
				transport: async ({ headers, body }) => {
					expect(headers["webhook-id"]).toBe(id);
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							next,
							id,
							headers["webhook-timestamp"],
							body,
						),
					);
					expect(JSON.parse(body)).toMatchObject({
						type: "auth.sign-in",
						data: { event: { userId } },
					});
					return 204;
				},
			});
			expect(delivered).toMatchObject({ delivered: 1, claimed: 1 });
			expect((await send("owned", `${base}/retry`, { id })).status).toBe(400);

			const createdOwned = await endpoint("owned", "owned");
			const stored = await database.query<{ encryptedSecret: string }>(
				`SELECT "encryptedSecret" FROM "${alpha.schemaName}"."allauthWebhookEndpoint" WHERE id=$1`,
				[createdOwned.endpoint.id],
			);
			expect(
				await symmetricDecrypt({
					key: alpha.secret,
					data: stored.rows[0].encryptedSecret,
				}),
			).toBe(createdOwned.secret);
			const rollbackList = await listed("legacy");
			expect(rollbackList.endpoints).toEqual(
				expect.arrayContaining([createdOwned.endpoint]),
			);
			expect(JSON.stringify(rollbackList)).not.toContain(createdOwned.secret);
			expect(
				(
					await owned.dispatch(
						request(`${alpha.path}/sign-in/email`, {
							email: userEmail,
							password,
						}),
					)
				).status,
			).toBe(200);
			const targets: string[] = [];
			const job = await deliverPendingWebhooks({
				database: projectDatabase,
				secret: alpha.secret,
				resolver,
				transport: async ({ destination, headers, body }) => {
					const ownedTarget =
						destination.url.hostname === "owned.webhook.fixture.example";
					targets.push(destination.url.hostname);
					const signing = ownedTarget ? createdOwned.secret : next;
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							signing,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					expect(JSON.parse(body)).toMatchObject({
						type: "auth.sign-in",
						data: { event: { userId } },
					});
					return ownedTarget ? 400 : 204;
				},
			});
			expect(job).toMatchObject({ claimed: 2, delivered: 1, failed: 1 });
			expect(targets.sort()).toEqual([
				"legacy.webhook.fixture.example",
				"owned.webhook.fixture.example",
			]);
			const candidateDelivery = (
				await deliveries("legacy", createdOwned.endpoint.id)
			).deliveries[0];
			expect(candidateDelivery).toMatchObject({
				status: "failed",
				attempts: 1,
			});
			const legacyRetry = await send("legacy", `${base}/retry`, {
				id: candidateDelivery.id,
			});
			expect(legacyRetry.status).toBe(200);
			expect(
				(await deliveries("owned", createdOwned.endpoint.id)).deliveries[0],
			).toMatchObject({
				id: candidateDelivery.id,
				status: "pending",
				attempts: 1,
			});
			expect(
				await deliverPendingWebhooks({
					database: projectDatabase,
					secret: alpha.secret,
					resolver,
					transport: async ({ headers }) => {
						expect(headers["webhook-id"]).toBe(candidateDelivery.id);
						return 204;
					},
				}),
			).toMatchObject({ claimed: 1, delivered: 1 });
			expect(
				(
					await database.query(
						`SELECT 1 FROM "${beta.schemaName}"."allauthWebhookDelivery"`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(await send("owned", `${base}/delete`, { id: old.endpoint.id })).status,
			).toBe(200);
			expect((await deliveries("legacy", old.endpoint.id)).total).toBe(0);
			expect(
				(
					await send("legacy", `${base}/delete`, {
						id: createdOwned.endpoint.id,
					})
				).status,
			).toBe(200);
			expect((await listed("owned")).endpoints).toEqual([]);
			const audit = await database.query(
				`SELECT type,"actorId","ipAddress","userAgent" FROM "${alpha.schemaName}"."allauthEvent" WHERE type LIKE 'webhook.%'`,
			);
			expect(audit.rows).toEqual(
				expect.arrayContaining(
					[
						"webhook.created",
						"webhook.secret-rotated",
						"webhook.delivery-retried",
						"webhook.deleted",
					].map((type) => ({
						type,
						actorId: rootId,
						ipAddress: "192.0.2.46",
						userAgent: "webhook-management-fixture",
					})),
				),
			);
		});

		it("delivers the same public password sign-in and sign-out events from either writer", async () => {
			const created = await send("legacy", `${base}/create`, {
				url: "https://payload.webhook.fixture.example/receive",
				eventTypes: ["auth.sign-in", "session.*", "session.created"],
			});
			expect(created.status).toBe(200);
			const { secret, endpoint } = (await created.json()) as {
				secret: string;
				endpoint: ControlWebhookEndpoint;
			};
			const incorrectPassword = "Disposable-invalid-attempt-0!";
			async function exercise(writer: "legacy" | "owned") {
				const attempt = await send(
					writer,
					"/sign-in/email",
					{
						email: userEmail,
						password: incorrectPassword,
					},
					"",
				);
				expect(attempt.status).toBe(401);
				const signedIn = await send(
					writer,
					"/sign-in/email",
					{
						email: userEmail,
						password,
					},
					"",
				);
				expect(signedIn.status).toBe(200);
				const cookie = signedIn.headers
					.getSetCookie()
					.find((value) =>
						value.startsWith(
							`__Secure-allauth_project_${alpha.slug}.session_token=`,
						),
					)
					?.split(";", 1)[0];
				expect(cookie).toBeTruthy();
				const active = await send(writer, "/get-session", undefined, cookie);
				const { session } = (await active.json()) as {
					session: { id: string };
				};
				expect(session.id).toBeTruthy();
				expect((await send(writer, "/sign-out", {}, cookie)).status).toBe(200);
				const events = await signedEvents(
					{ secret, endpoint },
					[userEmail, password, incorrectPassword, cookie ?? ""],
					new Map([[session.id, "session"]]),
				);
				for (const { event, user } of events) {
					expect(user).toBeUndefined();
					if (event.targetId) expect(event.targetId).toBe("session");
				}
				return events.map(({ event }) => event);
			}
			const nativeEvents = await exercise("legacy");
			expect(nativeEvents.map((event) => event.type)).toEqual([
				"auth.sign-in",
				"auth.sign-in",
				"session.created",
				"session.deleted",
				"session.signed-out",
			]);
			expect(await exercise("owned")).toEqual(nativeEvents);
			expect(
				(await send("owned", `${base}/delete`, { id: endpoint.id })).status,
			).toBe(200);
		});

		it("delivers native profile mutation events and only the public user projection", async () => {
			const name = "Updated fixture profile";
			const privateMetadata = "fixture-profile-private-metadata";
			async function exercise(writer: "legacy" | "owned") {
				await database.query(
					`UPDATE "${alpha.schemaName}"."user" SET name='Previous profile', "publicMetadata"=$2::jsonb, "privateMetadata"=$3::jsonb WHERE id=$1`,
					[
						eventUserId,
						JSON.stringify({ category: "fixture" }),
						JSON.stringify({ note: privateMetadata }),
					],
				);
				const { cookie } = await browserSession(eventEmail);
				const subscription = await endpoint(
					"legacy",
					`profile-payload-${writer}`,
					["user.*", "user.updated"],
				);
				try {
					expect(
						(await send(writer, "/update-user", { name }, cookie)).status,
					).toBe(200);
					expect(
						(
							await send(
								writer,
								"/update-user",
								{ email: "unexpected@fixture.example" },
								cookie,
							)
						).status,
					).toBe(400);
					expect((await send(writer, "/update-user", {}, cookie)).status).toBe(
						400,
					);
					expect(
						(await send(writer, "/update-user", { name }, "")).status,
					).toBe(401);
					return await signedEvents(subscription, [
						password,
						cookie,
						privateMetadata,
						"unexpected@fixture.example",
					]);
				} finally {
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const nativeEvents = await exercise("legacy");
			expect(
				nativeEvents.filter(({ event }) => event.outcome === "success"),
			).toHaveLength(2);
			for (const { event, user } of nativeEvents) {
				expect(event.type).toBe("user.updated");
				if (event.userId)
					expect(user).toEqual({
						id: eventUserId,
						name,
						email: eventEmail,
						emailVerified: true,
						publicMetadata: { category: "fixture" },
					});
			}
			expect(await exercise("owned")).toEqual(nativeEvents);
		});

		it("delivers native password-change results with safe request context to user subscribers", async () => {
			const replacement = "Replacement-fixture-password-31!";
			const compromised = "Compromised-fixture-password-31!";
			const incorrect = "Incorrect-fixture-password-31!";
			const offline = "Offline-fixture-password-31!";
			const oversized = "Large-fixture-current-password-".repeat(5);
			const digest = createHash("sha1")
				.update(compromised)
				.digest("hex")
				.toUpperCase();
			const offlinePrefix = createHash("sha1")
				.update(offline)
				.digest("hex")
				.slice(0, 5)
				.toUpperCase();
			const table = `"${alpha.schemaName}"."account"`;
			const match = `"userId"=$1 AND "providerId"='credential'`;
			const { rows } = await database.query<{ password: string }>(
				`SELECT password FROM ${table} WHERE ${match}`,
				[eventUserId],
			);
			const originalHash = rows[0].password;
			async function setHash(hash: string | null) {
				await database.query(`UPDATE ${table} SET password=$2 WHERE ${match}`, [
					eventUserId,
					hash,
				]);
			}
			const breachFetch = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) => {
					const url = new URL(input instanceof Request ? input.url : input);
					expect(url.origin).toBe("https://api.pwnedpasswords.com");
					expect(url.pathname).toMatch(/^\/range\/[A-F0-9]{5}$/);
					if (url.pathname.endsWith(offlinePrefix))
						return new Response("Unavailable", { status: 503 });
					return new Response(
						url.pathname.endsWith(digest.slice(0, 5))
							? `${digest.slice(5)}:7\r\n`
							: `${"0".repeat(35)}:0\r\n`,
					);
				});
			async function exercise(writer: "legacy" | "owned") {
				const { cookie } = await browserSession(eventEmail);
				const subscription = await endpoint(
					"legacy",
					`password-change-${writer}`,
					["user.*"],
				);
				async function change(
					currentPassword: string,
					newPassword: string,
					session = cookie,
				) {
					return send(
						writer,
						"/change-password",
						{ currentPassword, newPassword },
						session,
					);
				}
				try {
					expect((await change(password, replacement, "")).status).toBe(401);
					expect((await change(password, "short")).status).toBe(400);
					expect((await change(oversized, replacement)).status).toBe(400);
					const beforeIncorrect = breachFetch.mock.calls.length;
					expect((await change(incorrect, replacement)).status).toBe(400);
					if (writer === "owned")
						expect(breachFetch.mock.calls).toHaveLength(beforeIncorrect);
					expect((await change(password, compromised)).status).toBe(400);
					expect((await change(password, offline)).status).toBe(
						writer === "legacy" ? 500 : 503,
					);
					await setHash(null);
					expect((await change(password, replacement)).status).toBe(400);
					await setHash(originalHash);
					expect((await change(password, replacement)).status).toBe(200);
					return await signedEvents(subscription, [
						password,
						incorrect,
						compromised,
						offline,
						oversized,
						replacement,
						originalHash,
						cookie,
					]);
				} finally {
					await setHash(originalHash);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			try {
				const native = await exercise("legacy");
				expect(
					native
						.map(({ event }) => event.metadata.errorCode ?? "success")
						.sort(),
				).toEqual([
					"AUTHENTICATION_FAILED",
					"CREDENTIAL_ACCOUNT_NOT_FOUND",
					"INVALID_PASSWORD",
					"PASSWORD_COMPROMISED",
					"PASSWORD_TOO_LONG",
					"UNAUTHORIZED",
					"success",
				]);
				for (const { event, user } of native) {
					expect(event).toMatchObject({
						type: "user.password-changed",
						ipAddress: "192.0.2.46",
						userAgent: "webhook-management-fixture",
						metadata: { path: "/change-password" },
					});
					if (event.metadata.errorCode === "UNAUTHORIZED") {
						expect(event.userId).toBeUndefined();
						expect(event.actorId).toBeUndefined();
						expect(user).toBeUndefined();
					} else {
						expect(event.userId).toBe(eventUserId);
						expect(event.actorId).toBe(eventUserId);
						expect(user).toMatchObject({ id: eventUserId, email: eventEmail });
					}
				}
				expect(await exercise("owned")).toEqual(native);
				expect(
					(
						await database.query(
							`SELECT id FROM "${beta.schemaName}"."allauthEvent" WHERE type='user.password-changed'`,
						)
					).rows,
				).toEqual([]);
			} finally {
				breachFetch.mockRestore();
			}
		});

		it("clears the active organization and team when a password change replaces the session", async () => {
			const schema = `"${alpha.schemaName}"`;
			const organizationId = randomUUID();
			const teamId = randomUUID();
			const replacementPassword = "Replacement-fixture-password-82!";
			const { rows } = await database.query<{ password: string }>(
				`SELECT password FROM ${schema}.account WHERE "userId"=$1 AND "providerId"='credential'`,
				[eventUserId],
			);
			await database.query(
				`INSERT INTO ${schema}.organization (id,name,slug,"createdAt")
				 VALUES ($1,'Password rotation fixture','password-rotation-fixture',now())`,
				[organizationId],
			);
			await database.query(
				`INSERT INTO ${schema}.team (id,name,"memberCount","organizationId","createdAt")
				 VALUES ($1,'Password rotation team',1,$2,now())`,
				[teamId, organizationId],
			);
			await database.query(
				`INSERT INTO ${schema}.member (id,"organizationId","userId",role,"createdAt")
				 VALUES ($1,$2,$3,'member',now())`,
				[randomUUID(), organizationId, eventUserId],
			);
			await database.query(
				`INSERT INTO ${schema}."teamMember" (id,"teamId","userId","createdAt")
				 VALUES ($1,$2,$3,now())`,
				[randomUUID(), teamId, eventUserId],
			);
			const breachFetch = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(
					async () => new Response(`${"0".repeat(35)}:0\r\n`),
				);
			try {
				for (const writer of ["legacy", "owned"] as const) {
					const otherWriter = writer === "legacy" ? "owned" : "legacy";
					const active = await browserSession(eventEmail);
					const sibling = await browserSession(eventEmail);
					await database.query(
						`UPDATE ${schema}."session" SET "activeOrganizationId"=$1,"activeTeamId"=$2 WHERE id=$3`,
						[organizationId, teamId, active.id],
					);
					try {
						const response = await send(
							writer,
							"/change-password",
							{
								currentPassword: password,
								newPassword: replacementPassword,
								revokeOtherSessions: true,
							},
							active.cookie,
						);
						expect(response.status).toBe(200);
						const sessionCookieName = active.cookie.split("=", 1)[0];
						const replacementCookie =
							response.headers
								.getSetCookie()
								.find((cookie) => cookie.startsWith(`${sessionCookieName}=`))
								?.split(";", 1)[0] ?? "";
						expect(replacementCookie).toBeTruthy();
						const replacement = await send(
							otherWriter,
							"/get-session",
							undefined,
							replacementCookie,
						);
						expect(replacement.status).toBe(200);
						const replacementBody = (await replacement.json()) as {
							session: { id: string };
						};
						expect(replacementBody).toMatchObject({
							user: { id: eventUserId },
							session: { activeOrganizationId: null },
						});
						expect(replacementBody.session.id).not.toBe(active.id);
						const saved = await database.query(
							`SELECT "activeOrganizationId","activeTeamId" FROM ${schema}."session" WHERE id=$1`,
							[replacementBody.session.id],
						);
						expect(saved.rows).toEqual([
							{ activeOrganizationId: null, activeTeamId: null },
						]);
						for (const revoked of [active, sibling]) {
							const lookup = await send(
								otherWriter,
								"/get-session",
								undefined,
								revoked.cookie,
							);
							expect(await lookup.json()).toBeNull();
						}
					} finally {
						await database.query(
							`UPDATE ${schema}.account SET password=$2 WHERE "userId"=$1 AND "providerId"='credential'`,
							[eventUserId, rows[0].password],
						);
					}
				}
			} finally {
				breachFetch.mockRestore();
				await database.query(`DELETE FROM ${schema}.organization WHERE id=$1`, [
					organizationId,
				]);
			}
		});

		it("rolls back the profile and session mutations when their event cannot be recorded", async () => {
			const active = await browserSession(eventEmail);
			const sibling = await browserSession(eventEmail);
			const subscription = await endpoint("legacy", "atomic-payload", [
				"user.*",
				"session.*",
			]);
			const schema = `"${alpha.schemaName}"`;
			await database.query(`CREATE FUNCTION ${schema}."rejectFixtureEvent"() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'fixture event unavailable'; END;
			$$`);
			try {
				await database.query(`CREATE TRIGGER "rejectFixtureEvent" BEFORE INSERT ON ${schema}."allauthEvent"
					FOR EACH ROW WHEN ((NEW.type = 'user.updated' AND NEW."targetId" IS NULL) OR NEW.type = 'session.revoked-others')
					EXECUTE FUNCTION ${schema}."rejectFixtureEvent"()`);
				const currentName = await database.query<{ name: string }>(
					`SELECT name FROM ${schema}."user" WHERE id=$1`,
					[eventUserId],
				);
				await expect(
					send(
						"owned",
						"/update-user",
						{ name: "Failed fixture update" },
						active.cookie,
					),
				).rejects.toThrow("fixture event unavailable");
				await expect(
					send("owned", "/revoke-other-sessions", {}, active.cookie),
				).rejects.toThrow("fixture event unavailable");
				expect(
					(
						await database.query(
							`SELECT name FROM ${schema}."user" WHERE id=$1`,
							[eventUserId],
						)
					).rows,
				).toEqual(currentName.rows);
				expect(
					(
						await database.query(
							`SELECT id FROM ${schema}."session" WHERE id=ANY($1::text[])`,
							[[active.id, sibling.id]],
						)
					).rowCount,
				).toBe(2);
				expect(
					(await deliveries("legacy", subscription.endpoint.id)).total,
				).toBe(0);
			} finally {
				await database.query(
					`DROP FUNCTION ${schema}."rejectFixtureEvent"() CASCADE`,
				);
				expect(
					(
						await send("legacy", `${base}/delete`, {
							id: subscription.endpoint.id,
						})
					).status,
				).toBe(200);
			}
		});

		it("delivers the native session deletion event when the browser reads an expired session", async () => {
			const realm = `"${alpha.schemaName}"`;
			async function exercise(writer: "legacy" | "owned") {
				const expired = await browserSession(eventEmail);
				const active = await browserSession(eventEmail);
				const clientId = randomUUID();
				await database.query(
					`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[clientId],
				);
				const grants = {
					access: randomUUID(),
					online: randomUUID(),
					offline: randomUUID(),
				};
				const tokenScope = [expired.id, eventUserId, clientId];
				await database.query(
					`INSERT INTO ${realm}."oauthAccessToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
					 VALUES ($4,$4,$1,$2,$3,now()+interval '1 day',now(),'["openid"]')`,
					[...tokenScope, grants.access],
				);
				await database.query(
					`INSERT INTO ${realm}."oauthRefreshToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
					 VALUES ($4,$4,$1,$2,$3,now()+interval '1 day',now(),'["openid"]'),
					        ($5,$5,$1,$2,$3,now()+interval '1 day',now(),'["openid","offline_access"]')`,
					[...tokenScope, grants.online, grants.offline],
				);
				await database.query(
					`UPDATE ${realm}.session SET "expiresAt"=statement_timestamp()-interval '1 minute' WHERE id=$1`,
					[expired.id],
				);
				const subscription = await endpoint(
					"legacy",
					`expired-read-${writer}`,
					["session.deleted"],
				);
				const read = (cookie: string) => {
					const current = request(
						`${alpha.path}/get-session?disableRefresh=true`,
						undefined,
						cookie,
					);
					return writer === "legacy"
						? legacy.api.getSession({
								request: current,
								headers: current.headers,
								query: { disableCookieCache: true, disableRefresh: true },
								asResponse: true,
							})
						: owned.readSession(current);
				};
				try {
					const repeated =
						writer === "legacy"
							? [await read(expired.cookie), await read(expired.cookie)]
							: await Promise.all([read(expired.cookie), read(expired.cookie)]);
					for (const response of repeated) {
						expect(response.status).toBe(200);
						expect(await response.json()).toBeNull();
						expect(response.headers.getSetCookie()).toEqual(
							expect.arrayContaining([
								expect.stringMatching(/\.session_token=;.*Max-Age=0/),
							]),
						);
					}
					expect(await (await read(active.cookie)).json()).toMatchObject({
						session: { id: active.id },
					});
					const events = await signedEvents(
						subscription,
						[
							expired.cookie,
							active.cookie,
							eventEmail,
							...Object.values(grants),
						],
						new Map([[expired.id, "expired-browser"]]),
					);
					expect(
						(
							await database.query(
								`SELECT 1 FROM ${realm}.session WHERE id=$1`,
								[expired.id],
							)
						).rowCount,
					).toBe(0);
					const state = await database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthAccessToken" WHERE id=$1
						 UNION ALL SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthRefreshToken" WHERE id=ANY($2::text[])`,
						[grants.access, [grants.online, grants.offline]],
					);
					expect(state.rows).toHaveLength(3);
					for (const [kind, id] of Object.entries(grants))
						expect(state.rows.find((row) => row.id === id)).toEqual({
							id,
							revoked: kind !== "offline",
							sessionId: null,
						});
					return events;
				} finally {
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[expired.id, active.id]],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const native = await exercise("legacy");
			expect(native).toEqual([
				{
					event: {
						type: "session.deleted",
						outcome: "success",
						actorId: eventUserId,
						userId: eventUserId,
						targetId: "expired-browser",
						metadata: { path: "/get-session" },
					},
				},
			]);
			expect(await exercise("owned")).toEqual(native);
		});

		it.each([
			["email", true, "192.0.2.123"],
			["email", false, "192.0.2.124"],
			["username", true, "192.0.2.125"],
			["username", false, "192.0.2.126"],
		] as const)("delivers the native session deletion on %s sign-in with active browser cookie %s", async (identifier, hasActiveCookie, ip) => {
			const path = `/sign-in/${identifier}`;
			const schema = `"${alpha.schemaName}"`;
			const foreignSchema = `"${beta.schemaName}"`;
			const installed = installedNative();
			const candidate = createOwnedProjectEngine({
				database,
				project: alpha,
				baseURL: origin,
				basePath: alpha.path,
				signingSecret: alpha.secret,
				policy: defaultAuthPolicy,
				trustedOrigins: [],
				trustedIP: () => ip,
			});
			const username = "fixture_webhook_event_user";
			async function exercise(writer: "legacy" | "owned") {
				const active = await browserSession(userEmail);
				const previous = await browserSession(eventEmail);
				const otherBrowser = await browserSession(eventEmail);
				expect(active.deviceCookie).toBeTruthy();
				expect(previous.deviceCookie).toBeTruthy();
				const subscription = await endpoint(
					"legacy",
					`re-sign-in-${identifier}-${hasActiveCookie}-${writer}`,
					["session.deleted"],
				);
				const clientId = randomUUID();
				const foreignOwner = randomUUID();
				const grants = ["access", "online", "offline", "unrelated"].map(
					(kind) => ({ kind, id: randomUUID() }),
				);
				const sessionIds = [active.id, previous.id, otherBrowser.id];
				try {
					await database.query(
						`INSERT INTO ${foreignSchema}."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
						[foreignOwner, eventEmail],
					);
					await database.query(
						`INSERT INTO ${foreignSchema}.session (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
						[previous.id, previous.token, foreignOwner],
					);
					await database.query(
						`INSERT INTO ${schema}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[clientId],
					);
					for (const { kind, id } of grants) {
						const table =
							kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
						await database.query(
							`INSERT INTO ${schema}."${table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
							[
								id,
								kind === "unrelated" ? otherBrowser.id : previous.id,
								eventUserId,
								clientId,
								JSON.stringify(
									kind === "offline"
										? ["openid", "offline_access"]
										: ["openid"],
								),
							],
						);
					}
					const incoming = [active.deviceCookie, previous.deviceCookie];
					if (hasActiveCookie) incoming.unshift(active.cookie);
					const input = request(
						`${alpha.path}${path}`,
						{
							[identifier]: identifier === "email" ? eventEmail : username,
							password,
						},
						incoming.join("; "),
					);
					input.headers.set("x-real-ip", ip);
					const signedIn = await (writer === "legacy"
						? installed.handler(input)
						: candidate.dispatch(input));
					expect(signedIn.status).toBe(200);
					const cookies = signedIn.headers.getSetCookie();
					const primaryName = active.cookie.split("=", 1)[0];
					const primary = cookies
						.find((cookie) => cookie.startsWith(`${primaryName}=`))
						?.split(";", 1)[0];
					expect(primary).toBeTruthy();
					const read = await send("legacy", "/get-session", undefined, primary);
					const { session: replacement } = (await read.json()) as {
						session: { id: string; token: string; userId: string };
					};
					expect(replacement.userId).toBe(eventUserId);
					expect(replacement.id).not.toBe(previous.id);
					sessionIds.push(replacement.id);
					const previousCookieName = previous.deviceCookie.split("=", 1)[0];
					const activeCookieName = active.deviceCookie.split("=", 1)[0];
					expect(
						cookies.some(
							(cookie) =>
								cookie.startsWith(`${previousCookieName}=;`) &&
								cookie.includes("Max-Age=0"),
						),
					).toBe(true);
					expect(
						cookies.some((cookie) => cookie.startsWith(`${activeCookieName}=`)),
					).toBe(false);
					const { rows } = await database.query<{ id: string }>(
						`SELECT id FROM ${schema}.session WHERE id=ANY($1::text[]) ORDER BY id`,
						[sessionIds],
					);
					expect(rows.map(({ id }) => id)).toEqual(
						[active.id, otherBrowser.id, replacement.id].sort(),
					);
					expect(
						(
							await database.query(
								`SELECT id FROM ${foreignSchema}.session WHERE id=$1 AND token=$2`,
								[previous.id, previous.token],
							)
						).rows,
					).toEqual([{ id: previous.id }]);
					const grantState = await database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${schema}."oauthAccessToken" WHERE "clientId"=$1
						 UNION ALL SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM ${schema}."oauthRefreshToken" WHERE "clientId"=$1`,
						[clientId],
					);
					expect(grantState.rows).toHaveLength(grants.length);
					for (const { kind, id } of grants)
						expect(grantState.rows.find((row) => row.id === id)).toEqual({
							id,
							revoked: kind === "access" || kind === "online",
							sessionId: kind === "unrelated" ? otherBrowser.id : null,
						});
					return await signedEvents(
						subscription,
						[
							password,
							eventEmail,
							userEmail,
							active.token,
							previous.token,
							otherBrowser.token,
							replacement.token,
							...grants.map(({ id }) => id),
						],
						new Map([[previous.id, "replaced-device"]]),
					);
				} finally {
					await database.query(
						`DELETE FROM ${foreignSchema}."user" WHERE id=$1`,
						[foreignOwner],
					);
					await database.query(
						`DELETE FROM ${schema}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${schema}.session WHERE id=ANY($1::text[])`,
						[sessionIds],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			if (identifier === "username")
				await database.query(
					`UPDATE ${schema}."user" SET username=$2 WHERE id=$1`,
					[eventUserId, username],
				);
			try {
				const native = await exercise("legacy");
				expect(native).toEqual([
					{
						event: {
							type: "session.deleted",
							outcome: "success",
							...(hasActiveCookie ? { actorId: userId } : {}),
							userId: eventUserId,
							targetId: "replaced-device",
							metadata: { path },
						},
					},
				]);
				expect(await exercise("owned")).toEqual(native);
			} finally {
				if (identifier === "username")
					await database.query(
						`UPDATE ${schema}."user" SET username=NULL WHERE id=$1`,
						[eventUserId],
					);
			}
		});

		it("delivers the native guest deletion events on sign-in to an existing account", async () => {
			const path = "/sign-in/email";
			const ip = "192.0.2.122";
			const policy = { ...defaultAuthPolicy, requireEmailVerification: false };
			const installed = installedNative(policy);
			const candidate = createOwnedProjectEngine({
				database,
				project: alpha,
				baseURL: origin,
				basePath: alpha.path,
				signingSecret: alpha.secret,
				policy,
				trustedOrigins: [],
				trustedIP: () => ip,
				accountLinks: {
					publicLinkBaseURL: `${origin}${alpha.path}`,
					defer: () => {},
					deliver: async () => {},
					beforeDelete: async () => undefined,
				},
			});
			const scope = `"${alpha.schemaName}"`;
			const otherScope = `"${beta.schemaName}"`;
			const responseCookies = (response: Response) =>
				response.headers
					.getSetCookie()
					.filter((cookie) => !/;\s*Max-Age=0(?:;|$)/i.test(cookie))
					.map((cookie) => cookie.split(";", 1)[0])
					.join("; ");
			async function exercise(writer: "legacy" | "owned") {
				const startRequest = request(`${alpha.path}/sign-in/anonymous`, {});
				startRequest.headers.set("x-real-ip", ip);
				const start = await installed.handler(startRequest);
				expect(start.status).toBe(200);
				const guestCookie = responseCookies(start);
				const guest = await installed.api.getSession({
					headers: new Headers({ cookie: guestCookie }),
				});
				expect(guest?.user).toMatchObject({ role: "guest", isAnonymous: true });
				if (!guest) throw new Error("Expected an active guest session.");
				const sibling = randomUUID();
				const siblingToken = randomUUID();
				const clientId = randomUUID();
				const grantId = randomUUID();
				const existing = await browserSession(eventEmail);
				await database.query(
					`INSERT INTO ${otherScope}."user" (id,name,email,role,"isAnonymous","emailVerified") VALUES ($1,'Guest',$2,'guest',true,false)`,
					[guest.user.id, guest.user.email],
				);
				for (const realm of [scope, otherScope])
					await database.query(
						`INSERT INTO ${realm}.session (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
						[sibling, siblingToken, guest.user.id],
					);
				await database.query(
					`INSERT INTO ${scope}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[clientId],
				);
				await database.query(
					`INSERT INTO ${scope}."oauthRefreshToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes) VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),'["offline_access"]')`,
					[grantId, sibling, guest.user.id, clientId],
				);
				const subscription = await endpoint(
					"legacy",
					`guest-upgrade-${writer}`,
					["session.deleted", "user.deleted"],
				);
				let replacement: string | undefined;
				try {
					const incoming = request(
						`${alpha.path}${path}`,
						{ email: eventEmail, password },
						guestCookie,
					);
					incoming.headers.set("x-real-ip", ip);
					const signedIn = await (writer === "legacy"
						? installed.handler(incoming)
						: candidate.dispatch(incoming));
					expect(signedIn.status).toBe(200);
					const active = await installed.api.getSession({
						headers: new Headers({ cookie: responseCookies(signedIn) }),
					});
					expect(active?.user.id).toBe(eventUserId);
					replacement = active?.session.id;
					const { rows } = await database.query(
						`SELECT EXISTS (SELECT 1 FROM ${scope}."user" WHERE id=$1) AS guest,
						 EXISTS (SELECT 1 FROM ${scope}.session WHERE "userId"=$1) AS guest_session,
						 EXISTS (SELECT 1 FROM ${scope}."oauthRefreshToken" WHERE id=$2) AS guest_grant,
						 EXISTS (SELECT 1 FROM ${scope}.session WHERE id=$3) AS existing_account_session,
						 EXISTS (SELECT 1 FROM ${otherScope}.session WHERE id=$4 AND "userId"=$1) AS other_realm`,
						[guest.user.id, grantId, existing.id, sibling],
					);
					expect(rows).toEqual([
						{
							guest: false,
							guest_session: false,
							guest_grant: false,
							existing_account_session: true,
							other_realm: true,
						},
					]);
					const events = await signedEvents(
						subscription,
						[
							password,
							guest.user.email,
							eventEmail,
							guest.session.token,
							siblingToken,
							grantId,
						],
						new Map([
							[guest.session.id, "guest-session"],
							[sibling, "guest-sibling"],
							[guest.user.id, "guest"],
						]),
					);
					for (const { event, user } of events) {
						expect(event.actorId).toBe(guest.user.id);
						expect(event.userId).toBe(guest.user.id);
						expect(user).toBeUndefined();
					}
					return events.map(({ event }) => ({
						...event,
						actorId: "guest",
						userId: "guest",
					}));
				} finally {
					await database.query(
						`DELETE FROM ${scope}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${scope}.session WHERE id=ANY($1::text[])`,
						[[existing.id, replacement ?? ""]],
					);
					for (const realm of [scope, otherScope])
						await database.query(`DELETE FROM ${realm}."user" WHERE id=$1`, [
							guest.user.id,
						]);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const native = await exercise("legacy");
			expect(native).toEqual(
				[
					{ type: "session.deleted", targetId: "guest-session" },
					{ type: "session.deleted", targetId: "guest-sibling" },
					{ type: "user.deleted", targetId: "guest" },
				].map((event) => ({
					...event,
					outcome: "success",
					actorId: "guest",
					userId: "guest",
					metadata: { path },
				})),
			);
			expect(await exercise("owned")).toEqual(native);
		});

		it("attributes device revocation to the active browser account in the signed session event", async () => {
			const realm = `"${alpha.schemaName}"`;
			const path = "/multi-session/revoke";
			async function exercise(writer: "legacy" | "owned") {
				const active = await browserSession(userEmail);
				const target = await browserSession(eventEmail);
				const sibling = await browserSession(eventEmail);
				expect(active.deviceCookie).toBeTruthy();
				expect(target.deviceCookie).toBeTruthy();
				const clientId = randomUUID();
				const grants = {
					access: randomUUID(),
					online: randomUUID(),
					offline: randomUUID(),
					unaffected: randomUUID(),
				};
				await database.query(
					`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[clientId],
				);
				await database.query(
					`INSERT INTO ${realm}."oauthAccessToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
					 VALUES ($4,$4,$1,$2,$3,now()+interval '1 day',now(),'["openid"]')`,
					[target.id, eventUserId, clientId, grants.access],
				);
				await database.query(
					`INSERT INTO ${realm}."oauthRefreshToken" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
					 VALUES ($4,$4,$1,$2,$3,now()+interval '1 day',now(),'["openid"]'),
					        ($5,$5,$1,$2,$3,now()+interval '1 day',now(),'["openid","offline_access"]'),
					        ($6,$6,$7,$2,$3,now()+interval '1 day',now(),'["openid"]')`,
					[
						target.id,
						eventUserId,
						clientId,
						grants.online,
						grants.offline,
						grants.unaffected,
						sibling.id,
					],
				);
				const subscription = await endpoint(
					"legacy",
					`device-revoke-${writer}`,
					["session.deleted"],
				);
				try {
					const activeCookies = `${active.cookie}; ${active.deviceCookie}`;
					const body = { sessionToken: target.token };
					expect((await send(writer, path, body, activeCookies)).status).toBe(
						401,
					);
					expect(
						(await send(writer, path, body, target.deviceCookie)).status,
					).toBe(401);
					expect(
						(await deliveries("legacy", subscription.endpoint.id)).total,
					).toBe(0);
					const cookies = `${activeCookies}; ${target.deviceCookie}`;
					for (let attempt = 0; attempt < 2; attempt++) {
						const response = await send(writer, path, body, cookies);
						expect(response.status).toBe(200);
						expect(await response.json()).toEqual({ status: true });
					}
					const events = await signedEvents(
						subscription,
						[
							password,
							userEmail,
							eventEmail,
							active.token,
							target.token,
							...Object.values(grants),
						],
						new Map([[target.id, "device"]]),
					);
					const sessions = await database.query<{ id: string; userId: string }>(
						`SELECT id,"userId" FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, target.id, sibling.id]],
					);
					expect(sessions.rows).toHaveLength(2);
					expect(sessions.rows).toEqual(
						expect.arrayContaining([
							{ id: active.id, userId },
							{ id: sibling.id, userId: eventUserId },
						]),
					);
					const state = await database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthAccessToken" WHERE id=$1
						 UNION ALL SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthRefreshToken" WHERE id=ANY($2::text[])`,
						[grants.access, [grants.online, grants.offline, grants.unaffected]],
					);
					expect(state.rows).toHaveLength(4);
					for (const [kind, id] of Object.entries(grants))
						expect(state.rows.find((row) => row.id === id)).toEqual({
							id,
							revoked: kind === "access" || kind === "online",
							sessionId: kind === "unaffected" ? sibling.id : null,
						});
					return events;
				} finally {
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, target.id, sibling.id]],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const native = await exercise("legacy");
			expect(native).toEqual([
				{
					event: {
						type: "session.deleted",
						outcome: "success",
						actorId: userId,
						userId: eventUserId,
						targetId: "device",
						metadata: { path },
					},
				},
			]);
			expect(await exercise("owned")).toEqual(native);
		});

		it.each([
			"/revoke-session",
			"/sdk/sessions/revoke",
		] as const)("preserves %s authority, grants and signed session revocation events", async (path) => {
			const sdk = path === "/sdk/sessions/revoke";
			const realm = `"${alpha.schemaName}"`;
			async function exercise(writer: "legacy" | "owned") {
				const active = await browserSession(eventEmail);
				const target = await browserSession(eventEmail);
				const foreign = await browserSession(userEmail);
				const clientId = randomUUID();
				const challengeId = randomUUID();
				const grants = [
					"access",
					"online",
					"offline",
					"sibling",
					"foreign",
				].map((kind) => ({ kind, id: randomUUID() }));
				await database.query(
					`INSERT INTO ${realm}."oauthClient" (id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
					[clientId],
				);
				for (const { kind, id } of grants) {
					const session =
						kind === "foreign" ? foreign : kind === "sibling" ? active : target;
					const owner = kind === "foreign" ? userId : eventUserId;
					const table =
						kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
					const scopes =
						kind === "offline" ? ["openid", "offline_access"] : ["openid"];
					await database.query(
						`INSERT INTO ${realm}."${table}" (id,token,"sessionId","userId","clientId","expiresAt","createdAt",scopes)
							 VALUES ($1,$1,$2,$3,$4,now()+interval '1 day',now(),$5)`,
						[id, session.id, owner, clientId, JSON.stringify(scopes)],
					);
				}
				await database.query(
					`INSERT INTO ${realm}.verification (id,identifier,value,"expiresAt") VALUES ($1,$2,$3,now()+interval '1 day')`,
					[challengeId, `trust-device-${challengeId}`, eventUserId],
				);
				const subscription = await endpoint(
					"legacy",
					`revoke-${sdk ? "sdk" : "token"}-${writer}`,
					["session.*"],
				);
				const body = (session: typeof active) =>
					sdk ? { id: session.id } : { token: session.token };
				try {
					const denied = await send(writer, path, body(target), "");
					expect(denied.status).toBe(401);
					if (sdk) expect(await denied.text()).toBe("");
					else
						expect(await denied.json()).toEqual({
							code: "UNAUTHORIZED",
							message: "Unauthorized",
						});
					const crossOrigin = await send(
						writer,
						path,
						body(target),
						active.cookie,
						"https://foreign.fixture.example",
					);
					expect(crossOrigin.status).toBe(403);
					const wrong = await send(writer, path, body(foreign), active.cookie);
					expect(wrong.status).toBe(sdk ? 404 : 200);
					expect(await wrong.json()).toEqual(
						sdk
							? {
									message:
										"This session does not belong to your project account.",
								}
							: { status: true },
					);
					expect(
						(
							await database.query(
								`SELECT 1 FROM ${realm}.session WHERE id=$1`,
								[target.id],
							)
						).rowCount,
					).toBe(1);
					const revoked = await send(writer, path, body(target), active.cookie);
					expect(revoked.status).toBe(200);
					expect(await revoked.json()).toEqual(
						sdk ? { success: true } : { status: true },
					);
					expect(revoked.headers.getSetCookie()).toEqual([]);
					const sessions = await database.query<{ id: string }>(
						`SELECT id FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, foreign.id, target.id]],
					);
					expect(sessions.rows.map(({ id }) => id).sort()).toEqual(
						[active.id, foreign.id].sort(),
					);
					const grantState = await database.query<{
						id: string;
						revoked: boolean;
						sessionId: string | null;
					}>(
						`SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthAccessToken" WHERE "clientId"=$1
							 UNION ALL SELECT id, revoked IS NOT NULL AS revoked, "sessionId" FROM ${realm}."oauthRefreshToken" WHERE "clientId"=$1`,
						[clientId],
					);
					expect(grantState.rows).toHaveLength(sdk ? 1 : 5);
					for (const { kind, id } of grants) {
						const grant = grantState.rows.find((row) => row.id === id);
						if (sdk && kind !== "foreign") expect(grant).toBeUndefined();
						else
							expect(grant).toEqual({
								id,
								revoked: kind === "access" || kind === "online",
								sessionId:
									kind === "foreign"
										? foreign.id
										: kind === "sibling"
											? active.id
											: null,
							});
					}
					expect(
						(
							await database.query(
								`SELECT 1 FROM ${realm}.verification WHERE id=$1`,
								[challengeId],
							)
						).rowCount,
					).toBe(sdk ? 0 : 1);
					const events = await signedEvents(
						subscription,
						[
							password,
							eventEmail,
							userEmail,
							active.token,
							target.token,
							foreign.token,
						],
						new Map([[target.id, "revoked"]]),
					);
					expect(
						events.filter(({ event }) => event.type === "session.deleted"),
					).toEqual([
						{
							event: {
								type: "session.deleted",
								outcome: "success",
								actorId: eventUserId,
								userId: eventUserId,
								targetId: "revoked",
								metadata: { path },
							},
						},
					]);
					const self = await send(writer, path, body(active), active.cookie);
					expect(self.status).toBe(200);
					expect(await self.json()).toEqual(
						sdk ? { success: true } : { status: true },
					);
					if (sdk)
						expect(self.headers.getSetCookie()).toEqual(
							expect.arrayContaining([
								expect.stringMatching(/\.session_token=;.*Max-Age=0/),
							]),
						);
					else expect(self.headers.getSetCookie()).toEqual([]);
					return events;
				} finally {
					await database.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[clientId],
					);
					await database.query(
						`DELETE FROM ${realm}.session WHERE id=ANY($1::text[])`,
						[[active.id, target.id, foreign.id]],
					);
					await database.query(
						`DELETE FROM ${realm}.verification WHERE id=$1`,
						[challengeId],
					);
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const native = await exercise("legacy");
			expect(await exercise("owned")).toEqual(native);
		});

		it("keeps a session whose concurrent renewal commits during expiration cleanup", async () => {
			const active = await browserSession(eventEmail);
			const realm = `"${alpha.schemaName}"`;
			const renewal = await database.connect();
			let pending: Promise<Response> | undefined;
			let committed = false;
			try {
				await database.query(
					`UPDATE ${realm}.session SET "expiresAt"=statement_timestamp()+interval '2 seconds' WHERE id=$1`,
					[active.id],
				);
				await renewal.query("BEGIN");
				const renewed = await renewal.query(
					`UPDATE ${realm}.session SET "expiresAt"=statement_timestamp()+interval '7 days'
					 WHERE id=$1 AND "expiresAt">statement_timestamp()`,
					[active.id],
				);
				expect(renewed.rowCount).toBe(1);
				await expect
					.poll(
						async () => {
							const { rows } = await database.query<{ expired: boolean }>(
								`SELECT "expiresAt"<=statement_timestamp() AS expired FROM ${realm}.session WHERE id=$1`,
								[active.id],
							);
							return rows[0]?.expired;
						},
						{ timeout: 5000 },
					)
					.toBe(true);
				pending = owned.readSession(
					request(
						`${alpha.path}/get-session?disableRefresh=true`,
						undefined,
						active.cookie,
					),
				);
				void pending.catch(() => {});
				await expect
					.poll(
						async () => {
							const { rows } = await database.query<{ waiting: boolean }>(
								`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
						 AND wait_event_type='Lock' AND query LIKE '%WHERE token = ANY($1::text[])%' AND query LIKE '%FOR UPDATE%') AS waiting`,
							);
							return rows[0]?.waiting;
						},
						{ timeout: 4000 },
					)
					.toBe(true);
				await renewal.query("COMMIT");
				committed = true;
				const result = await pending;
				expect(result.status).toBe(200);
				expect(await result.json()).toMatchObject({
					session: { id: active.id },
				});
				expect(result.headers.getSetCookie()).toEqual([]);
				expect(
					(
						await database.query(
							`SELECT id FROM ${realm}."allauthEvent" WHERE type='session.deleted' AND "targetId"=$1`,
							[active.id],
						)
					).rows,
				).toEqual([]);
			} finally {
				if (!committed) await renewal.query("ROLLBACK");
				renewal.release();
				await pending?.catch(() => {});
				await database.query(`DELETE FROM ${realm}.session WHERE id=$1`, [
					active.id,
				]);
			}
		});

		it("delivers native bulk session events for the exact deleted sessions and request actor", async () => {
			async function exercise(writer: "legacy" | "owned") {
				await database.query(
					`DELETE FROM "${alpha.schemaName}"."session" WHERE "userId"=$1`,
					[eventUserId],
				);
				const active = await browserSession(eventEmail);
				const sibling = await browserSession(eventEmail);
				const expired = await browserSession(eventEmail);
				await database.query(
					`UPDATE "${alpha.schemaName}"."session" SET "expiresAt"=statement_timestamp()-interval '1 minute' WHERE id=$1`,
					[expired.id],
				);
				const subscription = await endpoint(
					"legacy",
					`bulk-payload-${writer}`,
					["session.*", "session.deleted"],
				);
				try {
					for (const path of [
						"/revoke-other-sessions",
						"/revoke-other-sessions",
						"/revoke-sessions",
					])
						expect((await send(writer, path, {}, active.cookie)).status).toBe(
							200,
						);
					expect((await send(writer, "/revoke-sessions", {}, "")).status).toBe(
						401,
					);
					const sessions = new Map([
						[active.id, "current"],
						[sibling.id, "sibling"],
						[expired.id, "expired"],
					]);
					const events = await signedEvents(
						subscription,
						[
							password,
							eventEmail,
							active.cookie,
							sibling.cookie,
							expired.cookie,
						],
						sessions,
					);
					for (const { user } of events) expect(user).toBeUndefined();
					return events;
				} finally {
					expect(
						(
							await send("legacy", `${base}/delete`, {
								id: subscription.endpoint.id,
							})
						).status,
					).toBe(200);
				}
			}
			const nativeEvents = await exercise("legacy");
			expect(
				nativeEvents
					.filter(({ event }) => event.type === "session.deleted")
					.map(({ event }) => event.targetId)
					.sort(),
			).toEqual(["current", "expired", "sibling"]);
			expect(await exercise("owned")).toEqual(nativeEvents);
		});
	},
);
