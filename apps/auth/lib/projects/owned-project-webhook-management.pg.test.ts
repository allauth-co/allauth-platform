import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { oauthProvider } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import { symmetricDecrypt } from "better-auth/crypto";
import {
	admin,
	haveIBeenPwned,
	jwt,
	multiSession,
	organization,
} from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { authPolicyPlugin } from "../auth-policy/plugin";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import { recordControlEvent } from "../control/events";
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
import {
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "../enterprise";
import { featureBoundaries } from "../features/server";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";
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
			},
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			plugins: [
				admin(),
				...(realm
					? [
							featureBoundaries(),
							haveIBeenPwned({ paths: ["/change-password"] }),
							authPolicyPlugin(defaultAuthPolicy),
							multiSession({ maximumSessions: 5 }),
							organization(),
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
					for (const migration of migrations)
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
