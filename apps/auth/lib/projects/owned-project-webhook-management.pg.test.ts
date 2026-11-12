import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { symmetricDecrypt } from "better-auth/crypto";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
	webhookSignature,
} from "../control/webhook-contract";
import {
	createControlWebhooks,
	deliverPendingWebhooks,
} from "../control/webhooks";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";
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
const resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const base = "/control/webhooks";
const migrations = [
	"001-initial-auth",
	"002-control-plane",
	"004-webhooks",
	"005-free-plugins",
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
	const control = allauthControl();
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
			const engine = (project: typeof alpha) =>
				createOwnedProjectEngine({
					database,
					project,
					baseURL: origin,
					basePath: project.path,
					signingSecret: project.secret,
					policy: defaultAuthPolicy,
					trustedOrigins: [],
					trustedIP: () => "192.0.2.46",
					adminDeletion: {
						id: project.id,
						workspaceId: project.workspaceId,
						platformOrigin: origin,
						readWorkspacePrincipal: readRoot,
					},
					webhookManagement: { resolver },
				});
			owned = engine(alpha);
			other = engine(beta);
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
		async function endpoint(engine: "legacy" | "owned", label: string) {
			const response = await send(engine, `${base}/create`, {
				url: `https://${label}.webhook.fixture.example/receive?state=1`,
				description: "  Fixture  ",
				eventTypes: ["auth.sign-in", "auth.sign-in"],
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
			const rotated = await send("owned", `${base}/rotate`, {
				id: old.endpoint.id,
			});
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
	},
);
