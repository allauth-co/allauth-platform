import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runWithAdapter } from "@better-auth/core/context";
import { getTestInstance } from "better-auth/test";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { projectProxySecret } from "./proxy";
import type { Project } from "./registry";
import {
	consumeProxySessionCheck,
	createSessionCheckCoordinator,
	handleProjectAuthentication,
} from "./session-introspection";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const archive = "allauth-react-1.0.0.tgz";
const origin = "https://legacy-introspection.example";
const environment = {
	BETTER_AUTH_SECRET: "legacy-introspection-platform-fixture-secret",
};
const secret = "legacy-introspection-project-session-fixture-secret";
const project = {
	id: "00000000-0000-4000-8000-000000000075",
	slug: "legacy-introspection",
	proxyVersion: "legacy-fixture",
	origins: [origin],
} as Project;
type LegacyProxy = (
	request: Request,
	context: { params: Promise<{ all: string[] }> },
) => Promise<Response>;
type LegacyModule = {
	createAllAuthProxy: (options: {
		project: string;
		proxySecret: string;
		appOrigin: string;
	}) => LegacyProxy;
};

describe.skipIf(!existsSync(fixturePath))(
	"unchanged 1.0.0 integration under admin page fan-out",
	() => {
		const databaseName = `allauth_legacy_qa_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let pools: Pool[] = [];
		let directory: string | undefined;
		let proxy: LegacyProxy;
		const backgroundErrors: string[] = [];
		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			) {
				throw new Error(
					"Only the dedicated local AllAuth fixture is permitted.",
				);
			}
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			admin.on("error", (error: Error) => {
				backgroundErrors.push(error.name);
			});
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			pools = [0, 1].map(
				() => new Pool({ connectionString: url.toString(), max: 2 }),
			);
			for (const pool of pools)
				pool.on("error", (error: Error) => {
					backgroundErrors.push(error.name);
				});
			const definition = readFileSync(
				new URL("../../migrations/001-initial-auth.sql", import.meta.url),
				"utf8",
			).match(/create table "rateLimit"[^;]+;/)?.[0];
			if (!definition)
				throw new Error("Canonical rate-limit table is missing.");
			await pools[0].query(definition);
			directory = await mkdtemp(join(tmpdir(), "allauth-legacy-load-"));
			const extracted = spawnSync("tar", [
				"-xzf",
				fileURLToPath(new URL(`../../public/sdk/${archive}`, import.meta.url)),
				"-C",
				directory,
			]);
			expect(extracted.status).toBe(0);
			await symlink(
				fileURLToPath(new URL("../../node_modules", import.meta.url)),
				join(directory, "node_modules"),
				"dir",
			);
			const sdk = (await import(
				/* @vite-ignore */ pathToFileURL(join(directory, "package/next.ts"))
					.href
			)) as LegacyModule;
			proxy = sdk.createAllAuthProxy({
				project: project.slug,
				proxySecret: projectProxySecret(project, environment),
				appOrigin: origin,
			});
		});
		afterAll(async () => {
			vi.restoreAllMocks();
			await Promise.all(pools.map((pool) => pool.end()));
			if (admin) {
				try {
					await admin.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
				} finally {
					await admin.end();
				}
			}
			if (directory) await rm(directory, { recursive: true, force: true });
			expect(
				backgroundErrors,
				"PostgreSQL fixture had unexpected background connection errors.",
			).toEqual([]);
		});

		/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
		it("serves 384 page/API/prefetch checks for two real users on two replicas and then observes revocation", async () => {
			const fixture = await getTestInstance(
				{
					secret,
					basePath: `/api/projects/${project.slug}/auth`,
					advanced: { cookiePrefix: `allauth_project_${project.slug}` },
					session: { updateAge: 0 },
					logger: { disabled: true },
				},
				{ disableTestUser: true },
			);
			const context = await fixture.auth.$context;
			const users = await Promise.all(
				[0, 1].map(async (index) => {
					const response = await fixture.auth.api.signUpEmail({
						body: {
							name: `Legacy fixture ${index}`,
							email: `legacy-${index}@fixture.example`,
							password: "fixture-password-long-enough",
						},
						asResponse: true,
					});
					const data = (await response.json()) as { user: { id: string } };
					return {
						id: data.user.id,
						cookie: response.headers
							.getSetCookie()
							.map((value) => value.split(";", 1)[0])
							.join("; "),
					};
				}),
			);
			// Force an ordinary native refresh so every member of the first cohort
			// must receive its own response with the provider's Set-Cookie headers.
			await context.adapter.updateMany({
				model: "session",
				where: [],
				update: { expiresAt: new Date(Date.now() + 86400000) },
			});
			let upstreamRequests = 0;
			let nativeReads = 0;
			const latencies: number[] = [];
			const replicas = pools.map((pool) => ({
				coordinator: createSessionCheckCoordinator(),
				scope: fixture.auth,
				diagnostic: () => {},
				consume: (key: string) => consumeProxySessionCheck(pool, key),
				fallback: (request: Request) => fixture.auth.handler(request),
				session: async (headers: Headers) => {
					nativeReads++;
					return runWithAdapter(context.adapter, () =>
						fixture.auth.api.getSession({
							headers,
							query: { disableCookieCache: true },
							asResponse: true,
						}),
					);
				},
			}));
			vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
				const request = new Request(input, init);
				const replica = replicas[upstreamRequests++ % replicas.length];
				return handleProjectAuthentication(
					request,
					project,
					environment,
					secret,
					replica,
				);
			});
			const check = async (user: (typeof users)[number]) => {
				const started = performance.now();
				const response = await proxy(
					new Request(`${origin}/api/allauth/get-session`, {
						headers: { cookie: user.cookie, origin },
					}),
					{ params: Promise.resolve({ all: ["get-session"] }) },
				);
				latencies.push(performance.now() - started);
				return {
					response,
					user,
					body: (await response.json()) as {
						user?: { id: string };
						session?: { id: string };
						code?: string;
					} | null,
				};
			};
			const results: Awaited<ReturnType<typeof check>>[] = [];
			// One layout, one page, sixteen API consumers and six prefetched destinations.
			// The integration itself performs no coalescing or prefetch suppression.
			for (let wave = 0; wave < 8; wave++) {
				if (wave) await new Promise((resolve) => setTimeout(resolve, 1200));
				results.push(
					...(await Promise.all(
						users.flatMap((user) =>
							Array.from({ length: 24 }, () => check(user)),
						),
					)),
				);
			}
			expect(results).toHaveLength(384);
			expect(
				results.filter(({ response }) => response.status === 200),
			).toHaveLength(384);
			for (const result of results) {
				expect(result.body?.user?.id).toBe(result.user.id);
				expect(result.response.headers.get("cache-control")).toBe("no-store");
				expect(JSON.stringify(result.body)).not.toMatch(/"token"/);
			}
			for (const { response } of results.slice(0, 48)) {
				expect(
					response.headers
						.getSetCookie()
						.some((value) => value.includes(".session_token=")),
				).toBe(true);
			}
			expect(nativeReads).toBeLessThanOrEqual(32);
			const readsBeforeRevoke = nativeReads;
			await context.adapter.deleteMany({
				model: "session",
				where: [{ field: "userId", value: users[0].id }],
			});
			const revoked = await check(users[0]);
			expect(revoked.body).toBeNull();
			expect(
				revoked.response.headers
					.getSetCookie()
					.some((value) => value.includes("Max-Age=0")),
			).toBe(true);
			expect((await check(users[1])).body?.user?.id).toBe(users[1].id);
			expect(nativeReads).toBeGreaterThan(readsBeforeRevoke);
			latencies.sort((a, b) => a - b);
			process.stdout.write(
				JSON.stringify({
					fixture: "unchanged-sdk-1.0.0",
					requests: results.length,
					replicas: replicas.length,
					users: users.length,
					nativeReadsBeforeRevoke: readsBeforeRevoke,
					nativeReadReductionPercent:
						Math.round((1 - readsBeforeRevoke / results.length) * 1000) / 10,
					p50Ms: Math.round(latencies[Math.floor(latencies.length * 0.5)]),
					p95Ms: Math.round(latencies[Math.floor(latencies.length * 0.95)]),
					p99Ms: Math.round(latencies[Math.floor(latencies.length * 0.99)]),
				}) + "\n",
			);
		}, 30000);

		/** @see docs/content/docs/integrations/allauth-signed-session-introspection.mdx */
		it.skipIf(process.env.ALLAUTH_SESSION_LOAD !== "1")(
			"sustains a full minute at 20 checks/second/user after a 120-check burst",
			async () => {
				vi.restoreAllMocks();
				const fixture = await getTestInstance(
					{
						secret,
						basePath: `/api/projects/${project.slug}/auth`,
						advanced: { cookiePrefix: `allauth_project_${project.slug}` },
						session: { updateAge: 0 },
						logger: { disabled: true },
					},
					{ disableTestUser: true },
				);
				const context = await fixture.auth.$context;
				const users = await Promise.all(
					[0, 1].map(async (index) => {
						const response = await fixture.auth.api.signUpEmail({
							body: {
								name: `Sustained fixture ${index}`,
								email: `sustained-${index}@fixture.example`,
								password: "fixture-password-long-enough",
							},
							asResponse: true,
						});
						const body = (await response.json()) as { user: { id: string } };
						return {
							id: body.user.id,
							cookie: response.headers
								.getSetCookie()
								.map((value) => value.split(";", 1)[0])
								.join("; "),
						};
					}),
				);
				let upstreamRequests = 0;
				let nativeReads = 0;
				const latencies: number[] = [];
				const replicas = pools.map((pool) => ({
					coordinator: createSessionCheckCoordinator(),
					scope: fixture.auth,
					diagnostic: () => {},
					consume: (key: string) => consumeProxySessionCheck(pool, key),
					fallback: (request: Request) => fixture.auth.handler(request),
					session: async (headers: Headers) => {
						nativeReads++;
						return runWithAdapter(context.adapter, () =>
							fixture.auth.api.getSession({
								headers,
								query: { disableCookieCache: true },
								asResponse: true,
							}),
						);
					},
				}));
				vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) =>
					handleProjectAuthentication(
						new Request(input, init),
						project,
						environment,
						secret,
						replicas[upstreamRequests++ % replicas.length],
					),
				);
				let successes = 0;
				const wave = async (count: number) => {
					const results = await Promise.all(
						users.flatMap((user) =>
							Array.from({ length: count }, async () => {
								const started = performance.now();
								const response = await proxy(
									new Request(`${origin}/api/allauth/get-session`, {
										headers: { cookie: user.cookie, origin },
									}),
									{ params: Promise.resolve({ all: ["get-session"] }) },
								);
								latencies.push(performance.now() - started);
								const body = (await response.json()) as {
									user?: { id: string };
								} | null;
								return {
									status: response.status,
									actualUser: body?.user?.id,
									expectedUser: user.id,
								};
							}),
						),
					);
					for (const result of results) {
						expect(result.status).toBe(200);
						expect(result.actualUser).toBe(result.expectedUser);
						successes++;
					}
				};
				const started = performance.now();
				await wave(120);
				for (let second = 0; second < 60; second++) {
					await new Promise((resolve) => setTimeout(resolve, 1000));
					await wave(20);
				}
				expect(successes).toBe(2640);
				expect(nativeReads).toBeLessThanOrEqual(244);
				latencies.sort((a, b) => a - b);
				process.stdout.write(
					JSON.stringify({
						fixture: "unchanged-sdk-1.0.0-sustained",
						requests: successes,
						durationSeconds:
							Math.round((performance.now() - started) / 100) / 10,
						replicas: replicas.length,
						users: users.length,
						burstPerUser: 120,
						sustainedChecksPerSecondPerUser: 20,
						nativeReads,
						nativeReadReductionPercent:
							Math.round((1 - nativeReads / successes) * 1000) / 10,
						p50Ms: Math.round(latencies[Math.floor(latencies.length * 0.5)]),
						p95Ms: Math.round(latencies[Math.floor(latencies.length * 0.95)]),
						p99Ms: Math.round(latencies[Math.floor(latencies.length * 0.99)]),
					}) + "\n",
				);
			},
			90000,
		);
	},
);
