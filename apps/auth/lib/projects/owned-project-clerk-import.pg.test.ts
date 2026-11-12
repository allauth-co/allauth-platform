import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { runWithAdapter } from "@better-auth/core/context";
import { hash } from "bcryptjs";
import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { AuthEnvironment } from "../configuration";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createWorkspace } from "../workspaces/repository";
import { projectManagement } from "./management-plugin";
import { ownedClerkImportPath } from "./owned-project-clerk-import";
import { legacyProjectPlatformAuthority } from "./legacy-project-platform-authority";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createOwnedProjectRuntimeCandidate } from "./owned-project-runtime-factory";
import type { Project } from "./registry";
import { projectRegistryPool, provisionProject } from "./registry";
import { projectSecret } from "./runtime";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const appRoot = fileURLToPath(new URL("../..", import.meta.url));
const origin = "https://clerk-import.fixture.example";
const password = "Synthetic-Clerk-password-7!";
const rootId = "clerk-import-workspace-owner";
const rootEmail = "owner@clerk-import.fixture.example";
const sourceInstance = "ins_isolated_fixture";
const authSecret = "disposable-clerk-import-platform-signing-secret";
const subject = 'external-"subject"-日本語';

function request(path: string, body: object, cookie?: string, caller = origin) {
	return new Request(`${origin}${path}`, {
		method: "POST",
		headers: {
			origin: caller,
			"content-type": "application/json",
			...(cookie ? { cookie } : {}),
		},
		body: JSON.stringify(body),
	});
}

async function nativeInstance(
	database: Pool,
	basePath: string,
	secret: string,
	project?: Project,
	readRoot?: (headers: Headers) => Promise<ControlPrincipal | null>,
) {
	const storage = new Kysely<Record<string, Record<string, unknown>>>({
		dialect: new PostgresDialect({ pool: database }),
	});
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret,
			logger: { disabled: true },
			database: { db: storage, type: "postgres", transaction: true },
			advanced: {
				cookiePrefix: project
					? `allauth_project_${project.slug}`
					: "better-auth",
			},
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			user: {
				additionalFields: {
					privateMetadata: {
						type: "json",
						required: false,
						returned: false,
						input: false,
					},
					publicMetadata: { type: "json", required: false, input: false },
				},
			},
			plugins: [
				admin(),
				allauthControl(),
				...(project && readRoot
					? [
							projectManagement({
								projectId: project.id,
								projectSlug: project.slug,
								baseURL: origin,
								async requirePlatformAdmin(ctx) {
									const actor = await readRoot(ctx.headers ?? new Headers());
									if (!actor) throw new APIError("FORBIDDEN");
									return actor;
								},
							}),
						]
					: []),
			],
		},
		{ disableTestUser: true },
	);
	return auth;
}

function importUser(
	sourceUserId: string,
	passwordHash: string,
	appleSubject: string,
) {
	return {
		sourceUserId,
		email: `${sourceUserId}@clerk-import.fixture.example`,
		emailVerified: true,
		name: `Fixture ${sourceUserId}`,
		createdAt: "2025-01-01T05:00:00.000Z",
		updatedAt: "2025-01-02T05:00:00.000Z",
		passwordHash,
		passwordHasher: "bcrypt",
		publicMetadata: { migration: true },
		privateMetadata: { fixture: "private" },
		socialAccounts: [{ provider: "apple", subject: appleSubject }],
	};
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated Clerk import across project engines",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const pools: Pool[] = [];
		let administrator: Pool;
		let database: Pool;
		let project: Project;
		let env: AuthEnvironment;
		let root: Awaited<ReturnType<typeof nativeInstance>>;
		let legacy: Awaited<ReturnType<typeof nativeInstance>>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let rootCookie: string;
		let passwordHash: string;
		let path: string;
		let created = false;

		async function readRoot(
			headers: Headers,
		): Promise<ControlPrincipal | null> {
			const session = await runWithAdapter((await root.$context).adapter, () =>
				root.api.getSession({ headers, query: { disableCookieCache: true } }),
			);
			if (!session) return null;
			return {
				user: {
					...session.user,
					role: session.user.role ?? undefined,
					banned: session.user.banned ?? undefined,
				},
				session: {
					id: session.session.id,
					userId: session.session.userId,
					impersonatedBy: session.session.impersonatedBy ?? undefined,
				},
			};
		}

		beforeAll(async () => {
			const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error("Clerk import requires isolated fixture PostgreSQL.");
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			const runtime: NodeJS.ProcessEnv = {
				PATH: process.env.PATH,
				NODE_ENV: "test",
				DATABASE_URL: url.href,
				AUTH_RUNTIME: "node",
				ALLAUTH_AUTH_URL: origin,
				BETTER_AUTH_URL: origin,
				ALLAUTH_AUTH_SECRET: authSecret,
				BETTER_AUTH_SECRET: authSecret,
				SCIM_CREDENTIAL_HASH_SECRET: "disposable-clerk-import-scim-key",
				TRUSTED_ORIGINS: "",
				EMAIL_FROM: "",
			};
			await promisify(execFile)(
				process.execPath,
				["scripts/database.mjs", "migrate"],
				{ cwd: appRoot, env: runtime },
			);
			env = { ...runtime, EMAIL: { async send() {} } };
			database = projectRegistryPool(env);
			pools.push(database);
			const rootDatabase = new Pool({
				connectionString: url.href,
				max: 2,
				options: "-c search_path=public",
			});
			pools.push(rootDatabase);
			root = await nativeInstance(rootDatabase, "/api/auth", authSecret);
			passwordHash = await hash(password, 10);
			await rootDatabase.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified",role) VALUES ($1,'Fixture Owner',$2,true,'user');
			`,
				[rootId, rootEmail],
			);
			await rootDatabase.query(
				`INSERT INTO public."account" (id,"accountId","providerId","userId",password,"updatedAt")
			 VALUES ($1,$2,'credential',$2,$3,now())`,
				[randomUUID(), rootId, passwordHash],
			);
			const signed = await root.handler(
				request("/api/auth/sign-in/email", { email: rootEmail, password }),
			);
			expect(signed.status).toBe(200);
			rootCookie = signed.headers
				.getSetCookie()
				.map((entry) => entry.split(";", 1)[0])
				.join("; ");
			const actor = await readRoot(new Headers({ cookie: rootCookie }));
			if (!actor)
				throw new Error(
					"Fixture workspace owner has no live platform session.",
				);
			const currentDirectory = vi
				.spyOn(process, "cwd")
				.mockReturnValue(appRoot);
			try {
				const { workspace } = await createWorkspace(
					actor,
					{ name: "Clerk Import", slug: "clerk-import" },
					env,
				);
				project = await provisionProject(
					{
						name: "Clerk Import",
						slug: "clerk-import-fixture",
						primaryOrigin: "https://app.clerk-import.fixture.example",
						environment: "development",
						origins: [],
					},
					{
						clientId: "isolated-clerk-import",
						clientSecret: "synthetic-clerk-broker-secret",
					},
					rootId,
					env,
					{
						workspaceId: workspace.id,
						principal: actor,
					},
				);
			} finally {
				currentDirectory.mockRestore();
			}
			path = `/api/projects/${project.slug}/auth`;
			const scoped = new Pool({
				connectionString: url.href,
				max: 3,
				options: `-c search_path=${project.schemaName}`,
			});
			pools.push(scoped);
			const secret = projectSecret(env, project.id);
			legacy = await nativeInstance(scoped, path, secret, project, readRoot);
			owned = createOwnedProjectEngine({
				database,
				project,
				baseURL: origin,
				basePath: path,
				signingSecret: secret,
				policy: defaultAuthPolicy,
				trustedOrigins: [],
				trustedIP: () => "192.0.2.46",
				adminDeletion: {
					id: project.id,
					workspaceId: project.workspaceId,
					platformOrigin: origin,
					readWorkspacePrincipal: readRoot,
				},
			});
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
			body: object,
			cookie = rootCookie,
			caller = origin,
		) {
			const incoming = request(
				path + ownedClerkImportPath,
				body,
				cookie,
				caller,
			);
			return engine === "legacy"
				? legacy.handler(incoming)
				: owned.dispatch(incoming);
		}

		it("preserves dry runs, credential and provider IDs, conflict outcomes, live scope, and rollback", async () => {
			const nativeUser = importUser("native-clerk", passwordHash, subject);
			const candidateUser = importUser(
				"owned-clerk",
				passwordHash,
				"other-subject",
			);
			const nativeBody = { sourceInstance, users: [nativeUser] };
			const candidateBody = { sourceInstance, users: [candidateUser] };
			const dry = await send("owned", candidateBody);
			expect(dry.status).toBe(200);
			const preview = (await dry.json()) as {
				users: Array<{ userId: string }>;
			};
			expect(preview).toMatchObject({
				project: project.slug,
				projectId: project.id,
				dryRun: true,
				created: 0,
				users: [{ status: "would_create" }],
			});
			expect(
				(
					await database.query(
						`SELECT count(*)::int AS count FROM "${project.schemaName}"."user"`,
					)
				).rows[0]?.count,
			).toBe(0);

			const createdNative = await send("legacy", {
				...nativeBody,
				dryRun: false,
			});
			expect(createdNative.status).toBe(200);
			const nativeResult = (await createdNative.json()) as {
				users: Array<{ userId: string }>;
			};
			expect(nativeResult).toMatchObject({
				created: 1,
				users: [{ status: "created" }],
			});
			const inspectedNative = await send("owned", {
				...nativeBody,
				dryRun: false,
			});
			expect(await inspectedNative.json()).toMatchObject({
				existing: 1,
				users: [{ userId: nativeResult.users[0].userId, status: "existing" }],
			});

			expect((await send("owned", candidateBody, "")).status).toBe(403);
			expect(
				(
					await send(
						"owned",
						candidateBody,
						rootCookie,
						"https://foreign.fixture.example",
					)
				).status,
			).toBe(403);
			expect(
				(await send("owned", { ...candidateBody, projectId: randomUUID() }))
					.status,
			).toBe(400);
			const createdOwned = await send("owned", {
				...candidateBody,
				dryRun: false,
			});
			expect(createdOwned.status).toBe(200);
			const ownedResult = await createdOwned.json();
			expect(ownedResult).toMatchObject({
				created: 1,
				users: [{ userId: preview.users[0].userId, status: "created" }],
			});
			expect(JSON.stringify(ownedResult)).not.toContain(passwordHash);
			const inspectedOwned = await send("legacy", {
				...candidateBody,
				dryRun: false,
			});
			expect(await inspectedOwned.json()).toMatchObject({
				existing: 1,
				users: [{ userId: preview.users[0].userId, status: "existing" }],
			});
			const changed = await send("owned", {
				...nativeBody,
				users: [{ ...nativeUser, name: "Changed source" }],
			});
			expect(await changed.json()).toMatchObject({
				conflicts: 1,
				users: [{ reason: "source_changed" }],
			});
			const conflicts = await send("owned", {
				sourceInstance,
				users: [
					{ ...nativeUser, sourceUserId: "different-email-source" },
					importUser("provider-conflict", passwordHash, subject),
					{
						...importUser("mfa", passwordHash, "mfa-subject"),
						twoFactorEnabled: true,
					},
				],
			});
			expect(await conflicts.json()).toMatchObject({
				conflicts: 3,
				users: [
					{ reason: "email_conflict" },
					{ reason: "provider_conflict" },
					{ reason: "mfa_unsupported" },
				],
			});

			const nativeLogin = await owned.dispatch(
				request(`${path}/sign-in/email`, { email: nativeUser.email, password }),
			);
			expect(nativeLogin.status).toBe(200);
			expect(await nativeLogin.json()).toMatchObject({
				user: { id: nativeResult.users[0].userId },
			});
			const rollbackLogin = await legacy.handler(
				request(`${path}/sign-in/email`, {
					email: candidateUser.email,
					password,
				}),
			);
			expect(rollbackLogin.status).toBe(200);
			expect(await rollbackLogin.json()).toMatchObject({
				user: { id: preview.users[0].userId },
			});

			const candidate = () =>
				createOwnedProjectRuntimeCandidate({
					database,
					project,
					env,
					policy: defaultAuthPolicy,
					platformAuthority: legacyProjectPlatformAuthority,
					transport: { kind: "direct" },
					signingSecret: projectSecret(env, project.id),
					credentialHashSecret: "disposable-clerk-fixture-scoped-scim-secret",
					trustedIP: () => "192.0.2.46",
					defer() {},
				});
			const runtime = await candidate();
			const config = await runtime.dispatch(
				new Request(`${origin}${path}/sdk/config`),
			);
			expect(await config.json()).toMatchObject({
				apple: false,
				google: false,
			});
			const profile = await database.query(
				`SELECT a.id, a."userId", u."privateMetadata"
			 FROM "${project.schemaName}"."account" a JOIN "${project.schemaName}"."user" u ON u.id=a."userId"
			 WHERE a."providerId"='apple' AND a."accountId"=$1`,
				[subject],
			);
			expect(profile.rows[0]).toMatchObject({
				userId: nativeResult.users[0].userId,
				privateMetadata: {
					allauthClerkMigration: {
						version: 1,
						sourceInstance,
						sourceUserId: nativeUser.sourceUserId,
					},
				},
			});
			await database.query(
				`UPDATE "${project.schemaName}"."account" SET "idToken"='fixture-token' WHERE id=$1`,
				[profile.rows[0].id],
			);
			await expect(candidate()).rejects.toThrow(
				"stored features outside the candidate scope",
			);
			await database.query(
				`UPDATE "${project.schemaName}"."account" SET "idToken"=NULL,id=$1 WHERE id=$2`,
				[randomUUID(), profile.rows[0].id],
			);
			await expect(candidate()).rejects.toThrow(
				"stored features outside the candidate scope",
			);

			const audit = await database.query(
				`SELECT type, "actorId", metadata FROM "${project.schemaName}"."allauthEvent" WHERE type='admin.clerk-import'`,
			);
			expect(audit.rows).toHaveLength(2);
			expect(audit.rows).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						actorId: rootId,
						metadata: {
							path: ownedClerkImportPath,
							signal: "clerk-import",
							version: 1,
						},
					}),
				]),
			);
			const sharedSubject = "clerk-concurrent-provider-subject";
			const concurrent = await Promise.all(
				["concurrent-a", "concurrent-b"].map(async (sourceId) => {
					const response = await send("owned", {
						sourceInstance,
						dryRun: false,
						users: [importUser(sourceId, passwordHash, sharedSubject)],
					});
					expect(response.status).toBe(200);
					return response.json();
				}),
			);
			expect(concurrent).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						created: 1,
						users: [
							{
								status: "created",
								userId: expect.any(String),
								sourceUserId: expect.any(String),
								sourceUpdatedAt: expect.any(String),
							},
						],
					}),
					expect.objectContaining({
						conflicts: 1,
						users: [expect.objectContaining({ reason: "provider_conflict" })],
					}),
				]),
			);
			const auditTable = `"${project.schemaName}"."allauthEvent"`;
			await database.query(
				`ALTER TABLE ${auditTable} ADD CONSTRAINT fixture_clerk_event_rejected CHECK (type <> 'admin.clerk-import') NOT VALID`,
			);
			const atomic = importUser(
				"clerk-atomic",
				passwordHash,
				"clerk-atomic-subject",
			);
			try {
				const failed = await send("owned", {
					sourceInstance,
					dryRun: false,
					users: [atomic],
				});
				expect(await failed.json()).toMatchObject({
					conflicts: 1,
					users: [{ reason: "write_conflict" }],
				});
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${project.schemaName}"."user" WHERE email=$1`,
							[atomic.email],
						)
					).rowCount,
				).toBe(0);
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${project.schemaName}"."account" WHERE "accountId"=$1`,
							[atomic.socialAccounts[0].subject],
						)
					).rowCount,
				).toBe(0);
			} finally {
				await database.query(
					`ALTER TABLE ${auditTable} DROP CONSTRAINT fixture_clerk_event_rejected`,
				);
			}
			await database.query(
				'UPDATE public."session" SET "expiresAt"=now()-interval \'1 second\' WHERE "userId"=$1',
				[rootId],
			);
			expect((await send("owned", candidateBody)).status).toBe(403);
		});
	},
);
