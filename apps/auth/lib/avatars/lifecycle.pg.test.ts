import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import {
	cleanupOwnedAvatars,
	eraseOwnedAvatarsBeforeDelete,
	ownedAvatarReady,
	storeOwnedAvatar,
} from "./lifecycle";
import type { AvatarScope } from "./lifecycle";
import worker from "../../workers/brand-assets";
import type { AuthEnvironment } from "../configuration";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const asset = {
	contentType: "image/png",
	extension: "png",
	bytes: new Uint8Array([
		137,
		80,
		78,
		71,
		13,
		10,
		26,
		10,
		...Array(25).fill(0),
	]),
} as const;
const secret = "synthetic-owned-avatar-test-secret-more-than-thirty-two";
describe.skipIf(!existsSync(fixturePath))(
	"owned-avatar isolated PostgreSQL lifecycle",
	() => {
		const databaseName = `allauth_avatar_${randomUUID().replaceAll("-", "")}`,
			schemaName = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const scope: AvatarScope = {
			schemaName,
			projectId: randomUUID(),
			workspaceId: randomUUID(),
			applicationId: randomUUID(),
		};
		let admin: Pool,
			pool: Pool,
			env: AuthEnvironment,
			failDelete = false;
		const records = new Map<
			string,
			{ bytes: Uint8Array; metadata: Record<string, string> }
		>();
		let beforePut: (() => Promise<void>) | undefined;
		const object = (key: string) => {
			const row = records.get(key);
			return row
				? {
						body: new Blob([new Uint8Array(row.bytes)]).stream(),
						size: row.bytes.length,
						customMetadata: row.metadata,
						httpEtag: '"fixture"',
						writeHttpMetadata: (headers: Headers) =>
							headers.set("content-type", "image/png"),
					}
				: null;
		};
		const bucket = {
			put: async (
				key: string,
				body: Uint8Array,
				options: { onlyIf?: Headers; customMetadata?: Record<string, string> },
			) => {
				if (options.onlyIf) await beforePut?.();
				else if (failDelete && !key.startsWith("avatar-lifecycle-probes/"))
					throw new Error("private-storage-error-sentinel");
				if (options.onlyIf && records.has(key)) return null;
				records.set(key, {
					bytes: new Uint8Array(body),
					metadata: options.customMetadata || {},
				});
				return object(key);
			},
			get: async (key: string) => object(key),
			head: async (key: string) => object(key),
			delete: async (key: string) => {
				records.delete(key);
			},
		} as unknown as R2Bucket;
		async function user(id = "owner") {
			await pool.query('INSERT INTO "user" (id) VALUES ($1)', [id]);
			return id;
		}
		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
					readFileSync(fixturePath, "utf8"),
				),
				url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error("Only the isolated local fixture is permitted.");
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			pool = new Pool({
				connectionString: url.toString(),
				max: 5,
				options: `-c search_path=${schemaName}`,
			});
			await pool.query(`CREATE SCHEMA "${schemaName}"`);
			await pool.query('CREATE TABLE "user" (id TEXT PRIMARY KEY,image TEXT)');
			await pool.query(
				readFileSync(
					new URL(
						"../../migrations/013-owned-user-avatars.sql",
						import.meta.url,
					),
					"utf8",
				),
			);
			env = {
				DATABASE_URL: url.toString(),
				ALLAUTH_ASSET_ORIGIN: "https://assets.allauth.co",
				ALLAUTH_AVATAR_SECRET: secret,
				ALLAUTH_OWNED_AVATAR_PROJECT_IDS: scope.projectId,
				ALLAUTH_AVATAR_CLEANUP_ENABLED: "true",
			};
			vi.stubGlobal(
				"fetch",
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const request = new Request(input, init);
					expect(new URL(request.url).origin).toBe("https://assets.allauth.co");
					expect(init?.redirect).toBe("error");
					return worker.fetch(request, {
						BRAND_ASSETS: {} as R2Bucket,
						ALLAUTH_ASSET_SECRET: "legacy-secret-not-used",
						OWNED_AVATARS: bucket,
						ALLAUTH_AVATAR_SECRET: secret,
						OWNED_AVATAR_PRIVATE_STORAGE: "true",
					});
				},
			);
		}, 30000);
		beforeEach(async () => {
			records.clear();
			failDelete = false;
			beforePut = undefined;
			await pool.query(
				'TRUNCATE "allauthAvatarAsset","allauthAvatarUserState","user" CASCADE',
			);
			await pool.query('UPDATE "allauthAvatarLifecycle" SET "healthyAt"=NULL');
		});
		afterAll(async () => {
			vi.unstubAllGlobals();
			if (pool) await pool.end();
			if (admin) {
				try {
					await dropClosedFixtureDatabase(admin, databaseName);
				} finally {
					await admin.end();
				}
			}
		});

		it("a selected realm refuses account deletion if its ownership registry is missing", async () => {
			await user();
			await pool.query(
				'ALTER TABLE "allauthAvatarAsset" RENAME TO "fixtureAvatarAssetHidden"',
			);
			try {
				await expect(
					eraseOwnedAvatarsBeforeDelete("owner", scope, pool, env),
				).rejects.toMatchObject({ statusCode: 503 });
				expect(
					(await pool.query('SELECT id FROM "user" WHERE id=$1', ["owner"]))
						.rowCount,
				).toBe(1);
			} finally {
				await pool.query(
					'ALTER TABLE "fixtureAvatarAssetHidden" RENAME TO "allauthAvatarAsset"',
				);
			}
		});
		it("keeps missing-user deletion an idempotent no-op without touching storage", async () => {
			await expect(
				eraseOwnedAvatarsBeforeDelete("absent-owner", scope, pool, env),
			).resolves.toBeUndefined();
			expect(records.size).toBe(0);
			expect(
				(await pool.query('SELECT * FROM "allauthAvatarUserState"')).rowCount,
			).toBe(0);
		});
		it("fails closed before heartbeat/config/hooks and stores exact owner intent before sending any bytes", async () => {
			const owner = await user();
			expect(await ownedAvatarReady(pool, scope, env)).toBe(false);
			await expect(
				storeOwnedAvatar(asset, owner, scope, pool, env),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(records.size).toBe(0);
			await cleanupOwnedAvatars(scope, pool, env);
			expect(await ownedAvatarReady(pool, scope, env)).toBe(true);
			expect(
				await ownedAvatarReady(pool, scope, {
					...env,
					ALLAUTH_OWNED_AVATAR_PROJECT_IDS: "",
				}),
			).toBe(false);
			beforePut = async () => {
				const row = (await pool.query('SELECT * FROM "allauthAvatarAsset"'))
					.rows[0];
				expect(row).toMatchObject({
					userId: owner,
					projectId: scope.projectId,
					workspaceId: scope.workspaceId,
					applicationId: scope.applicationId,
					state: "prepared",
				});
			};
			const url = await storeOwnedAvatar(asset, owner, scope, pool, env);
			expect(url).toContain(
				`/avatars/${scope.workspaceId}/${scope.applicationId}/${scope.projectId}/`,
			);
			expect(
				(await pool.query('SELECT image FROM "user" WHERE id=$1', [owner]))
					.rows[0].image,
			).toBeNull();
			await pool.query(
				'ALTER TABLE "user" DISABLE TRIGGER allauth_avatar_delete_guard',
			);
			expect(await ownedAvatarReady(pool, scope, env)).toBe(false);
			await pool.query(
				'ALTER TABLE "user" ENABLE TRIGGER allauth_avatar_delete_guard',
			);
		});

		it("rejects signup INSERT and unconfigured-realm UPDATE borrowing an owned namespace, while preserving ordinary external/branding images", async () => {
			const foreign = `https://assets.allauth.co/avatars/${scope.workspaceId}/${scope.applicationId}/${scope.projectId}/${randomUUID()}.png`;
			const owner = await user();
			for (const alias of [
				foreign,
				foreign + "#avatar",
				foreign + "?alias=1",
				foreign.replace("https:", "HTTPS:"),
				foreign.replace("https:", ""),
				" " + foreign + " ",
			]) {
				await expect(
					pool.query('INSERT INTO "user" (id,image) VALUES ($1,$2)', [
						"foreign-insert",
						alias,
					]),
				).rejects.toThrow("after creating this account");
				await expect(
					pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [alias, owner]),
				).rejects.toThrow("uploaded for this account");
			}
			for (const [id, image] of [
				["legacy-image", "https://assets.allauth.co/branding/unowned.png"],
				["external-image", "https://cdn.fixture.example/profile.jpg"],
			])
				await pool.query('INSERT INTO "user" (id,image) VALUES ($1,$2)', [
					id,
					image,
				]);
			expect(
				Number(
					(await pool.query('SELECT COUNT(*)::text AS count FROM "user"'))
						.rows[0].count,
				),
			).toBe(3);
		});
		it("enforces current realm/owner on saved URLs and queues replaced/abandoned drafts without deleting legacy URLs", async () => {
			const owner = await user(),
				other = await user("other");
			await cleanupOwnedAvatars(scope, pool, env);
			const first = await storeOwnedAvatar(asset, owner, scope, pool, env);
			await expect(
				pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [first, other]),
			).rejects.toThrow("uploaded for this account");
			await pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [
				first,
				owner,
			]);
			const second = await storeOwnedAvatar(asset, owner, scope, pool, env);
			await pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [
				second,
				owner,
			]);
			const abandoned = await storeOwnedAvatar(asset, owner, scope, pool, env);
			await pool.query(
				'UPDATE "allauthAvatarAsset" SET "expiresAt"=NOW()-INTERVAL \'1 second\' WHERE url=$1',
				[abandoned],
			);
			const result = await cleanupOwnedAvatars(scope, pool, env);
			expect(result).toEqual({ erased: 2, failed: 0 });
			expect(
				records.get(new URL(second).pathname.slice(1))?.bytes.length,
			).toBeGreaterThan(0);
			const legacy = "https://assets.allauth.co/branding/unowned-legacy.png";
			await pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [
				legacy,
				owner,
			]);
			await cleanupOwnedAvatars(scope, pool, env);
			expect(
				[...records.keys()].every((key) => key.startsWith("avatars/")),
			).toBe(true);
			expect(
				(await pool.query('SELECT image FROM "user" WHERE id=$1', [owner]))
					.rows[0].image,
			).toBe(legacy);
		});
		it("refuses account completion until all owned drafts acknowledge cleanup and retries without losing ownership intent", async () => {
			const owner = await user();
			await cleanupOwnedAvatars(scope, pool, env);
			await storeOwnedAvatar(asset, owner, scope, pool, env);
			failDelete = true;
			await expect(
				eraseOwnedAvatarsBeforeDelete(owner, scope, pool, env),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(
				(await pool.query('SELECT id FROM "user" WHERE id=$1', [owner]))
					.rowCount,
			).toBe(1);
			expect(
				(await pool.query('SELECT state,attempts FROM "allauthAvatarAsset"'))
					.rows[0],
			).toMatchObject({ state: "delete_pending", attempts: 1 });
			expect(await ownedAvatarReady(pool, scope, env)).toBe(false);
			await expect(
				storeOwnedAvatar(asset, owner, scope, pool, env),
			).rejects.toMatchObject({ statusCode: 503 });
			failDelete = false;
			await eraseOwnedAvatarsBeforeDelete(owner, scope, pool, env);
			await pool.query('DELETE FROM "user" WHERE id=$1', [owner]);
			expect(
				(await pool.query('SELECT state,"userId" FROM "allauthAvatarAsset"'))
					.rows[0],
			).toMatchObject({ state: "deleted", userId: null });
			expect([...records.values()].every((row) => row.bytes.length === 0)).toBe(
				true,
			);
		});
		it("serializes in-flight upload with pre-delete and retains raw-delete fallback jobs after owner removal", async () => {
			const owner = await user();
			await cleanupOwnedAvatars(scope, pool, env);
			let release: () => void = () => {},
				entered: () => void = () => {};
			const gate = new Promise<void>((yes) => {
					release = yes;
				}),
				started = new Promise<void>((yes) => {
					entered = yes;
				});
			beforePut = async () => {
				entered();
				await gate;
			};
			const uploading = storeOwnedAvatar(asset, owner, scope, pool, env);
			await started;
			let completed = false;
			const deleting = eraseOwnedAvatarsBeforeDelete(
				owner,
				scope,
				pool,
				env,
			).then(() => {
				completed = true;
			});
			await new Promise((yes) => setTimeout(yes, 15));
			expect(completed).toBe(false);
			release();
			await uploading;
			await deleting;
			expect([...records.values()].every((row) => row.bytes.length === 0)).toBe(
				true,
			);
			beforePut = undefined;
			const other = await user("raw-owner");
			await storeOwnedAvatar(asset, other, scope, pool, env);
			await pool.query('DELETE FROM "user" WHERE id=$1', [other]);
			expect(
				(
					await pool.query(
						'SELECT state,"userId" FROM "allauthAvatarAsset" WHERE state<>\'deleted\'',
					)
				).rows[0],
			).toMatchObject({ state: "delete_pending", userId: null });
			await cleanupOwnedAvatars(scope, pool, env);
			expect([...records.values()].every((row) => row.bytes.length === 0)).toBe(
				true,
			);
		});
		it("rolls back queued erasure with failed user update/delete and never cleans a forged cross-application path", async () => {
			const owner = await user();
			await cleanupOwnedAvatars(scope, pool, env);
			const url = await storeOwnedAvatar(asset, owner, scope, pool, env);
			await pool.query('UPDATE "user" SET image=$1 WHERE id=$2', [url, owner]);
			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				await client.query('DELETE FROM "user" WHERE id=$1', [owner]);
				await client.query("ROLLBACK");
			} finally {
				client.release();
			}
			expect(
				(await pool.query('SELECT state FROM "allauthAvatarAsset"')).rows[0]
					.state,
			).toBe("active");
			await pool.query(
				'UPDATE "allauthAvatarAsset" SET state=\'delete_pending\',"objectPath"=$1',
				[new URL(url).pathname.replace(scope.applicationId, randomUUID())],
			);
			const result = await cleanupOwnedAvatars(scope, pool, env);
			expect(result).toEqual({ erased: 0, failed: 1 });
			expect(
				records.get(new URL(url).pathname.slice(1))?.bytes.length,
			).toBeGreaterThan(0);
		});
	},
);
