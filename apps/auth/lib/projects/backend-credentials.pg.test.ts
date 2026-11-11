import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { backendCredentialRepository } from "./backend-credentials";
import { handleServiceDirectoryRequest } from "./service-directory-transport";
import { consumeProxySessionCheck } from "./session-introspection-admission";

const connection = process.env.ALLAUTH_BACKEND_TEST_DATABASE_URL;
/** A disposable local database only; never load production service credentials. */
describe.skipIf(!connection)("backend credential PostgreSQL lifecycle", () => {
	const schema = `backend_keys_${randomUUID().replaceAll("-", "")}`;
	let pool: Pool;
	let repository: ReturnType<typeof backendCredentialRepository>;
	beforeAll(async () => {
		const url = new URL(connection!);
		if (
			url.hostname !== "127.0.0.1" ||
			url.port !== "55583" ||
			url.pathname !== "/allauth_test"
		)
			throw new Error(
				"Only the explicit disposable backend-credential fixture is permitted.",
			);
		pool = new Pool({
			connectionString: connection,
			max: 1,
			options: `-c search_path=${schema}`,
		});
		await pool.query(`CREATE SCHEMA "${schema}"`);
		await pool.query(
			readFileSync(
				new URL("../../migrations/001-initial-auth.sql", import.meta.url),
				"utf8",
			),
		);
		await pool.query(
			`CREATE TABLE "${schema}"."allauthProject" (id TEXT PRIMARY KEY)`,
		);
		await pool.query(
			`INSERT INTO "${schema}"."allauthProject" VALUES ('project-a'),('project-b')`,
		);
		await pool.query(
			readFileSync(
				new URL(
					"../../migrations/015-project-backend-credentials.sql",
					import.meta.url,
				),
				"utf8",
			).replaceAll("public.", `"${schema}".`),
		);
		await pool.query(
			readFileSync(
				new URL(
					"../../migrations/016-invitation-import-provenance.sql",
					import.meta.url,
				),
				"utf8",
			),
		);
		const database = {
			query: (statement: string, values?: unknown[]) =>
				pool.query(
					statement.replaceAll(
						'public."allauthProjectBackendCredential"',
						`"${schema}"."allauthProjectBackendCredential"`,
					),
					values,
				),
		} as unknown as WorkspaceDatabase;
		repository = backendCredentialRepository(database);
	});
	afterAll(async () => {
		if (pool) {
			await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
			await pool.end();
		}
	});
	it("creates scoped hash-only credentials, rejects foreign projects, and revokes immediately", async () => {
		const result = await repository.create("project-a", "root-owner", {
			name: "Workers",
			expiresInDays: 1,
		});
		const credential = result.credential as { id: string };
		const headers = new Headers({ "allauth-backend-key": result.key });
		await expect(
			repository.authorize("project-a", headers),
		).resolves.toBeUndefined();
		await expect(
			repository.authorize("project-b", headers),
		).rejects.toMatchObject({ statusCode: 401 });
		const stored = (
			await pool.query(
				`SELECT * FROM "${schema}"."allauthProjectBackendCredential" WHERE id=$1`,
				[credential.id],
			)
		).rows[0];
		expect(stored.scope).toBe("directory:read");
		expect(stored.keyHash).toMatch(/^[a-f0-9]{64}$/);
		expect(stored.keyHash).not.toBe(result.key);
		expect(JSON.stringify(await repository.list("project-a"))).not.toMatch(
			/keyHash|aabk_/,
		);
		await expect(
			repository.revoke("project-b", credential.id),
		).rejects.toMatchObject({ statusCode: 404 });
		await repository.revoke("project-a", credential.id);
		await expect(
			repository.authorize("project-a", headers),
		).rejects.toMatchObject({ statusCode: 401 });
	});
	it("checks native database expiry on every request", async () => {
		const result = await repository.create("project-a", "root-owner", {
			name: "Expiry test",
		});
		const credential = result.credential as { id: string };
		await pool.query(
			`UPDATE "${schema}"."allauthProjectBackendCredential" SET "expiresAt"=NOW()-INTERVAL '1 second' WHERE id=$1`,
			[credential.id],
		);
		await expect(
			repository.authorize(
				"project-a",
				new Headers({ "allauth-backend-key": result.key }),
			),
		).rejects.toMatchObject({ statusCode: 401 });
	});
	it("shares bounded credential buckets across replicas, isolates keys/projects and recovers after refill", async () => {
		const first = await repository.create("project-a", "root-owner", {
			name: "Rate fixture",
		});
		const second = await repository.create("project-a", "root-owner", {
			name: "Independent key",
		});
		const foreign = await repository.create("project-b", "root-owner", {
			name: "Independent project",
		});
		const reads: { id: string }[] = [];
		const replica = (projectId: string, key: string) =>
			handleServiceDirectoryRequest(
				new Request(
					`https://allauth.example/api/projects/${projectId}/auth/service-directory/users`,
					{ headers: { "allauth-backend-key": key } },
				),
				{ id: projectId, slug: projectId },
				{
					authorize: (headers) => repository.authorize(projectId, headers),
					consume: (bucket) =>
						consumeProxySessionCheck(pool, bucket, {
							max: 1,
							window: 60,
							burst: 3,
						}),
					read: async () => {
						reads.push({ id: projectId });
						return Response.json({ users: [] });
					},
				},
			);
		const responses = await Promise.all(
			Array.from({ length: 6 }, () => replica("project-a", first.key)),
		);
		expect(
			responses.filter((response) => response?.status === 200),
		).toHaveLength(3);
		expect(
			responses.filter((response) => response?.status === 429),
		).toHaveLength(3);
		expect(reads).toHaveLength(3);
		expect((await replica("project-a", second.key))?.status).toBe(200);
		expect((await replica("project-b", foreign.key))?.status).toBe(200);
		expect(await replica("project-b", first.key)).toBeNull();
		await pool.query(
			`UPDATE "rateLimit" SET "lastRequest"=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-120000 WHERE "key" LIKE 'backend-directory:v1:%'`,
		);
		expect((await replica("project-a", first.key))?.status).toBe(200);
		await repository.revoke(
			"project-a",
			(first.credential as { id: string }).id,
		);
		expect(await replica("project-a", first.key)).toBeNull();
	});
});
