import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { promisify } from "node:util";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { platformWorkspaceId } from "../workspaces/types";
import type { ProjectEngineWriterState } from "./project-engine-writer-lease";
import {
	createProjectEngineWriterLease,
	projectEngineWriterConnectionOptions,
} from "./project-engine-writer-lease";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const execute = promisify(execFile);
const modeFile = "019-project-engine-writer.sql";
const legacy: ProjectEngineWriterState = { writer: "legacy", revision: 0 };
const scopeError = { code: "ALLAUTH_PROJECT_WRITER_SCOPE_FORBIDDEN" };
const mismatch = { code: "ALLAUTH_PROJECT_WRITER_MISMATCH" };
const staleWrite = { code: "55000" };
type Binding = Parameters<typeof createProjectEngineWriterLease>[0]["project"];

function realm(
	environment: Binding["environment"] = "development",
	workspaceId = platformWorkspaceId,
): Binding {
	const id = randomUUID();
	return {
		id,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		workspaceId,
		environment,
	};
}

function gate() {
	let open = () => {};
	const waiting = new Promise<void>((resolve) => {
		open = resolve;
	});
	return { waiting, open };
}

describe.skipIf(!existsSync(fixturePath))(
	"protected project PostgreSQL writer fence",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const alpha = realm();
		const beta = realm();
		const gamma = realm();
		const production = realm("production");
		const externalWorkspace = randomUUID();
		const external = realm("development", externalWorkspace);
		const pools: Pool[] = [];
		let admin: Pool | undefined;
		let database: Pool;
		let leases: Pool;
		let operator: Pool;
		let url: string;
		let created = false;

		function pool(applicationName: string, options?: string) {
			const createdPool = new Pool({
				connectionString: url,
				application_name: applicationName,
				options,
				max: 8,
				connectionTimeoutMillis: 2000,
			});
			pools.push(createdPool);
			return createdPool;
		}

		async function migrate() {
			await execute(process.execPath, ["scripts/database.mjs", "migrate"], {
				cwd: new URL("../../", import.meta.url),
				env: {
					...process.env,
					DATABASE_URL: url,
					ALLAUTH_DEPLOYMENT_MODE: "self-hosted",
				},
			});
		}

		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const target = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				target.hostname !== "127.0.0.1" ||
				target.port !== "55445"
			)
				throw new Error(
					"Writer tests require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			target.pathname = `/${databaseName}`;
			url = target.href;
			database = pool("allauth-writer-fixture-observer");
			leases = pool("allauth-writer-fixture-leases");
			operator = pool("allauth-writer-fixture-operator");
			await migrate();
			await database.query(
				`INSERT INTO public."allauthWorkspace"(id,name,slug,protected) VALUES ($1,'External','writer-external',false)`,
				[externalWorkspace],
			);
			for (const [index, project] of [
				alpha,
				beta,
				gamma,
				production,
				external,
			].entries()) {
				await database.query(`CREATE SCHEMA "${project.schemaName}"`);
				await database.query(
					`INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId") VALUES ($1,'Writer fixture',$2,$3,'https://writer.fixture.example','fixture','fixture',$4,'fixture',$1,$5,$6)`,
					[
						project.id,
						`writer-fixture-${index}`,
						project.schemaName,
						randomUUID(),
						project.environment,
						project.workspaceId,
					],
				);
			}
			await migrate();
		}, 20_000);

		afterAll(async () => {
			await Promise.all(pools.map((connection) => connection.end()));
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		function fence(
			project: Binding,
			selectedProjectId = project.id,
			connection = leases,
		) {
			return createProjectEngineWriterLease({
				database: connection,
				project,
				selectedProjectId,
			});
		}

		function writerPool(
			project: Binding,
			admitted?: ProjectEngineWriterState,
			taggedProject = project.id,
		) {
			const tag = admitted
				? ` ${projectEngineWriterConnectionOptions(taggedProject, admitted)}`
				: "";
			return pool(
				"allauth-writer-fixture-auth",
				`-c search_path=${project.schemaName}${tag}`,
			);
		}

		async function waitingOperator() {
			await vi.waitFor(
				async () => {
					const { rows } = await database.query<{ waiting: boolean }>(
						"SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name='allauth-writer-fixture-operator' AND wait_event_type='Lock') AS waiting",
					);
					expect(rows[0]?.waiting).toBe(true);
				},
				{ timeout: 4000, interval: 15 },
			);
		}

		const updateUser = `UPDATE "user" SET "emailVerified"=true WHERE id='fixture-user'`;
		const updateAccount = `UPDATE "account" SET password='synthetic-new-password-record' WHERE id='fixture-credential'`;
		const grantWrite = `UPDATE "oauthRefreshToken" SET revoked=now() WHERE id='fixture-grant'`;
		const sessionWrite = `INSERT INTO "session"(id,token,"userId","expiresAt","updatedAt") VALUES($1,$1,'fixture-user',now()+interval '1 hour',now())`;

		async function seed(connection: Pool) {
			await connection.query(
				`INSERT INTO "user"(id,name,email,"emailVerified") VALUES('fixture-user','Writer fixture','writer@fixture.example',false)`,
			);
			await connection.query(
				`INSERT INTO "account"(id,"accountId","providerId","userId",password,"updatedAt") VALUES('fixture-credential','fixture-user','credential','fixture-user','synthetic-original-password-record',now())`,
			);
			await connection.query(
				`INSERT INTO "oauthClient"(id,"clientId","redirectUris") VALUES('fixture-client','fixture-client','[]')`,
			);
			await connection.query(
				`INSERT INTO "oauthRefreshToken"(id,token,"clientId","userId","expiresAt","createdAt",scopes) VALUES('fixture-grant','fixture-grant','fixture-client','fixture-user',now()+interval '1 hour',now(),'[]')`,
			);
		}

		it("applies a checksum-tracked public migration and keeps untouched realms on legacy", async () => {
			const checksum = createHash("sha256")
				.update(
					readFileSync(
						new URL(`../../migrations/${modeFile}`, import.meta.url),
					),
				)
				.digest("hex");
			for (const namespace of ["public", alpha.schemaName]) {
				const applied = await database.query<{ checksum: string }>(
					`SELECT checksum FROM "${namespace}"."allauthMigrations" WHERE name=$1`,
					[modeFile],
				);
				expect(applied.rows).toEqual([{ checksum }]);
			}
			const localTable = await database.query<{ exists: boolean }>(
				"SELECT to_regclass($1) IS NOT NULL AS exists",
				[`${alpha.schemaName}.\"allauthProjectEngineWriter\"`],
			);
			expect(localTable.rows).toEqual([{ exists: false }]);
			await expect(fence(alpha).read()).resolves.toEqual(legacy);
			await expect(fence(alpha).switch(legacy, "legacy")).resolves.toEqual(
				legacy,
			);
			await expect(
				fence(alpha).run("allauth", async () => {}),
			).rejects.toMatchObject(mismatch);
		});

		it("rejects wrong-realm, production, unprotected and missing registry bindings", async () => {
			for (const callback of [
				() => fence(alpha, beta.id),
				() => fence(production),
				() => fence(external),
				() => fence({ ...alpha, schemaName: beta.schemaName }),
			])
				expect(callback).toThrow(expect.objectContaining(scopeError));
			for (const stale of [
				{ ...production, environment: "development" as const },
				{ ...external, workspaceId: platformWorkspaceId },
				realm(),
			]) {
				await expect(fence(stale).read()).rejects.toMatchObject(scopeError);
				await expect(
					fence(stale).switch(legacy, "allauth"),
				).rejects.toMatchObject(scopeError);
			}
			await database.query(
				`UPDATE public."allauthWorkspace" SET protected=false WHERE id=$1`,
				[platformWorkspaceId],
			);
			try {
				await expect(fence(alpha).read()).rejects.toMatchObject(scopeError);
				await expect(
					fence(alpha).switch(legacy, "allauth"),
				).rejects.toMatchObject(scopeError);
			} finally {
				await database.query(
					`UPDATE public."allauthWorkspace" SET protected=true WHERE id=$1`,
					[platformWorkspaceId],
				);
			}
		});

		it("waits for a pre-fence legacy mutation, then rejects an untagged writer and its old snapshot", async () => {
			const old = writerPool(alpha);
			await seed(old);
			const pending = await old.connect();
			const staleSnapshot = await old.connect();
			let switchMode: Promise<ProjectEngineWriterState> | undefined;
			try {
				await staleSnapshot.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
				await staleSnapshot.query(`SELECT count(*) FROM "session"`);
				await pending.query("BEGIN");
				await pending.query(updateUser);
				switchMode = fence(alpha, alpha.id, operator).switch(legacy, "allauth");
				void switchMode.catch(() => {});
				await waitingOperator();
				await expect(
					fence(beta).run("legacy", async () => "independent"),
				).resolves.toBe("independent");
				await pending.query("COMMIT");
				const owned = await switchMode;
				expect(owned).toEqual({ writer: "allauth", revision: 1 });
				await expect(
					staleSnapshot.query(sessionWrite, ["stale-snapshot-session"]),
				).rejects.toMatchObject(staleWrite);
				for (const query of [
					updateUser,
					updateAccount,
					grantWrite,
					`TRUNCATE "verification"`,
					`DELETE FROM "member" WHERE id='fixture-member'`,
					`DELETE FROM "scimManagedCredential" WHERE id='fixture-credential'`,
					`DELETE FROM "allauthSecurityCounter" WHERE key='fixture-counter'`,
				])
					await expect(old.query(query)).rejects.toMatchObject(staleWrite);
				await expect(
					old.query(sessionWrite, ["old-session"]),
				).rejects.toMatchObject(staleWrite);
				const wrongRealm = writerPool(alpha, owned, beta.id);
				await expect(wrongRealm.query(updateAccount)).rejects.toMatchObject(
					staleWrite,
				);
				const current = writerPool(alpha, owned);
				await expect(current.query(updateAccount)).resolves.toMatchObject({
					rowCount: 1,
				});
				await expect(current.query(grantWrite)).resolves.toMatchObject({
					rowCount: 1,
				});
				await expect(
					current.query(sessionWrite, ["owned-session"]),
				).resolves.toMatchObject({ rowCount: 1 });
			} finally {
				await Promise.allSettled([
					pending.query("ROLLBACK"),
					staleSnapshot.query("ROLLBACK"),
				]);
				pending.release();
				staleSnapshot.release();
				await Promise.allSettled([switchMode]);
			}
		});

		it("drains an owned lease and nested guarded work before rollback and blocks stale writers", async () => {
			const native = writerPool(beta);
			await seed(native);
			const selection = fence(beta);
			const owned = await fence(beta, beta.id, operator).switch(
				legacy,
				"allauth",
			);
			const current = writerPool(beta, owned);
			const entered = gate();
			const finish = gate();
			const callback = vi.fn(async () => "old writer called");
			const inFlight = selection.run("allauth", async (lease) => {
				entered.open();
				await finish.waiting;
				await expect(fence(beta).run("legacy", callback)).rejects.toMatchObject(
					mismatch,
				);
				await expect(selection.switch(owned, "legacy")).rejects.toMatchObject({
					code: "ALLAUTH_PROJECT_WRITER_SWITCH_IN_LEASE",
				});
				await expect(fence(alpha).read()).rejects.toMatchObject({
					code: "ALLAUTH_PROJECT_WRITER_NESTING_FORBIDDEN",
				});
				await fence(beta).withCurrent(async (nested) => {
					expect(nested).toBe(lease);
					await current.query(sessionWrite, ["nested-owned-session"]);
				});
			});
			let rollback: Promise<ProjectEngineWriterState> | undefined;
			let late: Promise<unknown> | undefined;
			try {
				await entered.waiting;
				rollback = fence(beta, beta.id, operator).switch(owned, "legacy");
				void rollback.catch(() => {});
				await waitingOperator();
				late = selection.run("allauth", callback);
				void late.catch(() => {});
				finish.open();
				await inFlight;
				const resumed = await rollback;
				expect(resumed).toEqual({ writer: "legacy", revision: 2 });
				await expect(late).rejects.toMatchObject(mismatch);
				expect(callback).not.toHaveBeenCalled();
				await expect(
					current.query(sessionWrite, ["late-owned-session"]),
				).rejects.toMatchObject(staleWrite);
				await expect(
					writerPool(beta, legacy).query(updateAccount),
				).rejects.toMatchObject(staleWrite);
				await expect(
					native.query(sessionWrite, ["new-native-session"]),
				).resolves.toMatchObject({ rowCount: 1 });
				await expect(
					writerPool(beta, resumed).query(updateAccount),
				).resolves.toMatchObject({ rowCount: 1 });
				await expect(
					fence(beta, beta.id, operator).switch(legacy, "allauth"),
				).rejects.toMatchObject({
					code: "ALLAUTH_PROJECT_WRITER_REVISION_CONFLICT",
				});
				expect(
					(await native.query(`SELECT id FROM "session" ORDER BY id`)).rows,
				).toEqual([
					{ id: "nested-owned-session" },
					{ id: "new-native-session" },
				]);
			} finally {
				finish.open();
				await Promise.allSettled([inFlight, rollback, late]);
			}
		});

		it("drains an open mutation and fences stale writes after the request lease disconnects", async () => {
			const native = writerPool(gamma);
			await seed(native);
			const owned = await fence(gamma, gamma.id, operator).switch(
				legacy,
				"allauth",
			);
			const active = writerPool(gamma, owned);
			const isolatedLease = pool("allauth-writer-fixture-disconnect");
			const guarded = await active.connect();
			let rollback: Promise<ProjectEngineWriterState> | undefined;
			let late: Promise<unknown> | undefined;
			const entered = gate();
			const resume = gate();
			const disconnected = gate();
			const operation = fence(gamma, gamma.id, isolatedLease).withCurrent(
				async ({ signal }) => {
					signal.addEventListener("abort", disconnected.open, { once: true });
					entered.open();
					await resume.waiting;
					// Independent SQL must fail even when the old work ignored cancellation.
					for (const query of [updateAccount, grantWrite])
						await expect(active.query(query)).rejects.toMatchObject(staleWrite);
					await expect(
						active.query(sessionWrite, ["disconnected-session"]),
					).rejects.toMatchObject(staleWrite);
				},
			);
			void operation.catch(() => {});
			try {
				await entered.waiting;
				await guarded.query("BEGIN");
				await guarded.query(sessionWrite, ["committed-before-switch"]);
				const { rows } = await database.query<{ killed: boolean }>(
					"SELECT pg_terminate_backend(pid) AS killed FROM pg_stat_activity WHERE application_name='allauth-writer-fixture-disconnect' AND state='idle in transaction'",
				);
				expect(rows).toEqual([{ killed: true }]);
				await disconnected.waiting;
				rollback = fence(gamma, gamma.id, operator).switch(owned, "legacy");
				void rollback.catch(() => {});
				await waitingOperator();
				const lateWriter = pool(
					"allauth-writer-fixture-stale-statement",
					`-c search_path=${gamma.schemaName} ${projectEngineWriterConnectionOptions(gamma.id, owned)}`,
				);
				late = lateWriter.query(updateAccount);
				void late.catch(() => {});
				await vi.waitFor(
					async () => {
						const { rows } = await database.query<{ waiting: boolean }>(
							"SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name='allauth-writer-fixture-stale-statement' AND wait_event_type='Lock') AS waiting",
						);
						expect(rows[0]?.waiting).toBe(true);
					},
					{ timeout: 4000, interval: 15 },
				);
				await guarded.query("COMMIT");
				await expect(rollback).resolves.toEqual({
					writer: "legacy",
					revision: 2,
				});
				await expect(late).rejects.toMatchObject(staleWrite);
				resume.open();
				await expect(operation).rejects.toMatchObject({
					code: "ALLAUTH_PROJECT_WRITER_LEASE_LOST",
				});
				expect(
					(await native.query(`SELECT password FROM "account"`)).rows,
				).toEqual([{ password: "synthetic-original-password-record" }]);
				expect(
					(await native.query(`SELECT revoked FROM "oauthRefreshToken"`)).rows,
				).toEqual([{ revoked: null }]);
				expect((await native.query(`SELECT id FROM "session"`)).rows).toEqual([
					{ id: "committed-before-switch" },
				]);
			} finally {
				await guarded.query("ROLLBACK");
				guarded.release();
				resume.open();
				await Promise.allSettled([operation, rollback, late]);
			}
		});
	},
);
