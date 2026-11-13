import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { platformWorkspaceId } from "../workspaces/types";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const authRoot = new URL("../../", import.meta.url);
const migrations = new URL("migrations/", authRoot);
const migrationScript = fileURLToPath(
	new URL("scripts/database.mjs", authRoot),
);
const execute = promisify(execFile);
const invalidBinding = { code: "AU001" };
const staleWriter = { code: "55000" };

function realm(workspaceId: string, environment: "development" | "production") {
	const id = randomUUID();
	return {
		id,
		workspaceId,
		environment,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
	};
}

describe.skipIf(!existsSync(fixturePath))(
	"production project PostgreSQL writer fence",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const workspace = randomUUID();
		const otherWorkspace = randomUUID();
		const production = realm(workspace, "production");
		const sibling = realm(workspace, "production");
		const development = realm(platformWorkspaceId, "development");
		const customerDevelopment = realm(workspace, "development");
		const otherDevelopment = realm(otherWorkspace, "development");
		const pairedProduction = realm(workspace, "production");
		const pairedApplication = randomUUID();
		const pools: Pool[] = [];
		let administrator: Pool | undefined;
		let database: Pool;
		let url: string;
		let created = false;

		function connect(options?: string) {
			const pool = new Pool({ connectionString: url, max: 2, options });
			pools.push(pool);
			return pool;
		}
		const tag = (writer: string, id: string, revision: number) =>
			connect(
				`-c allauth.project_engine_writer=${writer} -c allauth.project_engine_project_id=${id} -c allauth.project_engine_writer_revision=${revision}`,
			);

		async function migrate(cwd: string | URL) {
			await execute(process.execPath, [migrationScript, "migrate"], {
				cwd,
				env: {
					...process.env,
					DATABASE_URL: url,
					ALLAUTH_DEPLOYMENT_MODE: "self-hosted",
				},
			});
		}

		async function transition(
			projectId: string,
			previous: string,
			revision: number,
			next: string,
		) {
			const result = await database.query(
				"SELECT writer,revision FROM public.allauth_switch_project_engine_writer($1,$2,$3,$4)",
				[projectId, previous, revision, next],
			);
			return result.rows[0];
		}

		function register(projectId: string, workspaceId: string) {
			return database.query(
				"SELECT public.allauth_register_project_engine_production($1,$2)",
				[projectId, workspaceId],
			);
		}

		async function binding(project: ReturnType<typeof realm>) {
			const {
				rows: [row],
			} = await database.query(
				`SELECT p."projectEngineFenced", e."workspaceId", e."schemaName", e."registeredAt",
			        f.writer, f.revision, public.allauth_project_engine_production_allowed(p.id,p."workspaceId",p."schemaName") AS allowed
			   FROM public."allauthProject" p
			   LEFT JOIN public."allauthProjectEngineProduction" e ON e."projectId"=p.id
			   LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id WHERE p.id=$1`,
				[project.id],
			);
			return row;
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
				throw new Error("Production writer tests require isolated PostgreSQL.");
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			target.pathname = `/${databaseName}`;
			url = target.href;
			database = connect();
			const prior = mkdtempSync(join(tmpdir(), "allauth-production-fence-"));
			try {
				const priorMigrations = join(prior, "migrations");
				mkdirSync(priorMigrations);
				for (const name of readdirSync(migrations)) {
					if (name.endsWith(".sql") && name <= "020-project-webhook-writer.sql")
						copyFileSync(
							new URL(name, migrations),
							join(priorMigrations, name),
						);
				}
				await migrate(prior);
				await database.query(
					`INSERT INTO public."allauthWorkspace"(id,name,slug) VALUES ($1,'Fixture customer','fixture-customer'),($2,'Other customer','other-customer')`,
					[workspace, otherWorkspace],
				);
				for (const [index, project] of [
					production,
					sibling,
					development,
					customerDevelopment,
					otherDevelopment,
					pairedProduction,
				].entries()) {
					await database.query(`CREATE SCHEMA "${project.schemaName}"`);
					await database.query(
						`INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId")
					 VALUES ($1,'Writer fence fixture',$2,$3,$4,'fixture','fixture','fixture','fixture',$5,$6,$7)`,
						[
							project.id,
							`production-fence-${index}`,
							project.schemaName,
							project === customerDevelopment
								? "http://localhost:3210"
								: "https://writer.fixture.example",
							project === customerDevelopment || project === pairedProduction
								? pairedApplication
								: project.id,
							project.environment,
							project.workspaceId,
						],
					);
				}
				await migrate(prior);
				await expect(
					transition(production.id, "legacy", 0, "allauth"),
				).rejects.toMatchObject(invalidBinding);
				await expect(
					transition(development.id, "legacy", 0, "allauth"),
				).resolves.toEqual({ writer: "allauth", revision: 1 });
				const productionMigration = "021-project-engine-production.sql";
				copyFileSync(
					new URL(productionMigration, migrations),
					join(priorMigrations, productionMigration),
				);
				await migrate(prior);
				await register(pairedProduction.id, pairedProduction.workspaceId);
				await expect(
					transition(pairedProduction.id, "legacy", 0, "allauth"),
				).resolves.toEqual({ writer: "allauth", revision: 1 });
				await migrate(authRoot);
			} finally {
				rmSync(prior, { recursive: true, force: true });
			}
		}, 30_000);

		afterAll(async () => {
			await Promise.all(pools.map((pool) => pool.end()));
			if (!administrator) return;
			try {
				if (created)
					await dropClosedFixtureDatabase(administrator, databaseName);
			} finally {
				await administrator.end();
			}
		});

		it("registers only the exact production binding and preserves the current writer", async () => {
			await expect(
				register(production.id, otherWorkspace),
			).rejects.toMatchObject(invalidBinding);
			await expect(
				register(development.id, platformWorkspaceId),
			).rejects.toMatchObject(invalidBinding);
			await expect(
				transition(production.id, "legacy", 0, "allauth"),
			).rejects.toMatchObject(invalidBinding);
			await register(production.id, workspace);
			const pinned = await binding(production);
			expect(pinned).toMatchObject({
				projectEngineFenced: true,
				workspaceId: workspace,
				schemaName: production.schemaName,
				registeredAt: expect.any(Date),
				writer: null,
				revision: null,
				allowed: true,
			});
			await register(production.id, workspace);
			await expect(binding(production)).resolves.toEqual(pinned);
			await expect(binding(sibling)).resolves.toMatchObject({
				projectEngineFenced: false,
				allowed: false,
			});
			const { rows } = await database.query(
				`SELECT public.allauth_project_engine_production_allowed($1,$2,$3) AS "wrongWorkspace",
			        public.allauth_project_engine_production_allowed($1,$4,$5) AS "wrongSchema",
			        EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
			           WHERE p.oid='public.allauth_register_project_engine_production(text,text)'::regprocedure
			           AND a.grantee=0 AND a.privilege_type='EXECUTE') AS "publicCanRegister"`,
				[
					production.id,
					otherWorkspace,
					production.schemaName,
					workspace,
					sibling.schemaName,
				],
			);
			expect(rows).toEqual([
				{ wrongWorkspace: false, wrongSchema: false, publicCanRegister: false },
			]);
		});

		it("serializes registration with an admitted legacy operation", async () => {
			const holder = await database.connect();
			const registrar = await database.connect();
			try {
				await holder.query("BEGIN");
				await holder.query(
					"SELECT pg_advisory_xact_lock_shared(public.allauth_project_engine_admission_key($1))",
					[sibling.id],
				);
				await registrar.query("BEGIN");
				await registrar.query("SET LOCAL lock_timeout='100ms'");
				await expect(
					registrar.query(
						"SELECT public.allauth_register_project_engine_production($1,$2)",
						[sibling.id, workspace],
					),
				).rejects.toMatchObject({ code: "55P03" });
			} finally {
				await Promise.all([
					holder.query("ROLLBACK"),
					registrar.query("ROLLBACK"),
				]);
				holder.release();
				registrar.release();
			}
			await expect(binding(sibling)).resolves.toMatchObject({
				projectEngineFenced: false,
				allowed: false,
				writer: null,
			});
		});

		it("prevents clearing or rebinding a registered realm through ordinary registry writes", async () => {
			await register(production.id, workspace);
			for (const [assignment, value] of [
				['"projectEngineFenced"=$1', false],
				['"workspaceId"=$1', otherWorkspace],
				['"schemaName"=$1', sibling.schemaName],
				["environment=$1", "development"],
			] as const) {
				await expect(
					database.query(
						`UPDATE public."allauthProject" SET ${assignment} WHERE id=$2`,
						[value, production.id],
					),
				).rejects.toMatchObject(invalidBinding);
			}
			await expect(
				database.query(
					'UPDATE public."allauthProject" SET "projectEngineFenced"=TRUE WHERE id=$1',
					[sibling.id],
				),
			).rejects.toMatchObject(invalidBinding);
			await expect(binding(production)).resolves.toMatchObject({
				projectEngineFenced: true,
				allowed: true,
			});
		});

		it("fences production mutations after cutover and retains the exact registration through rollback", async () => {
			await register(production.id, workspace);
			const endpointTable = `"${production.schemaName}"."allauthWebhookEndpoint"`;
			const siblingEndpoints = `"${sibling.schemaName}"."allauthWebhookEndpoint"`;
			const write = (pool: Pool, table: string, description: string) =>
				pool.query(
					`UPDATE ${table} SET description=$1 WHERE id='fixture-endpoint' RETURNING id,description`,
					[description],
				);
			for (const table of [endpointTable, siblingEndpoints]) {
				await database.query(
					`INSERT INTO ${table}(id,url,"eventTypes","encryptedSecret") VALUES ('fixture-endpoint','https://webhook.fixture.example/events','["mfa.*"]','fixture')`,
				);
			}
			await expect(
				transition(sibling.id, "legacy", 0, "allauth"),
			).rejects.toMatchObject(invalidBinding);
			await expect(
				transition(production.id, "legacy", 0, "allauth"),
			).resolves.toEqual({ writer: "allauth", revision: 1 });
			await expect(
				transition(production.id, "legacy", 0, "allauth"),
			).rejects.toMatchObject({ code: "AU002" });
			const { rows: guards } = await database.query(
				`SELECT c.relname AS table FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
			   JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND t.tgname='allauth_project_engine_writer'
			   AND c.relname IN ('allauthWebhookEndpoint','session') AND t.tgenabled='O' ORDER BY c.relname`,
				[production.schemaName],
			);
			expect(guards).toEqual([
				{ table: "allauthWebhookEndpoint" },
				{ table: "session" },
			]);
			const old = tag("legacy", production.id, 0);
			const active = tag("allauth", production.id, 1);
			const foreign = tag("allauth", sibling.id, 1);
			for (const stale of [database, old, foreign])
				await expect(
					write(stale, endpointTable, "refused"),
				).rejects.toMatchObject(staleWriter);
			await expect(
				write(active, endpointTable, "owned writer"),
			).resolves.toMatchObject({ rowCount: 1 });
			await expect(
				write(database, siblingEndpoints, "untouched sibling"),
			).resolves.toMatchObject({ rowCount: 1 });
			await expect(
				transition(production.id, "allauth", 1, "legacy"),
			).resolves.toEqual({ writer: "legacy", revision: 2 });
			await expect(
				write(active, endpointTable, "refused"),
			).rejects.toMatchObject(staleWriter);
			await expect(
				write(
					tag("legacy", production.id, 2),
					endpointTable,
					"restored writer",
				),
			).resolves.toMatchObject({
				rows: [{ id: "fixture-endpoint", description: "restored writer" }],
			});
			await expect(binding(production)).resolves.toMatchObject({
				projectEngineFenced: true,
				allowed: true,
				writer: "legacy",
				revision: 2,
			});
			await expect(binding(sibling)).resolves.toMatchObject({
				projectEngineFenced: false,
				allowed: false,
				writer: null,
			});
		});

		it("preserves the already-active protected development writer through the additive upgrade", async () => {
			await expect(binding(development)).resolves.toMatchObject({
				projectEngineFenced: false,
				allowed: false,
				writer: "allauth",
				revision: 1,
			});
			await expect(
				transition(development.id, "allauth", 1, "legacy"),
			).resolves.toEqual({ writer: "legacy", revision: 2 });
		});

		describe("ordinary development project enrollment", () => {
			const registerDevelopment = (id: string, workspaceId: string) =>
				database.query(
					"SELECT public.allauth_register_project_engine_development($1,$2)",
					[id, workspaceId],
				);

			async function developmentBinding(project: ReturnType<typeof realm>) {
				const {
					rows: [row],
				} = await database.query(
					`SELECT p."projectEngineFenced", e."workspaceId", e."schemaName", e."registeredAt",
					 COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision,
					 public.allauth_project_engine_development_allowed(p.id,p."workspaceId",p."schemaName") AS allowed
					 FROM public."allauthProject" p
					 LEFT JOIN public."allauthProjectEngineDevelopment" e ON e."projectId"=p.id
					 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id WHERE p.id=$1`,
					[project.id],
				);
				return row;
			}

			it("registers one immutable development project at legacy revision zero", async () => {
				const target = customerDevelopment;
				for (const [id, workspaceId] of [
					[target.id, otherWorkspace],
					[pairedApplication, workspace],
					[pairedProduction.id, workspace],
					[development.id, platformWorkspaceId],
				] as const) {
					await expect(
						registerDevelopment(id, workspaceId),
					).rejects.toMatchObject(invalidBinding);
				}
				await expect(
					registerDevelopment(target.id, "workspace-slug"),
				).rejects.toMatchObject({ code: "22023" });
				await expect(register(target.id, workspace)).rejects.toMatchObject(
					invalidBinding,
				);
				await expect(
					transition(target.id, "legacy", 0, "allauth"),
				).rejects.toMatchObject(invalidBinding);
				await expect(
					database.query(
						'UPDATE public."allauthProject" SET "projectEngineFenced"=TRUE WHERE id=$1',
						[target.id],
					),
				).rejects.toMatchObject(invalidBinding);

				await registerDevelopment(target.id, workspace);
				const pinned = await developmentBinding(target);
				expect(pinned).toMatchObject({
					projectEngineFenced: true,
					workspaceId: workspace,
					schemaName: target.schemaName,
					registeredAt: expect.any(Date),
					writer: "legacy",
					revision: 0,
					allowed: true,
				});
				await registerDevelopment(target.id, workspace);
				await expect(developmentBinding(target)).resolves.toEqual(pinned);
				const { rows } = await database.query(
					`SELECT public.allauth_project_engine_development_allowed($1,$2,$3) AS "wrongWorkspace",
					 public.allauth_project_engine_development_allowed($1,$4,$5) AS "wrongSchema",
					 public.allauth_project_engine_development_allowed($6,$4,$5) AS "productionInDevelopment",
					 public.allauth_project_engine_production_allowed($1,$4,$3) AS "developmentInProduction",
					 EXISTS (SELECT 1 FROM pg_proc p
					   CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f',p.proowner))) a
					   WHERE p.oid='public.allauth_register_project_engine_development(text,text)'::regprocedure
					   AND a.grantee=0 AND a.privilege_type='EXECUTE') AS "publicCanRegister"`,
					[
						target.id,
						otherWorkspace,
						target.schemaName,
						workspace,
						pairedProduction.schemaName,
						pairedProduction.id,
					],
				);
				expect(rows).toEqual([
					{
						wrongWorkspace: false,
						wrongSchema: false,
						productionInDevelopment: false,
						developmentInProduction: false,
						publicCanRegister: false,
					},
				]);
				await expect(binding(pairedProduction)).resolves.toMatchObject({
					projectEngineFenced: true,
					allowed: true,
					writer: "allauth",
					revision: 1,
				});
			});

			it("serializes enrollment and refuses an unregistered preexisting writer", async () => {
				const holder = await database.connect();
				const registrar = await database.connect();
				try {
					await holder.query("BEGIN");
					await holder.query(
						"SELECT pg_advisory_xact_lock_shared(public.allauth_project_engine_admission_key($1))",
						[otherDevelopment.id],
					);
					await registrar.query("BEGIN");
					await registrar.query("SET LOCAL lock_timeout='100ms'");
					await expect(
						registrar.query(
							"SELECT public.allauth_register_project_engine_development($1,$2)",
							[otherDevelopment.id, otherWorkspace],
						),
					).rejects.toMatchObject({ code: "55P03" });
					await registrar.query("ROLLBACK");

					// A former protected pilot can have a persisted writer even though it has no enrollment marker.
					await registrar.query("BEGIN");
					await registrar.query(
						'UPDATE public."allauthProject" SET "workspaceId"=$1 WHERE id=$2',
						[workspace, development.id],
					);
					await expect(
						registrar.query(
							"SELECT public.allauth_register_project_engine_development($1,$2)",
							[development.id, workspace],
						),
					).rejects.toMatchObject({
						...invalidBinding,
						message: expect.stringContaining("already has a writer revision"),
					});
				} finally {
					await Promise.all([
						holder.query("ROLLBACK"),
						registrar.query("ROLLBACK"),
					]);
					holder.release();
					registrar.release();
				}
				await expect(
					developmentBinding(otherDevelopment),
				).resolves.toMatchObject({
					projectEngineFenced: false,
					allowed: false,
					writer: "legacy",
					revision: 0,
				});
			});

			it("preserves the binding and realm-specific write guards through rollback", async () => {
				const target = customerDevelopment;
				await registerDevelopment(target.id, workspace);
				for (const [assignment, value] of [
					["id=$1", randomUUID()],
					['"projectEngineFenced"=$1', false],
					['"workspaceId"=$1', otherWorkspace],
					['"schemaName"=$1', otherDevelopment.schemaName],
					["environment=$1", "production"],
				] as const) {
					await expect(
						database.query(
							`UPDATE public."allauthProject" SET ${assignment} WHERE id=$2`,
							[value, target.id],
						),
					).rejects.toMatchObject(invalidBinding);
				}

				await expect(
					transition(otherDevelopment.id, "legacy", 0, "allauth"),
				).rejects.toMatchObject(invalidBinding);
				await expect(
					transition(target.id, "legacy", 0, "allauth"),
				).resolves.toEqual({ writer: "allauth", revision: 1 });
				await expect(
					transition(target.id, "legacy", 0, "allauth"),
				).rejects.toMatchObject({ code: "AU002" });
				const active = tag("allauth", target.id, 1);
				const paired = tag("allauth", pairedProduction.id, 1);
				const sessionWrite = (pool: Pool, project: ReturnType<typeof realm>) =>
					pool.query(
						`UPDATE "${project.schemaName}"."session" SET token=token WHERE id='unused-fixture-session'`,
					);
				const createWebhook = (pool: Pool, project: ReturnType<typeof realm>) =>
					pool.query(
						`INSERT INTO "${project.schemaName}"."allauthWebhookEndpoint"(id,url,"eventTypes","encryptedSecret") VALUES ('dev-endpoint','https://webhook.fixture.example/events','["mfa.*"]','fixture')`,
					);
				for (const stale of [database, tag("legacy", target.id, 0), paired]) {
					await expect(sessionWrite(stale, target)).rejects.toMatchObject(
						staleWriter,
					);
					await expect(createWebhook(stale, target)).rejects.toMatchObject(
						staleWriter,
					);
				}
				await expect(sessionWrite(active, target)).resolves.toMatchObject({
					rowCount: 0,
				});
				await expect(createWebhook(active, target)).resolves.toMatchObject({
					rowCount: 1,
				});
				await expect(
					sessionWrite(active, pairedProduction),
				).rejects.toMatchObject(staleWriter);
				await expect(
					sessionWrite(paired, pairedProduction),
				).resolves.toMatchObject({ rowCount: 0 });
				await expect(
					sessionWrite(database, otherDevelopment),
				).resolves.toMatchObject({ rowCount: 0 });
				await expect(
					transition(target.id, "allauth", 1, "legacy"),
				).resolves.toEqual({ writer: "legacy", revision: 2 });
				await expect(sessionWrite(active, target)).rejects.toMatchObject(
					staleWriter,
				);
				await expect(
					sessionWrite(tag("legacy", target.id, 2), target),
				).resolves.toMatchObject({ rowCount: 0 });
				await registerDevelopment(target.id, workspace);
				await expect(developmentBinding(target)).resolves.toMatchObject({
					projectEngineFenced: true,
					allowed: true,
					writer: "legacy",
					revision: 2,
				});
			});
		});
	},
);
