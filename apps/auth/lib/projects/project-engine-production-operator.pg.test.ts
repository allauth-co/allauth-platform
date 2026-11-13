import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	productionAgentReplayApprovalsSetting,
	productionAgentReplayBridgeIdsSetting,
} from "../../scripts/project-agent-replay-evidence.mjs";
import { productionProjectEngineRevisionsSetting } from "../../scripts/project-engine-rollout-selection.mjs";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const service = new URL("../../", import.meta.url);
const execute = promisify(execFile);
const legacy = { writer: "legacy", revision: 0 };
const signingSecret = "disposable-production-writer-fixture-secret";

function project() {
	const id = randomUUID();
	return { id, schema: `allauth_project_${id.replaceAll("-", "")}` };
}

describe.skipIf(!existsSync(fixturePath))(
	"production project writer operator",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const workspace = randomUUID();
		const otherWorkspace = randomUUID();
		const target = project();
		const guarded = project();
		const sibling = project();
		let admin: Pool | undefined;
		let database: Pool | undefined;
		let databaseUrl: string;
		let created = false;

		async function script(
			name: string,
			args: string[],
			env: Record<string, string> = {},
		) {
			const path = fileURLToPath(new URL(`scripts/${name}.mjs`, service));
			return execute(process.execPath, [path, ...args], {
				cwd: service,
				env: {
					...process.env,
					DATABASE_URL: databaseUrl,
					ALLAUTH_DEPLOYMENT_MODE: "self-hosted",
					ALLAUTH_AUTH_SECRET: signingSecret,
					BETTER_AUTH_SECRET: signingSecret,
					ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: "",
					ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION: "",
					ALLAUTH_PROJECT_ENGINE_AGENT_BRIDGE_ID: "",
					ALLAUTH_PROJECT_ENGINE_AGENT_REPLAY_APPROVAL: "",
					ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL: "",
					[productionAgentReplayApprovalsSetting]: "",
					[productionAgentReplayBridgeIdsSetting]: "",
					[productionProjectEngineRevisionsSetting]: "",
					...env,
				},
			});
		}

		async function command(args: string[], env?: Record<string, string>) {
			const { stdout } = await script("project-engine-writer", args, env);
			return JSON.parse(stdout) as unknown;
		}

		function prepare(revisions: Record<string, number>) {
			return {
				[productionProjectEngineRevisionsSetting]: JSON.stringify(revisions),
			};
		}

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
					"Writer operator tests require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			databaseUrl = url.href;
			database = new Pool({ connectionString: databaseUrl, max: 2 });
			await script("database", ["migrate"]);
			await database.query(
				`INSERT INTO public."allauthWorkspace"(id,name,slug,protected)
			 VALUES ($1,'Writer operator','writer-operator',false),($2,'Writer sibling','writer-sibling',false)`,
				[workspace, otherWorkspace],
			);
			for (const [realm, slug, workspaceId] of [
				[target, "writer-operator-target", workspace],
				[guarded, "writer-operator-guarded", workspace],
				[sibling, "writer-operator-sibling", otherWorkspace],
			] as const) {
				await database.query(`CREATE SCHEMA "${realm.schema}"`);
				await database.query(
					`INSERT INTO public."allauthProject"(id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId")
				 VALUES ($1,'Writer operator fixture',$2,$3,'https://writer.fixture.example','fixture','fixture',$4,'fixture',$1,'production',$5)`,
					[realm.id, slug, realm.schema, randomUUID(), workspaceId],
				);
			}
			await script("database", ["migrate"]);
		}, 30_000);

		afterAll(async () => {
			await database?.end();
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		it("pins an exact realm and supports rollback when its deployment selection is disabled", async () => {
			const args = ["--project", target.id];
			await expect(command([...args, "status"])).rejects.toThrow(
				/registered production project/,
			);
			await expect(
				command(["register-production", target.id, otherWorkspace]),
			).rejects.toThrow(/binding is invalid/);
			await expect(command([...args, "status"])).rejects.toThrow(
				/registered production project/,
			);
			const registration = { projectId: target.id, workspaceId: workspace };
			await expect(
				command(["register-production", target.id, workspace]),
			).resolves.toEqual(registration);
			await expect(
				command(["register-production", target.id, workspace]),
			).resolves.toEqual(registration);
			await expect(command([...args, "status"])).resolves.toEqual(legacy);

			await expect(
				command([...args, "switch", "legacy", "0", "allauth"]),
			).rejects.toThrow(/exact legacy revision/);
			await expect(
				command(
					[...args, "switch", "legacy", "0", "allauth"],
					prepare({ [target.id]: 1 }),
				),
			).rejects.toThrow(/exact legacy revision/);
			await expect(
				command(
					["--project", sibling.id, "switch", "legacy", "0", "allauth"],
					prepare({ [sibling.id]: 0 }),
				),
			).rejects.toThrow(/registered production project/);
			await expect(command([...args, "status"])).resolves.toEqual(legacy);

			const unrelatedPilot = randomUUID();
			const exact = {
				...prepare({ [target.id]: 0, [sibling.id]: 0 }),
				ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: unrelatedPilot,
				ALLAUTH_PROJECT_ENGINE_AGENT_BRIDGE_ID: unrelatedPilot,
				ALLAUTH_PROJECT_ENGINE_AGENT_REPLAY_APPROVAL:
					"unrelated-protected-replay-evidence",
				ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL:
					"unrelated-protected-encrypted-approval",
			};
			const active = { writer: "allauth", revision: 1 };
			await expect(
				command([...args, "switch", "legacy", "0", "allauth"], exact),
			).resolves.toEqual(active);
			await expect(
				command(["--project", sibling.id, "status"]),
			).rejects.toThrow(/registered production project/);
			await expect(
				command(["switch", "allauth", "1", "allauth"], {
					ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: target.id,
				}),
			).rejects.toThrow(/protected project writer revision changed/);
			await expect(command([...args, "status"])).resolves.toEqual(active);

			const malformed = { [productionProjectEngineRevisionsSetting]: "{" };
			await expect(command([...args, "status"], malformed)).resolves.toEqual(
				active,
			);
			await expect(
				command([...args, "switch", "allauth", "1", "legacy"], malformed),
			).resolves.toEqual({ writer: "legacy", revision: 2 });
			await expect(
				command([...args, "switch", "legacy", "0", "allauth"], exact),
			).rejects.toThrow(/writer revision changed/);
			await expect(command([...args, "status"])).resolves.toEqual({
				writer: "legacy",
				revision: 2,
			});
		}, 30_000);

		it("rechecks production grant and Agent state before changing the writer", async () => {
			const args = ["--project", guarded.id];
			const selection = prepare({ [guarded.id]: 0 });
			await command(["register-production", guarded.id, workspace]);
			await database!.query(
				`INSERT INTO "${guarded.schema}"."oauthClient"(id,"clientId","redirectUris","grantTypes")
			 VALUES ('fixture-client','fixture-client','["https://writer.fixture.example/callback"]','["client_credentials"]')`,
			);
			await expect(
				command([...args, "switch", "legacy", "0", "allauth"], selection),
			).rejects.toThrow(/OAuth client grants/);
			await expect(command([...args, "status"])).resolves.toEqual(legacy);
			await database!.query(
				`DELETE FROM "${guarded.schema}"."oauthClient" WHERE id='fixture-client'`,
			);
			await database!.query(
				`INSERT INTO "${guarded.schema}"."user"(id,name,email,"emailVerified","createdAt","updatedAt")
			 VALUES ('fixture-owner','Fixture owner','owner@writer.fixture.example',true,now(),now());
			 INSERT INTO "${guarded.schema}"."agentHost"(id,"userId","publicKey",status,"createdAt","updatedAt")
			 VALUES ('fixture-host','fixture-owner','{}','active',now(),now())`,
			);
			await expect(
				command([...args, "switch", "legacy", "0", "allauth"], selection),
			).rejects.toThrow(/Stored Agent state/);
			await expect(command([...args, "status"])).resolves.toEqual(legacy);
			await database!.query(
				`DELETE FROM "${guarded.schema}"."agentHost" WHERE id='fixture-host';
				 INSERT INTO "${guarded.schema}"."verification" (id,identifier,value,"expiresAt")
				 VALUES ('fixture-replay','agent-status-jti:fixture','fixture-replay',now()+interval '90 seconds')`,
			);
			const bridge = { [productionAgentReplayBridgeIdsSetting]: guarded.id };
			const drainedAt = new Date(Date.now() - 120_000).toISOString();
			const evidence = [...args, "agent-replay-evidence", "fixture-deployment"];
			await expect(
				command([...evidence, drainedAt.slice(0, -1)], bridge),
			).rejects.toThrow("observed Agent drain time in UTC");
			const mismatchedAlias = {
				BETTER_AUTH_SECRET: `${signingSecret}-different`,
			};
			await expect(
				command([...evidence, drainedAt], { ...bridge, ...mismatchedAlias }),
			).rejects.toThrow(
				"ALLAUTH_AUTH_SECRET and BETTER_AUTH_SECRET must match",
			);
			const approval = await command([...evidence, drainedAt], bridge);
			const candidate = {
				...selection,
				...bridge,
				[productionAgentReplayApprovalsSetting]: JSON.stringify({
					[guarded.id]: approval,
				}),
			};
			const activation = [...args, "switch", "legacy", "0", "allauth"];
			await expect(
				command(activation, { ...candidate, ...mismatchedAlias }),
			).rejects.toThrow(
				"ALLAUTH_AUTH_SECRET and BETTER_AUTH_SECRET must match",
			);
			await expect(command(activation, candidate)).resolves.toEqual({
				writer: "allauth",
				revision: 1,
			});
			const rollback = [...args, "switch", "allauth", "1", "legacy"];
			await expect(command(rollback)).rejects.toThrow(
				"Agent replay bridge is unavailable",
			);
			await expect(
				command(rollback, { ...bridge, ...mismatchedAlias }),
			).resolves.toEqual({ writer: "legacy", revision: 2 });
		}, 20_000);
	},
);
