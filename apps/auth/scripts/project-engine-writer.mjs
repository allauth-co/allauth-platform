import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";
import {
	agentReplayApprovalSetting,
	agentReplayBridgeIdSetting,
	issueAgentReplayDrainEvidence,
	verifyAgentReplayDrainEvidence,
} from "./project-agent-replay-evidence.mjs";
import { assertStoredProjectAgentAdmission } from "./project-agent-stored-admission.mjs";
import { assertProjectOAuthGrantAdmission } from "./project-engine-oauth-grant-admission.mjs";
import {
	productionProjectEngineRevisionsSetting,
	projectEngineIdPattern,
	readProductionProjectEngineRevisions,
} from "./project-engine-rollout-selection.mjs";
import { verifyEncryptedSamlActivation } from "./project-engine-saml-approval.mjs";
import { verifyProjectWebhookActivation } from "./project-engine-webhook-admission.mjs";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
await projectEngine(process.argv.slice(2));

async function projectEngine(args) {
	const production = args[0] === "--project";
	const [operation, previous, revision, next, ...rest] = production
		? args.slice(2)
		: args;
	const registering = operation === "register-production";
	if (
		registering &&
		(production ||
			args.length !== 3 ||
			!projectEngineIdPattern.test(previous) ||
			!projectEngineIdPattern.test(revision))
	)
		throw new Error("Supply the exact production project ID and workspace ID.");

	const selectedId =
		process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_ID?.trim() ?? "";
	const bridgeId = process.env[agentReplayBridgeIdSetting]?.trim() ?? "";
	const reading = operation === "status" && previous === undefined;
	const issuingAgentEvidence =
		!production &&
		operation === "agent-replay-evidence" &&
		previous !== undefined &&
		revision !== undefined &&
		next === undefined;
	let id = selectedId;
	if (registering) id = previous;
	else if (production) id = args[1];
	else if (issuingAgentEvidence) id = bridgeId;
	if (!projectEngineIdPattern.test(id)) {
		if (production)
			throw new Error("The exact production project ID is required.");
		if (issuingAgentEvidence)
			throw new Error(
				"The exact protected Agent replay bridge ID is required.",
			);
		throw new Error("The exact protected internal project ID is required.");
	}
	if (issuingAgentEvidence && selectedId && selectedId !== bridgeId)
		throw new Error(
			"The protected project Agent replay bridge is unavailable.",
		);
	const writers = ["legacy", "allauth"];
	if (
		!registering &&
		!reading &&
		!issuingAgentEvidence &&
		(operation !== "switch" ||
			rest.length ||
			!writers.includes(previous) ||
			!writers.includes(next) ||
			!/^(0|[1-9][0-9]{0,9})$/.test(revision ?? "") ||
			Number(revision) > 2147483647)
	)
		throw new Error("Supply the expected writer, revision and next writer.");
	if (operation === "switch" && previous === "legacy" && next === "allauth") {
		const prepared = production
			? readProductionProjectEngineRevisions(
					process.env[productionProjectEngineRevisionsSetting],
				)
					.get(id)
					?.toString()
			: process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION?.trim() ||
				"0";
		if (revision !== prepared)
			throw new Error(
				"Deploy and verify readiness for the exact legacy revision before activating AllAuth.",
			);
	}
	const pool = new Pool({
		connectionString: process.env.DATABASE_URL,
		max: 1,
		connectionTimeoutMillis: 10000,
		options: "-c lock_timeout=10000 -c statement_timeout=20000",
	});
	const replaySecret =
		process.env.ALLAUTH_AUTH_SECRET || process.env.BETTER_AUTH_SECRET || "";
	try {
		if (registering) {
			await pool.query(
				"SELECT public.allauth_register_project_engine_production($1,$2)",
				[id, revision],
			);
			console.log(JSON.stringify({ projectId: id, workspaceId: revision }));
			return;
		}
		if (issuingAgentEvidence) {
			const current = await readWriter(pool, id, false);
			if (current?.writer !== "legacy")
				throw new Error(
					"Agent drain evidence requires the protected legacy writer.",
				);
			console.log(
				issueAgentReplayDrainEvidence(
					replaySecret,
					id,
					current.revision,
					previous,
					Date.parse(revision),
				),
			);
			return;
		}
		const current = reading
			? await readWriter(pool, id, production)
			: await switchProject(pool, {
					id,
					previous,
					revision: Number(revision),
					next,
					production,
					bridgeId,
					replaySecret,
				});
		if (!current)
			throw new Error(
				production
					? "The registered production project is unavailable."
					: "The protected internal project is unavailable.",
			);
		console.log(JSON.stringify(current));
	} finally {
		await pool.end();
	}
}

async function readWriter(database, id, production) {
	const binding = production
		? `p.environment='production'
		   AND public.allauth_project_engine_production_allowed(p.id,p."workspaceId",p."schemaName")`
		: `p.environment='development' AND w.protected AND w.id='00000000-0000-4000-8000-000000000001'`;
	const {
		rows: [current],
	} = await database.query(
		`SELECT COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision
		 FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
		 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id
		 WHERE p.id=$1 AND p."schemaName"='allauth_project_' || replace(p.id,'-','') AND ${binding}`,
		[id],
	);
	return current;
}

async function switchProject(pool, options) {
	const { id, previous, revision, next, production } = options;
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			"SELECT pg_advisory_xact_lock(public.allauth_project_engine_admission_key($1))",
			[id],
		);
		const current = await readWriter(client, id, production);
		if (current?.writer !== previous || current.revision !== revision)
			throw new Error(
				production
					? "The registered production project or writer revision changed."
					: "The protected project writer revision changed.",
			);
		const schema = `allauth_project_${id.replaceAll("-", "")}`;
		if (previous !== next && (!production || next === "allauth"))
			await verifyAgentSwitch(client, schema, options);
		if (previous === "legacy" && next === "allauth") {
			await assertProjectOAuthGrantAdmission(client, schema);
			await verifyProjectWebhookActivation(client, id, schema);
			// The protected encrypted SAML approval applies only to the internal pilot.
			await verifyEncryptedSamlActivation(
				client,
				id,
				schema,
				revision,
				production ? {} : process.env,
			);
		}
		const {
			rows: [selected],
		} = await client.query(
			"SELECT writer,revision FROM public.allauth_switch_project_engine_writer($1,$2,$3,$4)",
			[id, previous, revision, next],
		);
		await client.query("COMMIT");
		return selected;
	} catch (error) {
		await client.query("ROLLBACK");
		throw error;
	} finally {
		client.release();
	}
}

async function verifyAgentSwitch(
	client,
	schema,
	{ id, revision, next, production, bridgeId, replaySecret },
) {
	const {
		rows: [stored],
	} = await client.query(
		`SELECT EXISTS (SELECT 1 FROM "${schema}"."agentHost") OR EXISTS (SELECT 1 FROM "${schema}"."approvalRequest") AS agent`,
	);
	if (production) {
		if (stored.agent)
			throw new Error(
				"Stored Agent state requires production replay approval before activation.",
			);
		return;
	}
	const raw = process.env[agentReplayApprovalSetting]?.trim() || "";
	if (!stored.agent && !raw) return;
	if (bridgeId !== id)
		throw new Error(
			"The protected project Agent replay bridge is unavailable.",
		);
	if (next === "allauth") {
		verifyAgentReplayDrainEvidence(raw, replaySecret, id, revision);
		await assertStoredProjectAgentAdmission(client, schema);
	}
}
