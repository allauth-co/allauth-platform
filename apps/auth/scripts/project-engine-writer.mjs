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
import { verifyEncryptedSamlActivation } from "./project-engine-saml-approval.mjs";
import { verifyProjectWebhookActivation } from "./project-engine-webhook-admission.mjs";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
await projectEngine(process.argv.slice(2));

async function projectEngine([operation, previous, revision, next, ...rest]) {
	const selectedId = process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_ID?.trim() ?? "";
	const bridgeId = process.env[agentReplayBridgeIdSetting]?.trim() ?? "";
	const reading = operation === "status" && previous === undefined;
	const issuingAgentEvidence =
		operation === "agent-replay-evidence" &&
		previous !== undefined &&
		revision !== undefined &&
		next === undefined;
	const id = issuingAgentEvidence ? bridgeId : selectedId;
	if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id))
		throw new Error(issuingAgentEvidence ? "The exact protected Agent replay bridge ID is required." : "The exact protected internal project ID is required.");
	if (issuingAgentEvidence && selectedId && selectedId !== bridgeId)
		throw new Error("The protected project Agent replay bridge is unavailable.");
	const writers = ["legacy", "allauth"];
	if (
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
	const prepared =
		process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION?.trim() || "0";
	if (
		!reading &&
		previous === "legacy" &&
		next === "allauth" &&
		revision !== prepared
	)
		throw new Error(
			"Deploy and verify readiness for the exact legacy revision before activating AllAuth.",
		);
	const pool = new Pool({
		connectionString: process.env.DATABASE_URL,
		max: 1,
		connectionTimeoutMillis: 10000,
		options: "-c lock_timeout=10000 -c statement_timeout=20000",
	});
	const replaySecret =
		process.env.ALLAUTH_AUTH_SECRET || process.env.BETTER_AUTH_SECRET || "";
	try {
		if (issuingAgentEvidence) {
			const current = await readProtectedWriter(pool, id);
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
			? await readProtectedWriter(pool, id)
			: previous !== next
				? await switchProtectedProject(pool, id, previous, Number(revision), next, bridgeId, replaySecret)
				: (
						await pool.query(
							"SELECT writer,revision FROM public.allauth_switch_project_engine_writer($1,$2,$3,$4)",
							[id, previous, Number(revision), next],
						)
					).rows[0];
		if (!current)
			throw new Error("The protected internal project is unavailable.");
		console.log(JSON.stringify(current));
	} finally {
		await pool.end();
	}
}

async function readProtectedWriter(database, id) {
	const {
		rows: [current],
	} = await database.query(
		`SELECT COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision
		 FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
		 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id
		 WHERE p.id=$1 AND p.environment='development' AND w.protected
		 AND w.id='00000000-0000-4000-8000-000000000001'
		 AND p."schemaName"='allauth_project_' || replace(p.id,'-','')`,
		[id],
	);
	return current;
}

async function switchProtectedProject(pool, id, previous, revision, next, bridgeId, secret) {
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			"SELECT pg_advisory_xact_lock(public.allauth_project_engine_admission_key($1))",
			[id],
		);
		const current = await readProtectedWriter(client, id);
		if (current?.writer !== previous || current.revision !== revision)
			throw new Error("The protected project writer revision changed.");
		const schema = `allauth_project_${id.replaceAll("-", "")}`;
		const {
			rows: [stored],
		} = await client.query(
			`SELECT EXISTS (SELECT 1 FROM "${schema}"."agentHost") OR EXISTS (SELECT 1 FROM "${schema}"."approvalRequest") AS agent`,
		);
		const raw = process.env[agentReplayApprovalSetting]?.trim() || "";
		if (stored.agent || raw) {
			if (bridgeId !== id) throw new Error("The protected project Agent replay bridge is unavailable.");
			if (next === "allauth") {
				verifyAgentReplayDrainEvidence(raw, secret, id, revision);
				await assertStoredProjectAgentAdmission(client, schema);
			}
		}
		if (next === "allauth") {
			await assertProjectOAuthGrantAdmission(client, schema);
			await verifyProjectWebhookActivation(client, id, schema);
			await verifyEncryptedSamlActivation(client, id, schema, revision, process.env);
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
