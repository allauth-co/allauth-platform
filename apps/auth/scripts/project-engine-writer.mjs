import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";
import {
	agentReplayApprovalSetting,
	agentReplayBridgeIdSetting,
	developmentAgentReplayApprovalsSetting,
	developmentAgentReplayBridgeIdsSetting,
	issueAgentReplayDrainEvidence,
	productionAgentReplayApprovalsSetting,
	productionAgentReplayApprovalValue,
	productionAgentReplayBridgeIdsSetting,
	projectAgentReplayBridgeIdSelected,
	verifyAgentReplayDrainEvidence,
} from "./project-agent-replay-evidence.mjs";
import { assertStoredProjectAgentAdmission } from "./project-agent-stored-admission.mjs";
import { assertProjectOAuthGrantAdmission } from "./project-engine-oauth-grant-admission.mjs";
import {
	developmentProjectEngineRevisionsSetting,
	productionProjectEngineRevisionsSetting,
	projectEngineIdPattern,
	readProjectEngineRevisions,
} from "./project-engine-rollout-selection.mjs";
import { verifyEncryptedSamlActivation } from "./project-engine-saml-approval.mjs";
import { verifyProjectWebhookActivation } from "./project-engine-webhook-admission.mjs";

if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
await projectEngine(process.argv.slice(2));

async function projectEngine(args) {
	const scope =
		args[0] === "--project"
			? "production"
			: args[0] === "--development"
				? "development"
				: "protected";
	const enrolled = scope !== "protected";
	const [operation, previous, revision, next, ...rest] = enrolled
		? args.slice(2)
		: args;
	const registering =
		operation === "register-production"
			? "production"
			: operation === "register-development"
				? "development"
				: undefined;
	if (
		registering &&
		(enrolled ||
			args.length !== 3 ||
			!projectEngineIdPattern.test(previous) ||
			!projectEngineIdPattern.test(revision))
	)
		throw new Error(
			`Supply the exact ${registering} project ID and workspace ID.`,
		);

	const selectedId =
		process.env.ALLAUTH_PROJECT_ENGINE_INTERNAL_ID?.trim() ?? "";
	const bridgeId = process.env[agentReplayBridgeIdSetting]?.trim() ?? "";
	const reading = operation === "status" && previous === undefined;
	const issuingAgentEvidence =
		operation === "agent-replay-evidence" &&
		previous !== undefined &&
		revision !== undefined &&
		next === undefined;
	let id = selectedId;
	if (registering) id = previous;
	else if (enrolled) id = args[1];
	else if (issuingAgentEvidence) id = bridgeId;
	if (!projectEngineIdPattern.test(id)) {
		if (enrolled) throw new Error(`The exact ${scope} project ID is required.`);
		if (issuingAgentEvidence)
			throw new Error(
				"The exact protected Agent replay bridge ID is required.",
			);
		throw new Error("The exact protected internal project ID is required.");
	}
	if (
		!enrolled &&
		issuingAgentEvidence &&
		selectedId &&
		selectedId !== bridgeId
	)
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
		const prepared = enrolled
			? readProjectEngineRevisions(
					process.env[
						scope === "production"
							? productionProjectEngineRevisionsSetting
							: developmentProjectEngineRevisionsSetting
					],
					scope,
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
	try {
		if (registering) {
			await pool.query(
				`SELECT public.allauth_register_project_engine_${registering}($1,$2)`,
				[id, revision],
			);
			console.log(JSON.stringify({ projectId: id, workspaceId: revision }));
			return;
		}
		if (issuingAgentEvidence) {
			console.log(
				await issueAgentEvidence(pool, {
					id,
					scope,
					deployment: previous,
					drainedAt: agentDrainTime(revision, enrolled),
				}),
			);
			return;
		}
		const current = reading
			? await readWriter(pool, id, scope)
			: await switchProject(pool, {
					id,
					previous,
					revision: Number(revision),
					next,
					scope,
					bridgeId,
				});
		if (!current)
			throw new Error(
				enrolled
					? `The registered ${scope} project is unavailable.`
					: "The protected internal project is unavailable.",
			);
		console.log(JSON.stringify(current));
	} finally {
		await pool.end();
	}
}

async function readWriter(database, id, scope) {
	const binding =
		scope !== "protected"
			? `p.environment=$2 AND p."projectEngineFenced"
		   AND public.allauth_project_engine_binding_allowed(p.id,p."schemaName")`
			: `p.environment=$2 AND NOT p."projectEngineFenced" AND w.protected AND w.id='00000000-0000-4000-8000-000000000001'`;
	const {
		rows: [current],
	} = await database.query(
		`SELECT COALESCE(f.writer,'legacy') AS writer, COALESCE(f.revision,0) AS revision
		 FROM public."allauthProject" p JOIN public."allauthWorkspace" w ON w.id=p."workspaceId"
		 LEFT JOIN public."allauthProjectEngineWriter" f ON f."projectId"=p.id
		 WHERE p.id=$1 AND p."schemaName"='allauth_project_' || replace(p.id,'-','') AND ${binding}`,
		[id, scope === "protected" ? "development" : scope],
	);
	return current;
}

function agentDrainTime(value, enrolled) {
	const timestamp = Date.parse(value);
	if (
		enrolled &&
		(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value) ||
			!Number.isFinite(timestamp) ||
			new Date(timestamp).toISOString().slice(0, 19) !== value.slice(0, 19))
	)
		throw new Error("Supply the observed Agent drain time in UTC.");
	return timestamp;
}

function agentReplaySecret() {
	const { ALLAUTH_AUTH_SECRET: current, BETTER_AUTH_SECRET: legacy } =
		process.env;
	if (current !== undefined && legacy !== undefined && current !== legacy)
		throw new Error(
			"ALLAUTH_AUTH_SECRET and BETTER_AUTH_SECRET must match when both are set.",
		);
	return current ?? legacy ?? "";
}

async function issueAgentEvidence(pool, { id, scope, deployment, drainedAt }) {
	const enrolled = scope !== "protected";
	if (enrolled && !enrolledAgentBridgeConfigured(id, scope))
		throw new Error(
			`The registered ${scope} project Agent replay bridge is unavailable.`,
		);
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			"SELECT pg_advisory_xact_lock(public.allauth_project_engine_admission_key($1))",
			[id],
		);
		const current = await readWriter(client, id, scope);
		if (current?.writer !== "legacy")
			throw new Error(
				enrolled
					? `Agent drain evidence requires the registered ${scope} legacy writer.`
					: "Agent drain evidence requires the protected legacy writer.",
			);
		if (enrolled)
			await assertStoredProjectAgentAdmission(
				client,
				`allauth_project_${id.replaceAll("-", "")}`,
			);
		const evidence = issueAgentReplayDrainEvidence(
			agentReplaySecret(),
			id,
			current.revision,
			deployment,
			drainedAt,
		);
		await client.query("COMMIT");
		return evidence;
	} catch (error) {
		await client.query("ROLLBACK");
		throw error;
	} finally {
		client.release();
	}
}

async function switchProject(pool, options) {
	const { id, previous, revision, next, scope } = options;
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			"SELECT pg_advisory_xact_lock(public.allauth_project_engine_admission_key($1))",
			[id],
		);
		const current = await readWriter(client, id, scope);
		if (current?.writer !== previous || current.revision !== revision)
			throw new Error(
				scope !== "protected"
					? `The registered ${scope} project or writer revision changed.`
					: "The protected project writer revision changed.",
			);
		const schema = `allauth_project_${id.replaceAll("-", "")}`;
		if (previous !== next) await verifyAgentSwitch(client, schema, options);
		if (previous === "legacy" && next === "allauth") {
			await assertProjectOAuthGrantAdmission(client, schema);
			await verifyProjectWebhookActivation(client, id, schema);
			await verifyEncryptedSamlActivation(
				client,
				id,
				schema,
				revision,
				process.env,
				scope,
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
	{ id, revision, next, scope, bridgeId },
) {
	const enrolled = scope !== "protected";
	const {
		rows: [stored],
	} = await client.query(
		`SELECT EXISTS (SELECT 1 FROM "${schema}"."agentHost")
		 OR EXISTS (SELECT 1 FROM "${schema}"."approvalRequest")
		 OR EXISTS (SELECT 1 FROM "${schema}"."verification"
		  WHERE "expiresAt" > statement_timestamp() AND identifier LIKE ANY
		   (ARRAY['agent-status-jti:%','host-registration-jti:%','host-agent-key-rotation-jti:%'])) AS agent`,
	);
	const raw = enrolled
		? productionAgentReplayApprovalValue(
				process.env[
					scope === "production"
						? productionAgentReplayApprovalsSetting
						: developmentAgentReplayApprovalsSetting
				],
				id,
			)
		: process.env[agentReplayApprovalSetting]?.trim() || "";
	if (!stored.agent && !raw) return;
	if (enrolled && next === "allauth" && !raw)
		throw new Error(
			`Stored Agent state requires ${scope} replay approval before activation.`,
		);
	if (enrolled ? !enrolledAgentBridgeConfigured(id, scope) : bridgeId !== id)
		throw new Error(
			enrolled
				? `The registered ${scope} project Agent replay bridge is unavailable.`
				: "The protected project Agent replay bridge is unavailable.",
		);
	if (next === "allauth") {
		verifyAgentReplayDrainEvidence(raw, agentReplaySecret(), id, revision);
		await assertStoredProjectAgentAdmission(client, schema);
	}
}

function enrolledAgentBridgeConfigured(id, scope) {
	return projectAgentReplayBridgeIdSelected(
		process.env[
			scope === "production"
				? productionAgentReplayBridgeIdsSetting
				: developmentAgentReplayBridgeIdsSetting
		],
		id,
		scope,
	);
}
