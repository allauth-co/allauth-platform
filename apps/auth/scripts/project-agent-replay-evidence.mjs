import { createHmac, timingSafeEqual } from "node:crypto";
import {
	projectEngineIdPattern,
	readProjectEngineApprovalValue,
} from "./project-engine-rollout-selection.mjs";

export const agentReplayApprovalSetting =
	"ALLAUTH_PROJECT_ENGINE_AGENT_REPLAY_APPROVAL";
export const agentReplayBridgeIdSetting =
	"ALLAUTH_PROJECT_ENGINE_AGENT_BRIDGE_ID";
export const productionAgentReplayBridgeIdsSetting =
	"ALLAUTH_PROJECT_ENGINE_PRODUCTION_AGENT_BRIDGE_IDS";
export const productionAgentReplayApprovalsSetting =
	"ALLAUTH_PROJECT_ENGINE_PRODUCTION_AGENT_REPLAY_APPROVALS";
export const developmentAgentReplayBridgeIdsSetting =
	"ALLAUTH_PROJECT_ENGINE_DEVELOPMENT_AGENT_BRIDGE_IDS";
export const developmentAgentReplayApprovalsSetting =
	"ALLAUTH_PROJECT_ENGINE_DEVELOPMENT_AGENT_REPLAY_APPROVALS";
const kind = "operator-verified-agent-replay-drain-v1";
const drainWindowMs = 90_000;
const preparationWindowMs = 15 * 60_000;
const encoder = new TextEncoder();

/** @param {string | undefined} raw @param {"development" | "production"} scope @returns {Set<string>} */
export function readProjectAgentReplayBridgeIds(raw, scope = "production") {
	const configured = raw?.trim();
	if (!configured) return new Set();
	const ids = new Set();
	for (const entry of configured.split(",")) {
		const id = entry.trim();
		if (!projectEngineIdPattern.test(id) || ids.has(id))
			throw new Error(`The ${scope} project Agent bridge IDs are invalid.`);
		ids.add(id);
	}
	return ids;
}

/** @param {string | undefined} raw @param {string} projectId @param {"development" | "production"} scope */
export function projectAgentReplayBridgeIdSelected(
	raw,
	projectId,
	scope = "production",
) {
	return readProjectAgentReplayBridgeIds(raw, scope).has(projectId);
}

export const productionAgentReplayApprovalValue =
	readProjectEngineApprovalValue;

function unavailable() {
	return new Error("The project Agent replay drain evidence is unavailable.");
}

/** @param {string} id */
function schemaName(id) {
	return `allauth_project_${id.replaceAll("-", "")}`;
}

/** @param {string} secret @param {unknown[]} payload */
function fingerprint(secret, payload) {
	return createHmac("sha256", secret)
		.update(`${kind}\n`)
		.update(JSON.stringify(payload))
		.digest("hex");
}

/** @param {string} secret @param {string} id @param {number} revision @param {string} deployment @param {number} drainedAt */
export function issueAgentReplayDrainEvidence(
	secret,
	id,
	revision,
	deployment,
	drainedAt,
	now = Date.now(),
) {
	const payload = [id, schemaName(id), revision, deployment, drainedAt, now];
	const evidence = JSON.stringify({
		kind,
		payload,
		signature: fingerprint(secret, payload),
	});
	verifyAgentReplayDrainEvidence(evidence, secret, id, revision, now);
	return evidence;
}

/** @param {string} raw @param {string} secret @param {string} id @param {number} revision @param {"preparing" | "active"} mode */
export function verifyAgentReplayDrainEvidence(
	raw,
	secret,
	id,
	revision,
	now = Date.now(),
	mode = "preparing",
) {
	try {
		if (
			secret.length < 32 ||
			raw.length > 2048 ||
			!projectEngineIdPattern.test(id)
		)
			throw unavailable();
		const evidence = JSON.parse(raw);
		if (
			evidence?.kind !== kind ||
			!Array.isArray(evidence.payload) ||
			evidence.payload.length !== 6 ||
			typeof evidence.signature !== "string" ||
			!/^[a-f0-9]{64}$/.test(evidence.signature)
		)
			throw unavailable();
		const [
			projectId,
			schema,
			legacyRevision,
			deployment,
			drainedAt,
			observedAt,
		] = evidence.payload;
		if (
			projectId !== id ||
			schema !== schemaName(id) ||
			legacyRevision !== revision ||
			!Number.isInteger(revision) ||
			revision < 0 ||
			revision >= 2147483647 ||
			typeof deployment !== "string" ||
			!/^[A-Za-z0-9._:/-]{1,128}$/.test(deployment) ||
			!Number.isSafeInteger(drainedAt) ||
			drainedAt <= 0 ||
			!Number.isSafeInteger(observedAt) ||
			observedAt > now ||
			observedAt - drainedAt < drainWindowMs ||
			(mode === "preparing" && now - observedAt >= preparationWindowMs) ||
			!timingSafeEqual(
				encoder.encode(evidence.signature),
				encoder.encode(fingerprint(secret, evidence.payload)),
			)
		)
			throw unavailable();
		return true;
	} catch {
		throw unavailable();
	}
}
