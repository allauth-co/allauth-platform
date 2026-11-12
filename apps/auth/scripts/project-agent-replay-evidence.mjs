import { createHmac, timingSafeEqual } from "node:crypto";

export const agentReplayApprovalSetting =
	"ALLAUTH_PROJECT_ENGINE_AGENT_REPLAY_APPROVAL";
const kind = "operator-verified-agent-replay-drain-v1";
const drainWindowMs = 90_000;
const preparationWindowMs = 15 * 60_000;
const encoder = new TextEncoder();

function unavailable() {
	return new Error(
		"The protected project Agent replay drain evidence is unavailable.",
	);
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
			!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)
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
