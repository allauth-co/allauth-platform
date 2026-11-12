const metadataFields = new Set([
	"path",
	"method",
	"provider",
	"errorCode",
	"reason",
	"status",
	"fields",
	"sessionId",
	"newDevice",
	"knownDevice",
	"riskScore",
	"signal",
	"ruleId",
	"ruleType",
	"policy",
	"monitor",
	"legacy",
	"version",
	"action",
	"count",
	"windowSeconds",
	"blockedUntil",
	"expiresAt",
	"applicationAuditId",
	"actorKind",
	"contextKind",
	"contextId",
]);
const credentialKey =
	/password|secret|token|cookie|authorization|credential|otp|backup.?code|private.?metadata|access.?key|email|address/i;

/** Drop unknown and credential-bearing metadata, and bound strings/arrays before storage. */
export function sanitizeControlMetadata(
	metadata: Record<string, unknown> | undefined,
): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(metadata || {}).slice(0, 32)) {
		if (!metadataFields.has(key) || credentialKey.test(key)) continue;
		if (typeof value === "string")
			result[key] = value.slice(0, 256).replace(/[\u0000-\u001f]/g, "");
		else if (
			typeof value === "boolean" ||
			(typeof value === "number" && Number.isFinite(value)) ||
			value === null
		)
			result[key] = value;
		else if (Array.isArray(value))
			result[key] = value
				.filter(
					(item): item is string =>
						typeof item === "string" && !credentialKey.test(item),
				)
				.slice(0, 20)
				.map((item) => item.slice(0, 80));
	}
	return result;
}

const optionalString = (value: unknown, length: number) =>
	typeof value === "string" && value
		? value.slice(0, length).replace(/[\u0000-\u001f]/g, "")
		: undefined;

const identityFields = [
	"actorId",
	"userId",
	"organizationId",
	"clientId",
	"targetId",
	"ipAddress",
	"userAgent",
] as const;

type IdentityField = (typeof identityFields)[number];

/** Project bounded identity and request context fields without retaining raw credentials. */
export function controlEventAttributes(
	event: Partial<Record<IdentityField, unknown>>,
) {
	const data: Partial<Record<IdentityField, string>> = {};
	for (const field of identityFields) {
		const value = optionalString(
			event[field],
			field === "userAgent" ? 512 : 160,
		);
		if (value) data[field] = value;
	}
	return data;
}
