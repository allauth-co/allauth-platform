import { passkeyMutationKeys } from "@better-auth-ui/core/plugins/passkey";

const expectedCeremonyCodes = new Set([
	"AUTH_CANCELLED",
	"ERROR_CEREMONY_ABORTED",
	"ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY",
]);

function errorRecord(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === "object"
		? (value as Record<string, unknown>)
		: undefined;
}

/** Identify native browser ceremony outcomes without hiding server or RP configuration failures.
 * @see packages/passkey/src/client.ts
 */
export function isExpectedPasskeyCeremonyError(
	error: unknown,
	mutationKey?: readonly unknown[],
): boolean {
	if (
		!passkeyMutationKeys.signIn.every(
			(part, index) => mutationKey?.[index] === part,
		)
	)
		return false;
	const chain: Record<string, unknown>[] = [];
	let current = errorRecord(error);
	while (current && chain.length < 8 && !chain.includes(current)) {
		chain.push(current);
		current = errorRecord(current.error) ?? errorRecord(current.cause);
	}
	// Better Auth returns browser ceremony errors with status 400. An HTTP auth,
	// rate-limit or server failure still needs the original actionable reporting.
	if (
		chain.some(
			(entry) =>
				entry.status !== undefined &&
				entry.status !== 400 &&
				entry.status !== "400",
		)
	)
		return false;
	return chain.some(
		(entry) =>
			(typeof entry.code === "string" &&
				expectedCeremonyCodes.has(entry.code.toUpperCase())) ||
			entry.name === "NotAllowedError" ||
			entry.name === "AbortError",
	);
}
