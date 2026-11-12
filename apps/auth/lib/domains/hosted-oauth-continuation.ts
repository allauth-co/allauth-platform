import type { AuthEngine } from "../auth-engine";

/** The verified realm's issuer must recognize the same serialized browser continuation. */
export async function verifiedHostedOAuthContinuation(
	engine: Pick<AuthEngine, "readOAuthContext">,
	hostname: string,
	query: string,
) {
	const response = await engine
		.readOAuthContext(
			new Request(`https://${hostname}/api/oauth/context?${query}`, {
				headers: { accept: "application/json" },
			}),
		)
		.catch(() => null);
	if (!response?.ok) return false;
	const result: unknown = await response.json().catch(() => null);
	return Boolean(
		result &&
			typeof result === "object" &&
			"continueURL" in result &&
			result.continueURL === `/oauth2/continue?${query}`,
	);
}
