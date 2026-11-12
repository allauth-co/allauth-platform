import * as z from "zod";

// Keep protocol inputs server-owned on social and enterprise authorization requests.
const reservedAuthorizationParams = new Set([
	"state",
	"client_id",
	"redirect_uri",
	"response_type",
	"code_challenge",
	"code_challenge_method",
	"nonce",
	"scope",
]);

export const projectAdditionalAuthorizationParams = z
	.record(z.string(), z.string())
	.refine(
		(params) =>
			!Object.keys(params).some((name) =>
				reservedAuthorizationParams.has(name),
			),
	)
	.optional();

export function setProjectAdditionalAuthorizationParams(
	url: URL,
	params: z.infer<typeof projectAdditionalAuthorizationParams>,
) {
	for (const [name, value] of Object.entries(params ?? {})) {
		if (!reservedAuthorizationParams.has(name))
			url.searchParams.set(name, value);
	}
}
