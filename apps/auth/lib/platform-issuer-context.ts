import type { Pool } from "pg";
import type { AuthEnvironment } from "./configuration";
import { setting } from "./configuration";
import { ConsoleRequestError } from "./console/request-error";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import { readSignedProjectIssuerQuery } from "./projects/owned-project-issuer-authorization-query";

/** Resolve only the signed platform request's public client name and continuation. */
export async function readPlatformIssuerContext(
	request: Request,
	env: AuthEnvironment,
	database: Pick<Pool, "query">,
) {
	const serialized = new URL(request.url).searchParams.toString();
	const { signingSecret } = readLegacyProjectKeyring(
		setting(env, "ALLAUTH_AUTH_SECRET"),
		setting(env, "BETTER_AUTH_SECRETS"),
	);
	const signed = readSignedProjectIssuerQuery(serialized, signingSecret);
	if (!signed)
		throw new ConsoleRequestError(
			400,
			"The authorization request is invalid or expired.",
		);
	const clientId = signed.params.get("client_id");
	if (!clientId || signed.params.getAll("client_id").length !== 1)
		throw new ConsoleRequestError(
			400,
			"The authorization request contains invalid client fields.",
		);
	const {
		rows: [client],
	} = await database.query<{ clientId: string; name: string | null }>(
		`SELECT "clientId", name FROM public."oauthClient" WHERE "clientId"=$1 AND disabled IS DISTINCT FROM true`,
		[clientId],
	);
	if (!client)
		throw new ConsoleRequestError(404, "The OAuth client is unavailable.");
	return Response.json(
		{
			client: {
				client_id: client.clientId,
				client_name: client.name ?? undefined,
			},
			scopes: (signed.params.get("scope") || "").split(" ").filter(Boolean),
			continueURL: `/oauth2/continue?${serialized}`,
		},
		{
			headers: {
				"cache-control": "no-store",
				pragma: "no-cache",
				"x-content-type-options": "nosniff",
			},
		},
	);
}
