import type { PoolClient } from "pg";
import * as z from "zod";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { projectIssuerScopes } from "./owned-project-issuer-authorization-query";
import { issuerJSON, ProjectOAuthError } from "./owned-project-issuer-http";

const find = z.object({ id: z.string() });
const update = find.extend({
	update: z.object({ scopes: z.array(z.string()) }),
});
const fields = `id,"clientId","userId","referenceId",resources,"requestedUserInfoClaims",scopes,"createdAt","updatedAt"`;
const operations = new Map<
	string,
	{
		method: "GET" | "POST";
		action: "get" | "list" | "update" | "delete";
	}
>([
	["/oauth2/get-consent", { method: "GET", action: "get" }],
	["/oauth2/get-consents", { method: "GET", action: "list" }],
	["/oauth2/update-consent", { method: "POST", action: "update" }],
	["/oauth2/delete-consent", { method: "POST", action: "delete" }],
] as const);

const missing = (message: string) =>
	new ProjectOAuthError("not_found", message, 404).response();
const unauthorized = () =>
	Response.json(
		{ code: "UNAUTHORIZED", message: "Unauthorized" },
		{
			status: 401,
			headers: { "cache-control": "no-store", pragma: "no-cache" },
		},
	);

/** Read and manage existing user consent in the active project schema. */
export function createOwnedProjectConsentManagement(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	authorize(
		client: PoolClient,
		request: Request,
		write: boolean,
	): Promise<string | null>;
	readBody(request: Request): Promise<unknown>;
}) {
	return async (path: string, request: Request) => {
		const operation = operations.get(path);
		if (!operation || request.method !== operation.method) return;
		const { action, method } = operation;
		const write = method === "POST";
		const input = write
			? await options.readBody(request)
			: {
					id: new URL(request.url).searchParams.get("id"),
				};
		return options.store.transaction(async (client) => {
			const userId = await options.authorize(client, request, write);
			if (!userId) return unauthorized();
			if (action === "list") {
				const { rows } = await client.query(
					`SELECT ${fields} FROM "oauthConsent" WHERE "userId"=$1`,
					[userId],
				);
				return issuerJSON(rows);
			}
			const change = action === "update" ? update.safeParse(input) : null;
			const parsed = change ?? find.safeParse(input);
			if (!parsed.success)
				return new ProjectOAuthError(
					"invalid_request",
					"Invalid consent request.",
				).response();
			const { id } = parsed.data;
			if (!id) return missing("missing id parameter");
			const {
				rows: [consent],
			} = await client.query<{ userId: string | null; clientId: string }>(
				`SELECT ${fields} FROM "oauthConsent" WHERE id=$1`,
				[id],
			);
			if (!consent) return missing("no consent");
			if (consent.userId !== userId) return unauthorized();
			if (action === "get") return issuerJSON(consent);
			if (action === "delete") {
				await client.query(
					`DELETE FROM "oauthConsent" WHERE id=$1 AND "userId"=$2`,
					[id, userId],
				);
				return new Response(null, {
					headers: { "cache-control": "no-store", pragma: "no-cache" },
				});
			}
			if (!change?.success)
				throw new Error("Consent update is missing scopes.");
			const { scopes } = change.data.update;
			const {
				rows: [oauthClient],
			} = await client.query<{
				scopes: string[] | null;
				referenceId: string | null;
				userId: string | null;
			}>(
				`SELECT scopes,"referenceId","userId" FROM "oauthClient" WHERE "clientId"=$1 FOR SHARE`,
				[consent.clientId],
			);
			if (!oauthClient) return missing("client not found");
			const allowedScopes = new Set(oauthClient.scopes ?? projectIssuerScopes);
			if (!scopes.every((scope) => allowedScopes.has(scope)))
				return new ProjectOAuthError(
					"invalid_request",
					`unable to provide scopes to ${oauthClient.referenceId ?? oauthClient.userId}`,
				).response();
			const {
				rows: [saved],
			} = await client.query(
				`UPDATE "oauthConsent" SET scopes=$3::jsonb,"updatedAt"=date_trunc('second',statement_timestamp())
				 WHERE id=$1 AND "userId"=$2 RETURNING ${fields}`,
				[id, userId, JSON.stringify(scopes)],
			);
			return saved ? issuerJSON(saved) : missing("no consent");
		});
	};
}
