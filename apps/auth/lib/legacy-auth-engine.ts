import { runWithAdapter } from "@better-auth/core/context";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import type { AuthInstance } from "./api";
import type { AuthEngine } from "./auth-engine";
import { discoveryDocument, discoveryHeaders } from "./discovery";

type LegacyInstance = Pick<AuthInstance, "$context" | "handler"> & {
	api: Pick<
		AuthInstance["api"],
		| "getSession"
		| "accountSessions"
		| "accountRevokeSession"
		| "getOpenIdConfig"
		| "getOAuthServerConfig"
		| "getOAuthClientPublicPrelogin"
	>;
};

const engines = new WeakMap<LegacyInstance, AuthEngine>();

/** Bind to the exact native instance and adapter selected for this request. */
export function legacyAuthEngine(instance: LegacyInstance): AuthEngine {
	const existing = engines.get(instance);
	if (existing) return existing;

	async function withAdapter<T>(operation: () => Promise<T>): Promise<T> {
		return runWithAdapter((await instance.$context).adapter, operation);
	}

	const engine: AuthEngine = {
		dispatch: (request) => instance.handler(request),
		readIssuerMetadata: (kind) =>
			withAdapter(async () => {
				const document =
					kind === "openid"
						? await instance.api.getOpenIdConfig()
						: await instance.api.getOAuthServerConfig();
				return Response.json(discoveryDocument(document), {
					headers: discoveryHeaders,
				});
			}),
		readOAuthContext: (request) =>
			withAdapter(async () => {
				const query = new URL(request.url).searchParams;
				const serialized = query.toString();
				if (
					!(await verifyOAuthQueryParams(
						serialized,
						(
							await instance.$context
						).secret,
					))
				)
					throw new APIError("BAD_REQUEST", {
						message: "The authorization request is invalid or expired.",
					});
				const clientId = query.get("client_id");
				if (!clientId) throw new APIError("BAD_REQUEST");
				const client = await instance.api.getOAuthClientPublicPrelogin({
					headers: request.headers,
					body: { client_id: clientId, oauth_query: serialized },
				});
				return Response.json(
					{
						client: {
							client_id: client.client_id,
							client_name: client.client_name,
						},
						scopes: (query.get("scope") || "").split(" ").filter(Boolean),
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
			}),
		readPrincipal: (headers) =>
			withAdapter(async () => {
				const current = await instance.api.getSession({
					headers,
					query: { disableCookieCache: true },
				});
				if (!current) return null;
				const { session, user } = current;
				return {
					session: {
						id: session.id,
						userId: session.userId,
						impersonatedBy: session.impersonatedBy ?? undefined,
					},
					user: {
						id: user.id,
						name: user.name,
						email: user.email,
						emailVerified: user.emailVerified,
						role: user.role ?? undefined,
						banned: user.banned ?? undefined,
					},
				};
			}),
		readSession: (request) =>
			withAdapter(() =>
				instance.api.getSession({
					headers: request.headers,
					request,
					query: {
						disableCookieCache: true,
						...(new URL(request.url).searchParams.get("disableRefresh") === "true" ? { disableRefresh: true } : {}),
					},
					asResponse: true,
				}),
			),
		listAccountSessions: (headers) =>
			instance.api.accountSessions({ headers, asResponse: true }),
		revokeAccountSession: (headers, body) =>
			instance.api.accountRevokeSession({ headers, body, asResponse: true }),
		readDirectory: (operation, headers, query) =>
			withAdapter(async () => {
				const endpoint: unknown = Reflect.get(instance.api, operation);
				if (typeof endpoint !== "function")
					throw new Error("Directory endpoint is unavailable.");
				return Reflect.apply(endpoint, instance.api, [
					{ headers, query, asResponse: true },
				]) as Promise<Response>;
			}),
	};
	// The admission coordinator uses this identity to distinguish policy revisions.
	engines.set(instance, engine);
	return engine;
}
