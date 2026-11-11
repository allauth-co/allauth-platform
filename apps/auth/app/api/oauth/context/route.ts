import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import { apiRoute, json } from "@/lib/api";
import { withPortalRequest } from "@/lib/domains/hosting";

export const GET = (request: Request) => apiRoute(request, async () => withPortalRequest(request,async (instance,_env,request) => {
	const query = new URL(request.url).searchParams;
	const serialized = query.toString();
	if (!(await verifyOAuthQueryParams(serialized, (await instance.$context).secret))) throw new APIError("BAD_REQUEST", { message: "The authorization request is invalid or expired." });
	const clientId = query.get("client_id");
	if (!clientId) throw new APIError("BAD_REQUEST");
	const client = await instance.api.getOAuthClientPublicPrelogin({ headers: request.headers, body: { client_id: clientId, oauth_query: serialized } });
	return json({ client: { client_id: client.client_id, client_name: client.client_name }, scopes: (query.get("scope") || "").split(" ").filter(Boolean), continueURL: `/oauth2/continue?${serialized}` });
}));
