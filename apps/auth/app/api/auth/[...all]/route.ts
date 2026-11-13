import { withPortalAuthEngine } from "@/lib/domains/hosting";
import { authOrigin } from "@/lib/configuration";
import {
	hostedOAuthBrowserActionRequests,
	hostedVerificationLinkRequests,
} from "@/lib/domains/hosted-oauth-requests";
import { localDevelopmentAuthRequest } from "@/lib/local-development";
import { projectOpenApiPath } from "@/lib/projects/owned-project-openapi";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";

const publicProtocolPaths = new Set(["/api/auth/oauth2/token", "/api/auth/oauth2/userinfo", "/api/auth/jwks"]);
function protocolHeaders(request: Request, headers: Headers) {
	headers.set("Cache-Control", "no-store"); headers.set("Pragma", "no-cache");
	if (publicProtocolPaths.has(new URL(request.url).pathname)) {
		headers.set("Access-Control-Allow-Origin", "*");
		headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		headers.set("Access-Control-Allow-Headers", "authorization, content-type, dpop");
	}
}
function unavailable(request: Request, error: unknown) {
	if (!isProjectWriterUnavailable(error)) throw error;
	const response = Response.json({ error: "Authentication is temporarily unavailable." }, { status: 503 });
	protocolHeaders(request, response.headers);
	return response;
}
async function handle(request: Request) {
	const response = await withPortalAuthEngine(request, async (engine, env, bound, binding) => {
		const path = new URL(bound.url).pathname;
		if (
			binding?.kind === "accounts" &&
			bound.method === "POST" &&
			(path === "/api/auth/oauth2/continue" || path === "/api/auth/oauth2/consent")
		)
			hostedOAuthBrowserActionRequests.add(bound);
		if (
			binding?.kind === "accounts" &&
			bound.method === "GET" &&
			path === "/api/auth/verify-email"
		)
			hostedVerificationLinkRequests.add(bound);
		// The hosted gateway removes Authorization before the browser request reaches auth.
		const mixedSchemaCredentials =
			binding &&
			request.method === "GET" &&
			request.headers.has("authorization") &&
			path === `/api/auth${projectOpenApiPath}`;
		const result = mixedSchemaCredentials
			? Response.json(
					{
						code: "FORBIDDEN",
						message: "Use your signed-in browser session for this action.",
					},
					{ status: 403 },
				)
			: await engine.dispatch(
					binding
						? bound
						: localDevelopmentAuthRequest(bound, authOrigin(env), process.env.NODE_ENV),
				);
		protocolHeaders(request,result.headers);
		const origin=bound.headers.get("origin");
		if(binding && origin && binding.project.origins.includes(origin)) {result.headers.set("Access-Control-Allow-Origin",origin);result.headers.set("Access-Control-Allow-Credentials","true");result.headers.append("Vary","Origin");}
		return result;
	}).catch((error: unknown) => unavailable(request, error));
	return response;
}
export const GET = handle; export const POST = handle; export const PUT = handle; export const PATCH = handle; export const DELETE = handle;
export async function OPTIONS(request: Request) { return withPortalAuthEngine(request,async (_engine,_env,bound,binding)=>{ const headers=new Headers();protocolHeaders(request,headers);const origin=bound.headers.get("origin");if(binding && origin && binding.project.origins.includes(origin)){headers.set("Access-Control-Allow-Origin",origin);headers.set("Access-Control-Allow-Credentials","true");headers.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");headers.set("Access-Control-Allow-Headers","content-type, authorization");headers.set("Vary","Origin");} return new Response(null,{status:204,headers}); }).catch((error: unknown) => unavailable(request, error)); }
