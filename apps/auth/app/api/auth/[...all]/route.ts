import { withPortalRequest } from "@/lib/domains/hosting";
import { authOrigin } from "@/lib/configuration";
import { localDevelopmentAuthRequest } from "@/lib/local-development";

const publicProtocolPaths = new Set(["/api/auth/oauth2/token", "/api/auth/oauth2/userinfo", "/api/auth/jwks"]);
function protocolHeaders(request: Request, headers: Headers) {
	headers.set("Cache-Control", "no-store"); headers.set("Pragma", "no-cache");
	if (publicProtocolPaths.has(new URL(request.url).pathname)) {
		headers.set("Access-Control-Allow-Origin", "*");
		headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		headers.set("Access-Control-Allow-Headers", "authorization, content-type, dpop");
	}
}
async function handle(request: Request) {
	const response = await withPortalRequest(request, async (instance, env, bound, binding) => {
		const result=await instance.handler(binding ? bound : localDevelopmentAuthRequest(bound, authOrigin(env), process.env.NODE_ENV));
		protocolHeaders(request,result.headers);
		const origin=bound.headers.get("origin");
		if(binding && origin && binding.project.origins.includes(origin)) {result.headers.set("Access-Control-Allow-Origin",origin);result.headers.set("Access-Control-Allow-Credentials","true");result.headers.append("Vary","Origin");}
		return result;
	});
	return response;
}
export const GET = handle; export const POST = handle; export const PUT = handle; export const PATCH = handle; export const DELETE = handle;
export async function OPTIONS(request: Request) { return withPortalRequest(request,async (_instance,_env,bound,binding)=>{ const headers=new Headers();protocolHeaders(request,headers);const origin=bound.headers.get("origin");if(binding && origin && binding.project.origins.includes(origin)){headers.set("Access-Control-Allow-Origin",origin);headers.set("Access-Control-Allow-Credentials","true");headers.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");headers.set("Access-Control-Allow-Headers","content-type, authorization");headers.set("Vary","Origin");} return new Response(null,{status:204,headers}); }); }
