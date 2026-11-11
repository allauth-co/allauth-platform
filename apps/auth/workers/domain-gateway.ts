import { signEdgeRequest, strippedEdgeHeaders } from "../lib/domains/edge";
interface GatewayEnvironment { ALLAUTH_ORIGIN: string; ALLAUTH_EDGE_SECRET: string }
/** Customer hostnames terminate TLS at Cloudflare; the origin verifies every signed request again. */
export default {
	async fetch(request: Request, env: GatewayEnvironment): Promise<Response> {
		try {
			const incoming=new URL(request.url); const origin=new URL(env.ALLAUTH_ORIGIN);
			if(origin.protocol!=="https:" || !origin.hostname.endsWith(".up.railway.app") || origin.pathname!=="/" || origin.search || origin.hash || origin.username || origin.password) throw new Error("Invalid origin.");
			const ip=request.headers.get("cf-connecting-ip") || "";
			const headers=await signEdgeRequest(request,env.ALLAUTH_EDGE_SECRET,incoming.hostname,ip);
			headers.delete("host"); origin.pathname=incoming.pathname;origin.search=incoming.search;
			const outgoing=new Request(origin,{method:request.method,headers,body:request.body,redirect:"manual"});
			const response=await fetch(outgoing);
			const returned=strippedEdgeHeaders(response.headers);
			returned.set("cache-control","no-store");returned.set("pragma","no-cache");
			return new Response(response.body,{status:response.status,statusText:response.statusText,headers:returned});
		} catch { return Response.json({error:"Authentication gateway is unavailable."},{status:503,headers:{"cache-control":"no-store"}}); }
	},
};
