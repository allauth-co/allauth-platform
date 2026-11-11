import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getAuthEnvironment } from "./lib/auth";
import { authOrigin, setting } from "./lib/configuration";
import { edgeHeaders, portalHeader, portalPathAllowed, signPortalBinding, verifyEdgeRequest } from "./lib/domains/edge";
import { resolveHostedBinding } from "./lib/domains/hosting";
export async function proxy(request:NextRequest) {
	const headers=new Headers(request.headers);headers.delete(portalHeader);
	if(!edgeHeaders.some(name=>headers.has(name))) {
		for(const name of edgeHeaders) headers.delete(name);
		// Railway's internal readiness probe uses its own Host; this route exposes only readiness status.
		if(request.nextUrl.pathname==="/api/health" && ["GET","HEAD"].includes(request.method)) return NextResponse.next({request:{headers}});
		// Railway owns its direct hostname and the canonical platform hostname. Customer origins require a signed gateway.
		const expected=new URL(authOrigin(process.env)).hostname;
		const host=(headers.get("host")||request.nextUrl.host).split(":")[0];
		const railway=setting(process.env,"ALLAUTH_ORIGIN_HOSTNAME") || "allauth-production.up.railway.app";
		if(![expected,railway,"localhost","127.0.0.1","[::1]"].includes(host)) return new NextResponse("Unknown authentication hostname.",{status:404,headers:{"cache-control":"no-store"}});
		return NextResponse.next({request:{headers}});
	}
	try {
		const env=await getAuthEnvironment();const edge=await verifyEdgeRequest(request,setting(env,"ALLAUTH_EDGE_SECRET"));
		if(!edge) return new NextResponse("Invalid authentication gateway request.",{status:403,headers:{"cache-control":"no-store"}});
		const binding=await resolveHostedBinding(edge.hostname,env);
		if(!binding || !portalPathAllowed(request.nextUrl.pathname,binding.kind)) return new NextResponse("Authentication route is unavailable on this hostname.",{status:404,headers:{"cache-control":"no-store"}});
		headers.set(portalHeader,await signPortalBinding(edge.hostname,setting(env,"ALLAUTH_EDGE_SECRET")));headers.set("x-real-ip",edge.ip);
		return NextResponse.next({request:{headers}});
	} catch {return new NextResponse("Authentication gateway is unavailable.",{status:503,headers:{"cache-control":"no-store"}});}
}
export const config={matcher:"/:path*"};
