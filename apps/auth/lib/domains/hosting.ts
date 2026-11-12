import { APIError } from "better-auth";
import { getAuthEnvironment, withAuth, withAuthEngine } from "../auth";
import type { AuthInstance } from "../api";
import type { AuthEngine } from "../auth-engine";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import { getProject } from "../projects/registry";
import type { Project } from "../projects/registry";
import { withHostedProjectAuth, withHostedProjectAuthEngine } from "../projects/runtime";
import { lookupActiveHostname } from "./repository";
import { hostingBaseDomain } from "./validation";
import { edgeHeaders, portalHeader, verifyEdgeRequest, verifyPortalBinding } from "./edge";
import type { DomainKind } from "./types";
export interface HostedBinding { project: Project; kind: DomainKind; hostname: string }
/** Infrastructure readiness and an exact stored realm determine routing; unknown names never reach platform auth. */
export async function resolveHostedBinding(hostname: string, env: AuthEnvironment): Promise<HostedBinding | null> {
	if(setting(env,"CLOUDFLARE_SAAS_READY")!=="true" || setting(env,"ALLAUTH_EDGE_SECRET").length<32) return null;
	const base=hostingBaseDomain(env);
	if(hostname.endsWith(`.${base}`)) {
		const label=hostname.slice(0,-base.length-1); const match=/^([a-z][a-z0-9-]{1,47})-(accounts|api)$/.exec(label); if(!match) return null;
		try { return {project:await getProject(match[1],env),kind:match[2]==="accounts" ? "accounts" : "frontend-api",hostname}; }
		catch(error) {if(error instanceof APIError) return null;throw error;}
	}
	const custom=await lookupActiveHostname(hostname,env);
	return custom ? {project:custom.project,kind:custom.kind,hostname} : null;
}
export function hostedHeaders(headers: Headers, binding: HostedBinding, ip?: string): Headers {
	const clean=new Headers(headers); clean.delete("authorization");
	const prefix=`allauth_project_${binding.project.slug}.`;
	const cookies=(headers.get("cookie")||"").split(";").map(value=>value.trim()).filter(value=> {const name=value.slice(0,value.indexOf("="));return name.startsWith(prefix)||name.startsWith(`__Secure-${prefix}`);});
	if(cookies.length) clean.set("cookie",cookies.join("; "));else clean.delete("cookie");
	if(ip) clean.set("x-real-ip",ip);
	return clean;
}
export async function requestHostedBinding(request: Request, env: AuthEnvironment): Promise<{binding:HostedBinding;headers:Headers}|null> {
	if(!edgeHeaders.some(name=>request.headers.has(name))) return null;
	const edge=await verifyEdgeRequest(request,setting(env,"ALLAUTH_EDGE_SECRET"));
	if(!edge) throw new APIError("FORBIDDEN",{message:"Invalid authentication gateway request."});
	const binding=await resolveHostedBinding(edge.hostname,env); if(!binding) throw new APIError("NOT_FOUND",{message:"Authentication hostname is not active."});
	return {binding,headers:hostedHeaders(request.headers,binding,edge.ip)};
}
async function bindPortalRequest(request: Request) {
	const env = await getAuthEnvironment();
	const hosted = await requestHostedBinding(request, env);
	if (!hosted) return { env, request, binding: null };
	const url = new URL(request.url);
	url.protocol = "https:";
	url.host = hosted.binding.hostname;
	const bound = new Request(url, {
		method: request.method,
		headers: hosted.headers,
		body: request.body,
		duplex: "half",
	} as RequestInit);
	return { env, request: bound, binding: hosted.binding };
}

export async function withPortalRequest<T>(request: Request, callback:(instance:AuthInstance,env:AuthEnvironment,request:Request,binding:HostedBinding|null)=>Promise<T>):Promise<T> {
	const { env, request: bound, binding } = await bindPortalRequest(request);
	if (!binding) return withAuth((instance, environment) => callback(instance, environment, bound, null));
	return withHostedProjectAuth(binding.project, binding.hostname, (instance, environment) => callback(instance, environment, bound, binding), env);
}

/** The engine is selected only after verifying the gateway envelope and hostname. */
export async function withPortalAuthEngine<T>(
	request: Request,
	callback: (
		engine: AuthEngine,
		env: AuthEnvironment,
		request: Request,
		binding: HostedBinding | null,
	) => Promise<T>,
): Promise<T> {
	const { env, request: bound, binding } = await bindPortalRequest(request);
	if (!binding) {
		return withAuthEngine((engine, environment) =>
			callback(engine, environment, bound, null),
		);
	}
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		(engine, environment) => callback(engine, environment, bound, binding),
		env,
	);
}
/** Server-rendered pages receive only proxy-minted proofs and re-resolve the active mapping on each read. */
export async function withPortalHeaders<T>(headers:Headers,callback:(instance:AuthInstance,headers:Headers,binding:HostedBinding|null)=>Promise<T>):Promise<T> {
	const proof=headers.get(portalHeader);
	if(!proof) { if(edgeHeaders.some(name=>headers.has(name))) throw new APIError("FORBIDDEN"); return withAuth((instance)=>callback(instance,headers,null)); }
	const env=await getAuthEnvironment();const hostname=await verifyPortalBinding(proof,setting(env,"ALLAUTH_EDGE_SECRET"));
	const binding=hostname ? await resolveHostedBinding(hostname,env) : null;
	if(!binding) throw new APIError("FORBIDDEN");
	return withHostedProjectAuth(binding.project,binding.hostname,(instance)=>callback(instance,hostedHeaders(headers,binding),binding),env);
}
export function portalSession(headers:Headers) {return withPortalHeaders(headers,(instance,bound)=>instance.api.getSession({headers:bound,query:{disableCookieCache:true}}));}
