/** The gateway and origin share a short-lived, body-bound request envelope. No hostname header alone grants routing. */
export const edgeHeaders = ["x-allauth-edge-host", "x-allauth-edge-ip", "x-allauth-edge-time", "x-allauth-edge-signature"] as const;
export const portalHeader = "x-allauth-portal-binding";
export const maxEdgeBody = 262144;
const encoder = new TextEncoder();
const hex = (value: ArrayBuffer) => Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2,"0")).join("");
const bytes = (value: string) => new Uint8Array(value.match(/.{2}/g)!.map((pair) => parseInt(pair,16)));
async function key(secret: string) { if (secret.length < 32) throw new Error("Gateway secret is not configured."); return crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]); }
export async function boundedEdgeBody(request: Request): Promise<Uint8Array<ArrayBuffer>> {
	const reader = request.clone().body?.getReader(); if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = []; let length=0;
	try { for (;;) { const next=await reader.read(); if(next.done) break; length+=next.value.length; if(length>maxEdgeBody) { void reader.cancel().catch(()=>{}); throw new Error("Request body exceeds gateway limit."); } chunks.push(next.value); } }
	finally { reader.releaseLock(); }
	const body=new Uint8Array(length); let offset=0; for(const chunk of chunks) {body.set(chunk,offset);offset+=chunk.length;} return body;
}
async function message(request: Request, hostname: string, ip: string, timestamp: string) {
	const url=new URL(request.url); const body=await boundedEdgeBody(request);
	return encoder.encode(JSON.stringify(["allauth-edge-v1",request.method.toUpperCase(),url.pathname+url.search,hostname,ip,timestamp,hex(await crypto.subtle.digest("SHA-256",body))]));
}
export function canonicalEdgeHost(value: string): boolean { return value.length<=253 && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) && value.includes(".") && !value.includes(".."); }
export function strippedEdgeHeaders(input: Headers): Headers {
	const headers=new Headers(input);
	for(const name of [...edgeHeaders,portalHeader,"forwarded","x-forwarded-host","x-forwarded-for","x-forwarded-proto","x-real-ip","cf-connecting-ip","true-client-ip"]) headers.delete(name);
	return headers;
}
export async function signEdgeRequest(request: Request, secret: string, hostname: string, ip: string, time=Date.now()) {
	if(!canonicalEdgeHost(hostname) || !ip || ip.length>64 || /[\s,]/.test(ip)) throw new Error("Invalid gateway identity.");
	const timestamp=String(Math.floor(time/1000));
	const signature=hex(await crypto.subtle.sign("HMAC",await key(secret),await message(request,hostname,ip,timestamp)));
	const headers=strippedEdgeHeaders(request.headers);
	headers.set(edgeHeaders[0],hostname);headers.set(edgeHeaders[1],ip);headers.set(edgeHeaders[2],timestamp);headers.set(edgeHeaders[3],signature);
	return headers;
}
export async function verifyEdgeRequest(request: Request, secret: string, time=Date.now()): Promise<{hostname:string;ip:string}|null> {
	try {
		const [hostname,ip,timestamp,signature]=edgeHeaders.map((name)=>request.headers.get(name)||"");
		if(!canonicalEdgeHost(hostname) || !ip || ip.length>64 || /[\s,]/.test(ip) || !/^\d{10}$/.test(timestamp) || Math.abs(Math.floor(time/1000)-Number(timestamp))>60 || !/^[a-f0-9]{64}$/.test(signature)) return null;
		return await crypto.subtle.verify("HMAC",await key(secret),bytes(signature),await message(request,hostname,ip,timestamp)) ? {hostname,ip} : null;
	} catch { return null; }
}
/** Proxy mints this proof for server-rendered reads after verifying the complete edge request. */
export async function signPortalBinding(hostname: string, secret: string, time=Date.now()): Promise<string> {
	const payload=JSON.stringify(["allauth-portal-v1",hostname,Math.floor(time/1000)]);
	return `${btoa(payload)}.${hex(await crypto.subtle.sign("HMAC",await key(secret),encoder.encode(payload)))}`;
}
export async function verifyPortalBinding(value: string | null, secret: string, time=Date.now()): Promise<string|null> {
	try { if(!value || value.length>1024) return null; const [encoded,signature,...extra]=value.split("."); if(extra.length || !/^[a-f0-9]{64}$/.test(signature)) return null;
		const payload=atob(encoded); const parsed=JSON.parse(payload) as unknown;
		if(!Array.isArray(parsed) || parsed.length!==3 || parsed[0]!=="allauth-portal-v1" || typeof parsed[1]!=="string" || !canonicalEdgeHost(parsed[1]) || !Number.isSafeInteger(parsed[2]) || Math.abs(Math.floor(time/1000)-Number(parsed[2]))>60) return null;
		return await crypto.subtle.verify("HMAC",await key(secret),bytes(signature),encoder.encode(payload)) ? parsed[1] : null;
	} catch{return null;}
}
export function portalPathAllowed(pathname: string, kind: "accounts"|"frontend-api") {
	if(pathname==="/console") return kind==="accounts";
	if (pathname.startsWith("/api/")) return /^\/api\/auth(?:\/|$)/.test(pathname) || pathname==="/api/config" || /^\/api\/account\/sessions(?:\/revoke)?$/.test(pathname) || pathname==="/api/oauth/context";
	if(pathname==="/.well-known/openid-configuration" || pathname==="/.well-known/oauth-authorization-server") return true;
	return pathname==="/" || /^\/(account|organizations|organization|sign-in|sign-up|sign-out|forgot-password|reset-password|reset-link-sent|magic-link|magic-link-sent|email-otp|verify-email|two-factor|enterprise-sign-in|accept-invitation|auth-callback|auth-error|auth-redirect|oauth|oauth2|_next|brand)(\/|$)/.test(pathname) || /^\/(favicon\.ico|icon\.png|apple-icon\.png|robots\.txt)$/.test(pathname);
}
