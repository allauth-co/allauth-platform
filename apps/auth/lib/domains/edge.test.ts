import {describe,expect,it,vi} from "vitest";
import {boundedEdgeBody,edgeHeaders,portalHeader,portalPathAllowed,signEdgeRequest,signPortalBinding,strippedEdgeHeaders,verifyEdgeRequest,verifyPortalBinding} from "./edge";
const secret="fixture-gateway-secret-at-least-thirty-two-characters";
const now=1791350000000;
const url="https://accounts.customer.com/api/auth/sign-in/email?next=%2Faccount";
const body='{"email":"fixture@customer.com","password":"fixture-value"}';
async function signed() {const original=new Request(url,{method:"POST",body,headers:{"content-type":"application/json"}});return new Request("https://origin.up.railway.app/api/auth/sign-in/email?next=%2Faccount",{method:"POST",body,headers:await signEdgeRequest(original,secret,"accounts.customer.com","192.0.2.5",now)});}
describe("authentication gateway envelope",()=>{
	it("preserves authentication payload and binds original customer host/IP across origin rewrite",async()=>{const request=await signed();expect(await verifyEdgeRequest(request,secret,now)).toEqual({hostname:"accounts.customer.com",ip:"192.0.2.5"});expect(await request.text()).toBe(body);});
	it.each(["method","path","query","body","host","ip","time","signature"])("rejects changed %s",async(field)=>{const request=await signed();const headers=new Headers(request.headers);let changedUrl=request.url;let method="POST";let changedBody=body;if(field==="method")method="PUT";if(field==="path")changedUrl=changedUrl.replace("sign-in/email","sign-up/email");if(field==="query")changedUrl+="&extra=1";if(field==="body")changedBody+=" ";if(field==="host")headers.set(edgeHeaders[0],"accounts.other.com");if(field==="ip")headers.set(edgeHeaders[1],"192.0.2.6");if(field==="time")headers.set(edgeHeaders[2],String(now/1000+1));if(field==="signature")headers.set(edgeHeaders[3],"0".repeat(64));expect(await verifyEdgeRequest(new Request(changedUrl,{method,body:changedBody,headers}),secret,now)).toBeNull();});
	it("rejects expired requests and another deployment's secret",async()=>{expect(await verifyEdgeRequest(await signed(),secret,now+61000)).toBeNull();expect(await verifyEdgeRequest(await signed(),secret+"different",now)).toBeNull();});
	it("rejects forged proxy proof and client-address headers before gateway signing",async()=>{const headers=new Headers({[portalHeader]:"spoof",forwarded:"for=10.0.0.1","x-real-ip":"10.0.0.1","cf-connecting-ip":"10.0.0.2","x-forwarded-host":"allauth.co"});for(const key of edgeHeaders)headers.set(key,"spoof");const clean=strippedEdgeHeaders(headers);expect([...clean]).toEqual([]);});
	it("requires independently authenticated, fresh server-rendered bindings",async()=>{const proof=await signPortalBinding("accounts.customer.com",secret,now);expect(await verifyPortalBinding(proof,secret,now)).toBe("accounts.customer.com");expect(await verifyPortalBinding(proof,secret,now+61000)).toBeNull();expect(await verifyPortalBinding(proof.replace(/.$/,"x"),secret,now)).toBeNull();expect(await verifyPortalBinding(proof,secret+"different",now)).toBeNull();});
	it("caps streamed bodies without trusting Content-Length",async()=>{const request=new Request(url,{method:"POST",body:new Uint8Array(262145)});await expect(boundedEdgeBody(request)).rejects.toThrow("limit");});
	it.each(["/admin/users","/api/admin/users","/api/workspaces","/api/projects/other/auth/get-session","/api/organizations/other/scim"])("does not expose platform management path %s on customer hosts",(path)=>{expect(portalPathAllowed(path,"accounts")).toBe(false);expect(portalPathAllowed(path,"frontend-api")).toBe(false);});
	it("allows only the exact console entry on customer account hosts",()=>{expect(portalPathAllowed("/console","accounts")).toBe(true);expect(portalPathAllowed("/console","frontend-api")).toBe(false);expect(portalPathAllowed("/console/child","accounts")).toBe(false);expect(portalPathAllowed("/console/child","frontend-api")).toBe(false);});
	it.each(["/sign-in","/magic-link","/magic-link-sent","/email-otp","/reset-link-sent","/account/security","/api/auth/get-session","/api/account/sessions","/.well-known/openid-configuration"])("allows the realm's authentication path %s",(path)=>{expect(portalPathAllowed(path,"accounts")).toBe(true);});
	it.each([
		"/api/auth/scim/v2/Users",
		"/api/auth/sso/saml2/sp/acs/fixture-provider",
	])("bounds hosted protocol body reads for %s before binding", async (path) => {
		const url = `https://accounts.customer.com${path}`;
		const signed = await signEdgeRequest(
			new Request(url, { method: "POST", body: "fixture" }),
			secret,
			"accounts.customer.com",
			"192.0.2.5",
			now,
		);
		vi.useFakeTimers();
		try {
			const stalled = new Request(url, {
				method: "POST",
				headers: signed,
				body: new ReadableStream<Uint8Array>(),
				duplex: "half",
			} as RequestInit);
			const verification = verifyEdgeRequest(stalled, secret, now);
			await vi.advanceTimersByTimeAsync(5000);
			await expect(verification).resolves.toBeNull();
		} finally {
			vi.useRealTimers();
		}
	});
});
