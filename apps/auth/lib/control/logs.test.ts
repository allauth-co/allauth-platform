import { admin,organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach,describe,expect,it } from "vitest";
import { allauthControl } from "./index";
import { controlLogsQuery } from "./logs";
import type { ControlEventsResponse } from "./types";
const origin = "http://localhost:3000";
async function setup() {
	const instance = await getTestInstance({ logger: { disabled: true },session: { cookieCache: { enabled: true } },plugins: [admin(),organization(),allauthControl()] },{ disableTestUser: true });
	const context = await instance.auth.$context;
	const user = await instance.auth.api.signUpEmail({ body: { name: "Owner",email: "owner@fixture.example",password: "fixture-log-password" } });
	await context.adapter.update({ model: "user",where: [{ field: "id",value: user.user.id }],update: { role: "admin",emailVerified: true } });
	const login = await instance.auth.api.signInEmail({ body: { email: "owner@fixture.example",password: "fixture-log-password" },asResponse: true });
	const cookie = login.headers.getSetCookie().map((entry) => entry.split(";",1)[0]).join("; ");
	for (const id of ["org-owned","org-foreign"]) await context.adapter.create({ model: "organization",forceAllowId: true,data: { id,name: id,slug: id,createdAt: new Date() } });
	await context.adapter.create({ model: "member",data: { userId: user.user.id,organizationId: "org-owned",role: "owner",createdAt: new Date() } });
	for (const [id,userId,organizationId] of [["owned-event",user.user.id,"org-owned"],["foreign-event","other-user","org-foreign"],["expired-event",user.user.id,"org-owned"]]) await context.adapter.create({ model: "allauthEvent",forceAllowId: true,data: { id,type: "fixture.login",outcome: "success",userId,organizationId,actorId: "actor-one",targetId: "target-one",clientId: "client-one",ipAddress: "192.0.2.1",userAgent: "Fixture",createdAt: new Date(Date.now()-(id === "expired-event" ? 91*86400_000 : 0)),metadata: { method: "password",sessionId: "safe-session-id",token: "private-token",password: "private-password",nested: { secret: "private" } } } });
	const request = (path: string,authCookie = cookie) => instance.auth.handler(new Request(`${origin}/api/auth${path}`,{ headers: authCookie ? { cookie: authCookie } : {} }));
	return { instance,context,userId: user.user.id,cookie,request };
}
/** @see https://www.better-auth.com/docs/plugins/organization#access-control */
describe("native log list and detail scope",() => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => { state = await setup(); });
	it("projects safe metadata and exact actor/target/client/IP filters without leaking credentials",async () => {
		const response = await state.request("/control/logs?scope=user&type=fixture.login&actorId=actor-one&targetId=target-one&clientId=client-one&ipAddress=192.0.2.1"); expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store");
		const data = await response.json() as ControlEventsResponse; expect(data.total).toBe(1); expect(data.events[0]).toMatchObject({ id: "owned-event",metadata: { method: "password",sessionId: "safe-session-id" } }); expect(JSON.stringify(data)).not.toMatch(/private-token|private-password|nested|secret/);
		const detail = await state.request("/control/logs/detail?scope=user&id=owned-event"); expect(detail.status).toBe(200); expect(await detail.json()).toEqual({ event: data.events[0] });
	});
	it("denies foreign account filters and cannot read a guessed foreign or expired detail ID",async () => {
		expect((await state.request("/control/logs?scope=user&userId=other-user")).status).toBe(403);
		for (const id of ["foreign-event","expired-event"]) expect((await state.request(`/control/logs/detail?scope=user&id=${id}`)).status).toBe(404);
		expect((await state.request("/control/logs?scope=user","")).status).toBe(401);
	});
	it("rechecks organization membership for both listing and inspection",async () => {
		expect((await state.request("/control/logs/detail?scope=organization&organizationId=org-foreign&id=foreign-event")).status).toBe(403);
		expect((await state.request("/control/logs?scope=organization&organizationId=org-foreign")).status).toBe(403);
		expect((await state.request("/control/logs/detail?scope=organization&organizationId=org-owned&id=owned-event")).status).toBe(200);
		await state.context.adapter.updateMany({ model: "member",where: [{ field: "userId",value: state.userId }],update: { role: "member" } });
		expect((await state.request("/control/logs/detail?scope=organization&organizationId=org-owned&id=owned-event")).status).toBe(403);
	});
	it("uses fresh administrator authority and never inherits impersonated administrative access",async () => {
		expect((await state.request("/control/logs/detail?scope=admin&id=foreign-event")).status).toBe(200);
		const live = await state.instance.auth.api.getSession({ headers: new Headers({ cookie: state.cookie }) });
		await state.context.adapter.update({ model: "session",where: [{ field: "id",value: live!.session.id }],update: { impersonatedBy: "another-admin" } });
		expect((await state.request("/control/logs?scope=admin")).status).toBe(403); expect((await state.request("/control/logs/detail?scope=admin&id=foreign-event")).status).toBe(403);
	});
	it("rejects spoofed IPs and invalid ranges, and reports unsupported non-PG session searches honestly",async () => {
		for (const ip of ["192.0.2.1, 203.0.113.1","evil.example","[::1]"]) expect(controlLogsQuery.safeParse({ ipAddress: ip }).success).toBe(false);
		expect(controlLogsQuery.parse({ ipAddress: "2001:0DB8::1" }).ipAddress).toBe("2001:db8::1");
		expect((await state.request("/control/logs?scope=admin&sessionId=safe-session-id")).status).toBe(400);
		expect((await state.request("/control/logs?scope=admin&limit=101")).status).toBe(400);
	});
});
