import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import type { AuthInstance } from "../api";
import { consoleBody, requireConsoleAdministrator } from "./database";

describe("console authority and bounded management input", () => {
	it("rechecks native platform roles and verification despite a valid old signed cookie", async () => {
		const fixture = await getTestInstance({ plugins: [admin()], session: { cookieCache: { enabled: true } } });
		const context = await fixture.auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({ model: "user", where: [{ field: "email", value: fixture.testUser.email }] });
		if (!user) throw new Error("The native fixture user is missing.");
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin", emailVerified: true } });
		const login = await fixture.auth.api.signInEmail({ body: { email: fixture.testUser.email, password: fixture.testUser.password }, asResponse: true });
		const headers = new Headers({ cookie: login.headers.getSetCookie().map((cookie) => cookie.split(";")[0]).join("; ") });
		expect((await requireConsoleAdministrator(fixture.auth as unknown as AuthInstance, headers)).user.id).toBe(user.id);
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "user" } });
		await expect(requireConsoleAdministrator(fixture.auth as unknown as AuthInstance, headers)).rejects.toMatchObject({ statusCode: 403 });
		await context.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin", emailVerified: false } });
		await expect(requireConsoleAdministrator(fixture.auth as unknown as AuthInstance, headers)).rejects.toMatchObject({ statusCode: 403 });
	});
	it("rejects malformed, non-JSON and streamed oversized bodies before mutations", async () => {
		const request = (body: string, type = "application/json") => new Request("http://localhost/manage", { method: "POST", headers: { "content-type": type }, body });
		expect(await consoleBody(request('{"name":"Fixture"}'))).toEqual({ name: "Fixture" });
		await expect(consoleBody(request("{"))).rejects.toMatchObject({ statusCode: 400 });
		await expect(consoleBody(request("{}", "text/plain"))).rejects.toMatchObject({ statusCode: 400 });
		await expect(consoleBody(request(JSON.stringify({ name: "a".repeat(16_384) })))).rejects.toMatchObject({ statusCode: 413 });
	});
});
