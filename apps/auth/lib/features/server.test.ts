import { describe, expect, it } from "vitest";
import { extraClientPlugins } from "./client";
import { extraServerPlugins } from "./server";

const env = {
	BETTER_AUTH_URL: "https://allauth.example",
	GOOGLE_CLIENT_ID: "google-public",
	GOOGLE_CLIENT_SECRET: "test-only-secret",
};

describe("compatible native plugin factories", () => {
	it("keeps the platform and project plugins separate without duplicate OAuth providers", () => {
		const platform = extraServerPlugins(env, {
			project: false,
			origin: "https://allauth.example",
		});
		const project = extraServerPlugins(env, {
			project: true,
			origin: "https://app.example",
		});
		expect(platform.map((plugin) => plugin.id)).toContain("one-tap");
		expect(platform.map((plugin) => plugin.id)).not.toContain("anonymous");
		expect(project.map((plugin) => plugin.id)).toContain("anonymous");
		expect(project.map((plugin) => plugin.id)).not.toContain("one-tap");
		expect(project.map((plugin) => plugin.id)).not.toContain("generic-oauth");
		expect(
			platform.filter((plugin) => plugin.id === "device-authorization"),
		).toHaveLength(1);
		for (const id of [
			"oauth-provider",
			"mcp",
			"oauth-popup",
			"oauth-proxy",
			"test-utils",
			"captcha",
			"phone-number",
		])
			expect(platform.map((plugin) => plugin.id)).not.toContain(id);
	});
	it("forces anonymous user writes to an unverified guest regardless of supplied role", async () => {
		const plugin = extraServerPlugins(env, {
			project: true,
			origin: "https://app.example",
		}).find((plugin) => plugin.id === "anonymous");
		expect(plugin?.id).toBe("anonymous");
		if (plugin?.id !== "anonymous") throw new Error("Anonymous plugin missing");
		const config = plugin.init();
		const before = config.options.databaseHooks.user.create.before;
		expect(
			await before({ isAnonymous: true, role: "admin", emailVerified: true }),
		).toEqual({
			data: { isAnonymous: true, role: "guest", emailVerified: false },
		});
		expect(await before({ isAnonymous: false, role: "user" })).toBeUndefined();
	});
	it("limits one-time tokens and disables public reference pages", () => {
		const plugins = extraServerPlugins(env, {
			project: false,
			origin: "https://allauth.example",
		});
		const oneTime = plugins.find((plugin) => plugin.id === "one-time-token");
		expect(
			oneTime && "options" in oneTime ? oneTime.options : undefined,
		).toMatchObject({
			expiresIn: 1,
			storeToken: "hashed",
			disableClientRequest: true,
			disableSetSessionCookie: true,
		});
		const schema = plugins.find((plugin) => plugin.id === "open-api");
		expect(
			schema && "options" in schema ? schema.options : undefined,
		).toMatchObject({ disableDefaultReference: true });
	});
	it("does not grant agent actions or permit autonomous/dynamic hosts", async () => {
		const plugin = extraServerPlugins(env, {
			project: false,
			origin: "https://allauth.example",
		}).find((item) => item.id === "agent-auth");
		if (!plugin || !("options" in plugin))
			throw new Error("Agent plugin missing");
		expect(plugin.options).toMatchObject({
			modes: ["delegated"],
			capabilities: [],
			defaultHostCapabilities: [],
			allowDynamicHostRegistration: false,
			dangerouslySkipJtiCheck: false,
			trustProxy: false,
		});
		if (plugin.id !== "agent-auth") throw new Error("Wrong plugin");
		expect(await plugin.options?.validateCapabilities?.([])).toBe(true);
		expect(await plugin.options?.validateCapabilities?.(["users:read"])).toBe(
			false,
		);
	});
	it("exposes native client methods without a browser bearer extension", () => {
		const clients = extraClientPlugins().map((plugin) => plugin.id);
		expect(clients).toContain("device-authorization");
		expect(clients).not.toContain("bearer");
		expect(
			extraClientPlugins({ googleClientId: "public", project: true }).map(
				(plugin) => plugin.id,
			),
		).not.toContain("one-tap");
	});
});
