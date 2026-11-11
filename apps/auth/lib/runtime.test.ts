import { Pool } from "pg";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { databasePoolSize, isNodeRuntime } from "./runtime";

const cloudflare = vi.hoisted(() => ({ getContext: vi.fn() }));
vi.mock("@opennextjs/cloudflare", () => ({ getCloudflareContext: cloudflare.getContext }));
// Runtime lifecycle tests do not use a database; policy storage is covered separately.
vi.mock("./auth-policy/storage", async () => {
	const { defaultStoredAuthPolicy } = await import("./auth-policy/policy");
	return { readAuthPolicy: vi.fn(async () => defaultStoredAuthPolicy()) };
});
const localEnv = {
	BETTER_AUTH_URL: "https://allauth.co",
	BETTER_AUTH_SECRET: "test-auth-secret-at-least-thirty-two-characters",
	SCIM_CREDENTIAL_HASH_SECRET: "test-directory-secret-at-least-thirty-two-characters",
	DATABASE_URL: "postgresql://test:test@127.0.0.1:1/test",
};

beforeEach(() => {
	vi.resetModules();
	for (const [name, value] of Object.entries(localEnv)) vi.stubEnv(name, value);
	vi.stubEnv("AUTH_RUNTIME", ""); vi.stubEnv("RAILWAY_SERVICE_ID", ""); vi.stubEnv("DATABASE_POOL_MAX", "");
	cloudflare.getContext.mockReset().mockImplementation(() => { throw new Error("No Worker context"); });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe("Node and Workers runtime boundaries", () => {
	it("requires explicit Node deployment identification", () => {
		expect(isNodeRuntime({ NEXT_RUNTIME: "nodejs" })).toBe(false);
		expect(isNodeRuntime({ AUTH_RUNTIME: "node" })).toBe(true);
		expect(isNodeRuntime({ RAILWAY_SERVICE_ID: "test-service" })).toBe(true);
	});
	it("validates the bounded pool size", () => {
		expect(databasePoolSize(undefined)).toBe(5);
		expect(databasePoolSize("1")).toBe(1);
		expect(databasePoolSize("20")).toBe(20);
		for (const value of ["0", "21", "5.5", "1e2", "05", "Infinity", "-1", 5]) expect(() => databasePoolSize(value)).toThrow("DATABASE_POOL_MAX");
	});
	it.each(["AUTH_RUNTIME", "RAILWAY_SERVICE_ID"])("bypasses Cloudflare bindings when %s identifies Node", async (name) => {
		vi.stubEnv(name, name === "AUTH_RUNTIME" ? "node" : "test-service");
		const { getAuthEnvironment } = await import("./auth");
		expect(await getAuthEnvironment()).toBe(process.env);
		expect(cloudflare.getContext).not.toHaveBeenCalled();
	});
	it("does not initialize a Wrangler proxy in ordinary Next Node execution", async () => {
		vi.stubEnv("NEXT_RUNTIME", "nodejs");
		const { getAuthEnvironment } = await import("./auth");
		expect(await getAuthEnvironment()).toBe(process.env);
		expect(cloudflare.getContext).toHaveBeenCalledWith();
	});
	it("shares the Node auth instance across operations and preserves nested context", async () => {
		vi.stubEnv("AUTH_RUNTIME", "node");
		const ended = vi.spyOn(Pool.prototype, "end");
		const { withAuth } = await import("./auth");
		const first = await withAuth(async (instance) => {
			await withAuth(async (nested, env) => { expect(nested).toBe(instance); expect(env).toBe(process.env); });
			return instance;
		});
		expect(await withAuth(async (instance) => instance)).toBe(first);
		expect(ended).not.toHaveBeenCalled();
		expect(cloudflare.getContext).not.toHaveBeenCalled();
	});
	it("never captures a Worker/test environment in the later Node singleton", async () => {
		const workerEnv = { ...localEnv, EMAIL: { send: vi.fn() } };
		cloudflare.getContext.mockReturnValue({ env: workerEnv });
		const ended = vi.spyOn(Pool.prototype, "end");
		const { withAuth } = await import("./auth");
		const worker = await withAuth(async (instance, env) => { expect(env).toBe(workerEnv); return instance; });
		expect(ended).toHaveBeenCalledTimes(1);
		vi.stubEnv("AUTH_RUNTIME", "node");
		const node = await withAuth(async (instance, env) => { expect(env).toBe(process.env); return instance; });
		expect(node).not.toBe(worker);
		expect(await withAuth(async (instance) => instance)).toBe(node);
		expect(ended).toHaveBeenCalledTimes(1);
	});
	it("keeps Workers instances request-scoped with nested reuse and closes on errors", async () => {
		cloudflare.getContext.mockReturnValue({ env: localEnv });
		const ended = vi.spyOn(Pool.prototype, "end");
		const { withAuth } = await import("./auth");
		const first = await withAuth(async (instance) => {
			await withAuth(async (nested) => { expect(nested).toBe(instance); });
			return instance;
		});
		expect(await withAuth(async (instance) => instance)).not.toBe(first);
		await expect(withAuth(async () => { throw new Error("Test operation failed"); })).rejects.toThrow("Test operation failed");
		expect(ended).toHaveBeenCalledTimes(3);
	});
	it("uses Railway edge IP only on Node and the native Cloudflare header on Workers", async () => {
		const { createAuthOptions } = await import("./auth");
		expect(createAuthOptions(undefined, { ...localEnv, AUTH_RUNTIME: "node" }).advanced.ipAddress.ipAddressHeaders).toEqual(["x-real-ip"]);
		expect(createAuthOptions(undefined, localEnv).advanced.ipAddress.ipAddressHeaders).toEqual(["cf-connecting-ip"]);
	});
});
