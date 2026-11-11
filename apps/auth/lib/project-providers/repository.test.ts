import { describe, expect, it, vi } from "vitest";
import type { Pool } from "pg";
import { decryptGoogleSecret, googleProviderRepository } from "./repository";

const env = { BETTER_AUTH_SECRET: "fixture-provider-encryption-secret-with-32-characters" };
const project = { id: "fixture-development", schemaName: "allauth_project_0123456789abcdef0123456789abcdef" };
function poolWith(rows: unknown[][]) {
	const queue = [...rows];
	const query = vi.fn(async (_statement: string, _values?: unknown[]) => ({ rows: queue.shift() ?? [] }));
	return { query, pool: { query } as unknown as Pick<Pool, "query"> };
}

describe("encrypted versioned environment provider repository", () => {
	it("preserves stored ID/secret when disabling direct login or saving a blank secret", async () => {
		const before = { version: 2, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "existing-encrypted", updatedAt: new Date() };
		const state = poolWith([[before], [{ ...before, version: 3, enabled: false }]]);
		await googleProviderRepository(state.pool, env).update(project, { version: 2, google: { enabled: false, clientId: "", clientSecret: "" } }, "actor");
		expect(state.query.mock.calls[1]?.[1]).toEqual([project.id, false, before.clientId, before.encryptedClientSecret, "actor", 2, expect.any(String)]);
		expect(state.query.mock.calls[1]?.[0]).toContain('AND version=$6');
		expect(state.query.mock.calls[1]?.[0]).toContain('"allauthEvent"');
	});
	it("encrypts a new secret before the atomic scoped write and never includes it in SQL or audit metadata", async () => {
		const row = { version: 1, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "fixture-returned-encrypted", updatedAt: new Date() };
		const state = poolWith([[], [row]]);
		const secret = "fixture-new-google-secret";
		await googleProviderRepository(state.pool, env).update(project, { version: 0, google: { enabled: true, clientId: row.clientId, clientSecret: secret } }, "actor");
		const [statement, values] = state.query.mock.calls[1]!;
		expect(statement).not.toContain(secret);
		expect(JSON.stringify(values)).not.toContain(secret);
		expect(await decryptGoogleSecret(String(values?.[3]), project.id, env)).toBe(secret);
		expect(statement).toContain('ON CONFLICT ("projectId") DO NOTHING');
	});
	it("rejects stale settings before writes and concurrent stale writes after the compare-and-swap", async () => {
		const before = { version: 2, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "fixture-encrypted", updatedAt: new Date() };
		const stale = poolWith([[before]]);
		await expect(googleProviderRepository(stale.pool, env).update(project, { version: 1, google: { enabled: false, clientId: "" } }, "actor")).rejects.toMatchObject({ statusCode: 409 });
		expect(stale.query).toHaveBeenCalledTimes(1);
		const race = poolWith([[before], []]);
		await expect(googleProviderRepository(race.pool, env).update(project, { version: 2, google: { enabled: false, clientId: "" } }, "actor")).rejects.toMatchObject({ statusCode: 409 });
	});
	it("requires complete direct credentials and keeps environments isolated by their exact ID", async () => {
		const state = poolWith([[], []]);
		const repository = googleProviderRepository(state.pool, env);
		await expect(repository.update(project, { version: 0, google: { enabled: true, clientId: "tenant.apps.googleusercontent.com" } }, "actor")).rejects.toMatchObject({ statusCode: 400 });
		await repository.read("another-production");
		expect(state.query.mock.calls.map((call) => call[1])).toEqual([[project.id], ["another-production"]]);
	});
});
