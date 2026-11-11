import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { projectProxySecret, verifiedProjectRequest } from "../lib/projects/proxy";
import type { Project } from "../lib/projects/registry";

const published = JSON.parse(await readFile(new URL("../public/sdk/integrity.json", import.meta.url), "utf8")) as Record<string, string>;
const origin = "https://app.example";
const environment = { BETTER_AUTH_SECRET: "sdk-compatibility-test-only-platform-secret" };
const project: Project = {
	id: "00000000-0000-4000-8000-000000000043", name: "Compatibility fixture", slug: "compatibility-fixture",
	schemaName: "allauth_project_00000000000040008000000000000043", primaryOrigin: origin, origins: [origin],
	applicationId: "00000000-0000-4000-8000-000000000043", environment: "development", workspaceId: "fixture-workspace",
	brokerClientId: "fixture-broker", brokerSecret: "unused", proxyVersion: "fixture-version", createdBy: "fixture-owner", createdAt: new Date(0), updatedAt: new Date(0),
};
type ProxyFactory = (options: { project: string; proxySecret: string; appOrigin: string }) => (request: Request, context: { params: Promise<{ all: string[] }> }) => Promise<Response>;

for (const archiveName of Object.keys(published)) {
	test(`${archiveName} retains its signed session and sign-out request contract`, async (context) => {
		const folder = await mkdtemp(join(tmpdir(), "allauth-sdk-compatibility-"));
		try {
			const extracted = spawnSync("tar", ["-xzf", fileURLToPath(new URL(`../public/sdk/${archiveName}`, import.meta.url)), "-C", folder]);
			assert.equal(extracted.status, 0);
			await symlink(fileURLToPath(new URL("../node_modules", import.meta.url)), join(folder, "node_modules"), "dir");
			const sdk = await import(pathToFileURL(join(folder, "package/next.ts")).href) as { createAllAuthProxy: ProxyFactory };
			const received: string[] = [];
			context.mock.method(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
				const upstream = new Request(input, init);
				const verified = await verifiedProjectRequest(upstream, project, environment);
				received.push(new URL(verified.url).pathname);
				assert.equal(verified.headers.get("origin"), origin);
				assert.equal(verified.headers.get("cookie"), `__Secure-allauth_project_${project.slug}.session_token=legacy-cookie`);
				return Response.json(verified.method === "POST" ? { success: true } : { user: { id: "legacy-user" }, session: { id: "legacy-session" } });
			});
			const handler = sdk.createAllAuthProxy({ project: project.slug, proxySecret: projectProxySecret(project, environment), appOrigin: origin });
			const headers = { origin, cookie: `__Secure-allauth_project_${project.slug}.session_token=legacy-cookie` };
			const session = await handler(new Request(`${origin}/api/allauth/get-session`, { headers }), { params: Promise.resolve({ all: ["get-session"] }) });
			assert.equal(session.status, 200);
			const sessionBody = await session.json() as { session: { id: string } };
			assert.equal(sessionBody.session.id, "legacy-session");
			const permission = await handler(new Request(`${origin}/api/allauth/sign-out`, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: "{}" }), { params: Promise.resolve({ all: ["sign-out"] }) });
			assert.equal(permission.status, 200);
			const signedOut = await permission.json() as { success: boolean };
			assert.equal(signedOut.success, true);
			assert.deepEqual(received, [`/api/projects/${project.slug}/auth/get-session`, `/api/projects/${project.slug}/auth/sign-out`]);
		} finally { await rm(folder, { recursive: true, force: true }); }
	});
}
