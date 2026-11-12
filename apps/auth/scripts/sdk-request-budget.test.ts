import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setImmediate } from "node:timers/promises";
import type { AllAuthClient } from "../sdk/client";

/** Observe the client's real subscription and requests with no DOM or external service. */
test("organisation permission reads do not reload the active organisation, while saves still refresh it", async (context) => {
	const sdkEntry = process.env.ALLAUTH_SDK_ENTRY ?? fileURLToPath(new URL("../sdk/react.tsx", import.meta.url));
	const clientEntry = pathToFileURL(join(dirname(sdkEntry), "client.ts"));
	const cleanup: (() => void)[] = [];
	context.after(() => cleanup.forEach(unsubscribe => unsubscribe()));
	context.mock.module(createRequire(clientEntry).resolve("react"), {
		namedExports: {
			useSyncExternalStore<T>(subscribe: (listener: () => void) => () => void, snapshot: () => T): T {
				cleanup.push(subscribe(() => {}));
				return snapshot();
			},
		},
	});
	const sdk = await import(clientEntry.href) as {
		createAllAuthClient: (basePath: string, onTwoFactorRedirect: () => void) => AllAuthClient;
	};
	const requests: string[] = [];
	context.mock.method(globalThis, "fetch", async (input: RequestInfo | URL) => {
		const url = new URL(input instanceof Request ? input.url : String(input));
		assert.equal(url.origin, "http://localhost");
		assert.ok(url.pathname.startsWith("/api/allauth/organization/"));
		requests.push(url.pathname);
		return Response.json(url.pathname.endsWith("/has-permission") ? { success: true } : { id: "org-test", name: "Updated organisation" });
	});
	const client = sdk.createAllAuthClient("/api/allauth", () => {});
	const initial = client.useActiveOrganization();
	await initial.refetch();
	const activeOrg = "/api/allauth/organization/get-full-organization";
	assert.deepEqual(requests, [activeOrg]);
	const results = await Promise.all(Array.from({ length: 14 }, () => client.organization.hasPermission({ organizationId: "org-test", permissions: { organization: ["update"] } })));
	assert.ok(results.every((result) => result.data?.success === true));
	await setImmediate();
	assert.equal(requests.filter(path => path === activeOrg).length, 1, "permission reads must not reload the active organisation");
	assert.equal(requests.length, 15);
	const saved = await client.organization.update({ organizationId: "org-test", data: { name: "Updated organisation" } });
	assert.equal(saved.error, null);
	await setImmediate();
	assert.equal(requests.filter(path => path === activeOrg).length, 2, "an organisation save must refresh subscribed organisation data");
});
