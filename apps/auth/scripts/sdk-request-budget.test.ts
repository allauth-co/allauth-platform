import test from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

type SdkClient = {
  $store: { atoms: { $activeOrgSignal: { listen: (listener: () => void) => () => void } } };
  organization: {
    hasPermission: (input: { organizationId: string; permissions: Record<string, string[]> }) => Promise<{ data: { success: boolean }; error: unknown }>;
    update: (input: { organizationId: string; data: { name: string } }) => Promise<{ error: unknown }>;
  };
};

/** Exercise the installed package, so a dependency rollback fails the build. */
test("organisation permission reads do not reload active organisation data, while saves still refresh it", async (context) => {
  const sdkEntry = process.env.ALLAUTH_SDK_ENTRY ?? fileURLToPath(new URL("../sdk/react.tsx", import.meta.url));
  const sdk = await import(pathToFileURL(join(dirname(sdkEntry), "client.ts")).href) as {
    createAllAuthClient: (basePath: string, onTwoFactorRedirect: () => void) => SdkClient;
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
  let reloads = 0;
  const unsubscribe = client.$store.atoms.$activeOrgSignal.listen(() => { reloads += 1; });
  try {
    const results = await Promise.all(Array.from({ length: 14 }, () => client.organization.hasPermission({ organizationId: "org-test", permissions: { organization: ["update"] } })));
    assert.ok(results.every((result) => result.data.success === true));
    await delay(30);
    assert.equal(requests.length, 14);
    assert.equal(reloads, 0, "read-only permission checks must not fan out into active-organisation reloads");
    const saved = await client.organization.update({ organizationId: "org-test", data: { name: "Updated organisation" } });
    assert.equal(saved.error, null);
    await delay(30);
    assert.equal(reloads, 1, "an organisation save must still refresh subscribed organisation data");
  } finally {
    unsubscribe();
  }
});
