import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { publicCredentialFindings, publicServiceGuideSource, publicSourceExclusion, publicSourceText, publicWorkerConfiguration } from "./public-source-policy.mjs";

test("excludes operational records and credentials while keeping product code, tests and public docs", () => {
	for (const name of ["CLOUDFLARE_SETUP.md", "design-qa.md", "apps/auth/design-qa.md", "apps/auth/SESSION_INTROSPECTION_VALIDATION.md", "apps/auth/docs/clerk-reference-review.md", "apps/auth/releases/receipt.md", "apps/auth/.dev.vars", "apps/auth/.env.production"]) assert.ok(publicSourceExclusion(name), name);
	for (const name of ["apps/auth/lib/auth.ts", "apps/auth/lib/projects/runtime.test.ts", "apps/auth/lib/projects/registry-audit.pg.test.ts", "apps/auth/INTEGRATION.md", "docs/SELF_HOSTING.md", "apps/auth/.env.example", "deploy/self-host/.env.example"]) assert.equal(publicSourceExclusion(name), undefined, name);
});

test("keeps the public service README when replaying an already-public source export", () => {
	const publicGuide = "# AllAuth platform service\n\nPublic overview.";
	assert.equal(publicServiceGuideSource(["apps/auth/README.md", "apps/auth/README.public.md"], publicGuide), "apps/auth/README.public.md");
	assert.equal(publicServiceGuideSource(["apps/auth/README.md"], publicGuide), "apps/auth/README.md");
	assert.throws(() => publicServiceGuideSource(["apps/auth/README.md"], "# AllAuth production service\nPrivate operations."), /verified public service guide/);
	assert.throws(() => publicServiceGuideSource([], ""), /verified public service guide/);
});

test("retains the integration contract while replacing operational sections and dangling evidence links", async () => {
	const original = await readFile(new URL("../INTEGRATION.md", import.meta.url), "utf8");
	const transformed = publicSourceText("apps/auth/INTEGRATION.md", original);
	assert.ok(transformed.includes("## Clerk migration sequence"));
	assert.ok(transformed.includes("## Identity, organizations and impersonation"));
	assert.ok(transformed.includes("../../docs/SELF_HOSTING.md"));
	assert.ok(!transformed.includes("The AllAuth Railway project is"));
	assert.ok(!/surveypeach/i.test(transformed));
	assert.ok(!transformed.includes("./docs/clerk-reference-review.md"));
	assert.equal(publicSourceText("README.md", "[Overview](apps/auth/README.public.md)"), "[Overview](apps/auth/README.md)");
});

test("retains owned-photo contracts without publishing live deployment records or exact operator targets", async () => {
	const name = "docs/content/docs/integrations/allauth-owned-profile-photos.mdx";
	const source = await readFile(new URL(`../../../${name}`, import.meta.url), "utf8");
	const transformed = publicSourceText(name, source);
	assert.ok(transformed.includes("## Contract and boundaries"));
	assert.ok(transformed.includes("## Durable drafts and deletion"));
	assert.ok(transformed.includes("## Configure your own environment"));
	assert.ok(!transformed.includes("## Operator targets"));
	assert.ok(!transformed.includes("## Recorded deployment checkpoint"));
	assert.ok(!/\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/i.test(transformed));
});

test("generalizes tenant fixture labels and identifiers consistently without rewriting ordinary product code", () => {
	const fixture = 'const project = { id: "11111111-1111-4111-8111-111111111111", slug: "crowdtree-production", rpId: "crowdtr.ee", teamId: "JWJ4JYF8E6" }; expect(id).toBe("11111111-1111-4111-8111-111111111111");';
	const transformed = publicSourceText("apps/auth/lib/example.test.ts", fixture);
	assert.ok(transformed.includes("nativeapp-production")); assert.ok(transformed.includes("nativeapp.example")); assert.ok(transformed.includes("TESTTEAM01"));
	const ids = transformed.match(/\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g);
	assert.equal(ids.length, 2); assert.equal(ids[0], ids[1]); assert.notEqual(ids[0], "11111111-1111-4111-8111-111111111111");
	assert.equal(publicSourceText("apps/auth/lib/example.ts", fixture), fixture);
});

test("generic Worker configs have no account/routes/live origin and leave private storage unverified", async () => {
	for (const name of ["wrangler.jsonc", "wrangler.assets.jsonc", "wrangler.domains.jsonc"]) {
		const source = await readFile(new URL(`../${name}`, import.meta.url));
		const transformed = JSON.parse(new TextDecoder().decode(publicWorkerConfiguration(`apps/auth/${name}`, source)));
		assert.equal(transformed.account_id, undefined); assert.equal(transformed.routes, undefined);
		if (name === "wrangler.domains.jsonc") assert.equal(transformed.vars.ALLAUTH_ORIGIN, "https://your-service.up.railway.app");
		if (name === "wrangler.assets.jsonc") assert.equal(transformed.vars.OWNED_AVATAR_PRIVATE_STORAGE, "false");
		const again = JSON.parse(new TextDecoder().decode(publicWorkerConfiguration(`apps/auth/${name}`, new TextEncoder().encode(JSON.stringify(transformed)))));
		assert.deepEqual(again, transformed);
	}
});

test("credential findings contain metadata only", () => {
	const token = "rk_" + "test_" + "a".repeat(32);
	const findings = publicCredentialFindings("fixture.txt", `first line\n${token}`);
	assert.deepEqual(findings, [{ path: "fixture.txt", line: 2, kind: "Stripe secret" }]);
	assert.ok(!JSON.stringify(findings).includes(token));
});

test("retains exact public upstream crypto fixtures but detects changed key material", async () => {
	const source = "test/fixtures/key.pem";
	assert.equal(publicSourceExclusion(source), undefined);
	const original = await readFile(new URL(`../../../${source}`, import.meta.url), "utf8");
	assert.deepEqual(publicCredentialFindings(source, original), []);
	assert.equal(publicCredentialFindings(source, original + "\n")[0].kind, "Private key");
	assert.deepEqual(publicCredentialFindings("validation.ts", 'value.startsWith("-----BEGIN PRIVATE KEY-----")'), []);
});
