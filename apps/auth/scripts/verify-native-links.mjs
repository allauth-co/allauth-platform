import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A matching version can still be a second registry copy. Check the real
// source roots so plugin contexts and deployment code stay authoritative.
const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(appRoot, "package.json"), "utf8"));
const links = Object.entries(manifest.dependencies).filter(([name, specifier]) => (name === "better-auth" || name.startsWith("@better-auth/")) && specifier.startsWith("link:../../packages/"));
assert.equal(links.length, 12, "The auth app must declare all 12 native source links.");
const expected = new Map(links.map(([name, specifier]) => [name, realpathSync(resolve(appRoot, specifier.slice(5)))]));
for (const [name, source] of expected) {
	assert.equal(realpathSync(join(appRoot, "node_modules", name)), source, `${name} must resolve to the official repository source.`);
}
let peers = 0;
for (const name of ["@better-auth-ui/core", "@better-auth-ui/react", "@better-auth/agent-auth"]) {
	const packageRoot = realpathSync(join(appRoot, "node_modules", name));
	const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
	const fromPackage = createRequire(join(packageRoot, "package.json"));
	for (const dependency of Object.keys(pkg.peerDependencies || {})) {
		const source = expected.get(dependency);
		if (!source) continue;
		const resolved = realpathSync(fromPackage.resolve(dependency));
		const within = relative(source, resolved);
		assert.ok(within && !within.startsWith("..") && !within.startsWith("/"), `${name}'s ${dependency} peer must use the same official source context.`);
		peers++;
	}
}
console.log(`Verified ${links.length} official native source links and ${peers} shared UI/agent peer resolutions.`);
