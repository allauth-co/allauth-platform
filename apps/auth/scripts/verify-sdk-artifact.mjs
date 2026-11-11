import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sdk = new URL("../sdk/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("package.json", sdk), "utf8"));
const archive = fileURLToPath(new URL(`../public/sdk/allauth-react-${manifest.version}.tgz`, import.meta.url));
const integrity = JSON.parse(readFileSync(new URL("../public/sdk/integrity.json", import.meta.url), "utf8"));
if (!Object.hasOwn(integrity, `allauth-react-${manifest.version}.tgz`)) throw new Error("Current SDK archive has no recorded integrity.");
for (const [name, expected] of Object.entries(integrity)) {
	const actual = createHash("sha256").update(readFileSync(new URL(`../public/sdk/${name}`, import.meta.url))).digest("hex");
	if (actual !== expected) throw new Error(`Previously published SDK archive changed: ${name}`);
}

function archivedFile(name) {
	const result = spawnSync("tar", ["-xOf", archive, `package/${name}`], { maxBuffer: 4 * 1024 * 1024 });
	if (result.error || result.status !== 0) throw new Error(`SDK ${manifest.version} archive is missing or unreadable: ${name}`);
	return result.stdout;
}

const packedManifest = JSON.parse(archivedFile("package.json").toString("utf8"));
if (JSON.stringify(packedManifest) !== JSON.stringify(manifest)) throw new Error("SDK archive manifest differs from source. Publish a new immutable version.");
for (const name of manifest.files) {
	if (!archivedFile(name).equals(readFileSync(new URL(name, sdk)))) throw new Error(`SDK archive differs from source: ${name}. Publish a new immutable version.`);
}
console.log(`SDK ${manifest.version}: archive matches all ${manifest.files.length} published source files.`);
