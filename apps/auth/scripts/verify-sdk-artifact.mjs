import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sdk = new URL("../sdk/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("package.json", sdk), "utf8"));
const served = JSON.parse(readFileSync(new URL("../lib/published-sdk.json", import.meta.url), "utf8"));
const servedOnly = process.argv.includes("--served");
const candidate = process.argv[2] === "--candidate" ? process.argv[3] : undefined;
if (process.argv[2] === "--candidate" && (!candidate || servedOnly)) {
	throw new Error("Pass a local archive path after --candidate.");
}
const version = servedOnly ? served.version : manifest.version;
const archive = candidate ?? fileURLToPath(new URL(`../public/sdk/allauth-react-${version}.tgz`, import.meta.url));
const integrity = JSON.parse(readFileSync(new URL("../public/sdk/integrity.json", import.meta.url), "utf8"));
if (!candidate && !Object.hasOwn(integrity, `allauth-react-${version}.tgz`)) throw new Error("Current SDK archive has no recorded integrity.");
for (const [name, expected] of Object.entries(integrity)) {
	const actual = createHash("sha256").update(readFileSync(new URL(`../public/sdk/${name}`, import.meta.url))).digest("hex");
	if (actual !== expected) throw new Error(`Previously published SDK archive changed: ${name}`);
}

function archivedFile(name) {
	const result = spawnSync("tar", ["-xOf", archive, `package/${name}`], { maxBuffer: 4 * 1024 * 1024 });
	if (result.error || result.status !== 0) throw new Error(`SDK ${version} archive is missing or unreadable: ${name}`);
	return result.stdout;
}

const packedManifest = JSON.parse(archivedFile("package.json").toString("utf8"));
if (servedOnly) {
	for (const key of ["version", "peerDependencies", "peerDependenciesMeta"]) {
		if (JSON.stringify(packedManifest[key]) !== JSON.stringify(served[key])) {
			throw new Error(`Served SDK installation metadata differs from its archive: ${key}`);
		}
	}
}
if (!servedOnly || version === manifest.version) {
	if (JSON.stringify(packedManifest) !== JSON.stringify(manifest)) throw new Error("SDK archive manifest differs from source. Publish a new immutable version.");
	for (const name of manifest.files) {
		if (!archivedFile(name).equals(readFileSync(new URL(name, sdk)))) throw new Error(`SDK archive differs from source: ${name}. Publish a new immutable version.`);
	}
	console.log(`SDK ${version}: archive matches all ${manifest.files.length} published source files.`);
} else {
	console.log(`SDK ${version}: served archive integrity and installation metadata verified.`);
}
