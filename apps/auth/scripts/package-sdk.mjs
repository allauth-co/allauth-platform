import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sdk = new URL("../sdk/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("package.json", sdk), "utf8"));
const archiveName = `allauth-react-${manifest.version}.tgz`;
const archive = new URL(`../public/sdk/${archiveName}`, import.meta.url);
if (existsSync(archive)) throw new Error(`SDK ${manifest.version} already exists. Increment the version; published archives are immutable.`);
const integrityPath = new URL("../public/sdk/integrity.json", import.meta.url);
const integrity = JSON.parse(readFileSync(integrityPath, "utf8"));
for (const [name, expected] of Object.entries(integrity)) {
	const actual = createHash("sha256").update(readFileSync(new URL(`../public/sdk/${name}`, import.meta.url))).digest("hex");
	if (actual !== expected) throw new Error(`Previously published SDK archive changed: ${name}`);
}
const result = spawnSync("pnpm", ["--dir", fileURLToPath(sdk), "pack", "--pack-destination", "../public/sdk"], { stdio: "inherit" });
if (result.error || result.status !== 0) throw new Error("SDK packaging failed.");
integrity[archiveName] = createHash("sha256").update(readFileSync(archive)).digest("hex");
writeFileSync(integrityPath, `${JSON.stringify(integrity, null, 2)}\n`);
const verified = spawnSync(process.execPath, [fileURLToPath(new URL("verify-sdk-artifact.mjs", import.meta.url))], { stdio: "inherit" });
if (verified.error || verified.status !== 0) throw new Error("SDK archive verification failed.");
