import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { publicCredentialFindings, publicSourceExclusion, publicSourceText, publicWorkerConfiguration } from "./public-source-policy.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const outputArgument = process.argv.indexOf("--output");
const destination = outputArgument >= 0 ? path.resolve(process.argv[outputArgument + 1] || "") : undefined;
if (destination && !destination.startsWith(path.join(root, "output") + path.sep)) throw new Error("Source exports must use a new directory under repository-root output/.");
const names = [...new Set(execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: root, maxBuffer: 32 * 1024 * 1024 }).toString().split("\0").filter(Boolean))].sort();
const files = []; const excluded = []; const findings = []; const prepared = []; const transformed = [];
for (const source of names) {
	const reason = publicSourceExclusion(source);
	if (reason) { excluded.push({ path: source, reason }); continue; }
	const file = path.join(root, source);
	const metadata = await lstat(file);
	if (!metadata.isFile()) { excluded.push({ path: source, reason: "non-regular file requires manual review" }); continue; }
	const original = await readFile(file);
	let content = publicWorkerConfiguration(source, original);
	if (/\.(?:mdx?|(?:test|spec)\.[cm]?[jt]sx?)$/.test(source)) content = new TextEncoder().encode(publicSourceText(source, new TextDecoder().decode(content)));
	findings.push(...publicCredentialFindings(source, new TextDecoder().decode(content)));
	if (!original.equals(content)) transformed.push(source);
	const target = source === "apps/auth/README.public.md" ? "apps/auth/README.md" : source;
	const checksum = createHash("sha256").update(content).digest("hex");
	files.push({ path: target, sha256: checksum, bytes: content.length, mode: metadata.mode & 0o777 });
	prepared.push({ target, content, mode: metadata.mode & 0o777 });
}
const report = { generatedAt: new Date().toISOString(), sourceRepository: "thegarty/allauth", intendedPublicRepository: "thegarty/allauth-platform", files, excluded, transformed, credentialFindings: findings, note: "Clean source snapshot only; no Git history, credentials or operational receipts. Generic Worker configs, public documentation and consistent synthetic tenant fixtures replace private deployment references. Known upstream cryptographic test fixtures are retained by checksum. Pattern scanning complements manual review and is not a security certification." };
const reportDirectory = path.join(root, "output"); await mkdir(reportDirectory, { recursive: true });
const reportPath = path.join(reportDirectory, "public-source-audit.json");
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
if (findings.length) {
	process.exitCode = 1;
} else if (destination) {
	// Complete the preflight before writing any publishable source bytes.
	await mkdir(destination, { recursive: true });
	if ((await readdir(destination)).length) throw new Error("Refusing to overwrite a nonempty source export directory.");
	for (const { target, content, mode } of prepared) {
		const output = path.join(destination, target);
		await mkdir(path.dirname(output), { recursive: true });
		await writeFile(output, content, { mode });
	}
}
console.log(JSON.stringify({ files: files.length, bytes: files.reduce((total, file) => total + file.bytes, 0), excluded: excluded.length, credentialFindings: findings, destination: destination || null, reportPath }, null, 2));
