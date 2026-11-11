import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const repository = "https://github.com/thegarty/allauth-sdk";

/** Check public release metadata before publishing the service's matching release catalog. */
export function verifyPublicSdkReleases(integrity, releases, archiveSizes) {
	if (!Array.isArray(releases)) throw new Error("SDK publication: invalid GitHub release response.");
	if (!Object.keys(integrity).length) throw new Error("SDK publication: the retained archive catalog cannot be empty.");
	for (const release of releases) {
		if (release.draft || !/^v\d+\.\d+\.\d+$/.test(release.tag_name)) continue;
		const filename = `allauth-react-${release.tag_name.slice(1)}.tgz`;
		const archive = Array.isArray(release.assets) ? release.assets.find((asset) => asset.name === filename) : undefined;
		if (!integrity[filename] || archive?.digest !== `sha256:${integrity[filename]}`) throw new Error(`SDK publication: retain the already-public ${filename} and its original checksum.`);
	}
	for (const [filename, sha256] of Object.entries(integrity)) {
		const version = /^allauth-react-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.tgz$/.exec(filename)?.[1];
		const tag = `v${version}`;
		const release = releases.find((item) => item.tag_name === tag);
		if (!version || !release || release.draft || release.prerelease || release.immutable !== true || release.html_url !== `${repository}/releases/tag/${tag}` || typeof release.body !== "string" || !release.body.trim()) {
			throw new Error(`SDK publication: ${tag} needs public notes and an immutable published release.`);
		}
		const assets = Array.isArray(release.assets) ? release.assets : [];
		const archives = assets.filter((asset) => asset.name === filename);
		const checksums = assets.filter((asset) => asset.name === `${filename}.sha256`);
		const checksum = `${sha256}  ${filename}\n`;
		const checksumDigest = createHash("sha256").update(checksum).digest("hex");
		const archiveSize = archiveSizes?.[filename];
		if (!Number.isSafeInteger(archiveSize) || archiveSize <= 0 || archives.length !== 1 || archives[0].state !== "uploaded" || archives[0].size !== archiveSize || archives[0].digest !== `sha256:${sha256}` || checksums.length !== 1 || checksums[0].state !== "uploaded" || checksums[0].size !== checksum.length || checksums[0].digest !== `sha256:${checksumDigest}`) {
			throw new Error(`SDK publication: ${tag} needs its exact archive digest and checksum asset.`);
		}
	}
	return Object.keys(integrity).length;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const integrity = JSON.parse(await readFile(new URL("../public/sdk/integrity.json", import.meta.url), "utf8"));
	const archiveSizes = {};
	for (const [filename, sha256] of Object.entries(integrity)) {
		if (!/^allauth-react-\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.tgz$/.test(filename)) throw new Error("SDK publication: invalid archive filename.");
		const archive = await readFile(new URL(`../public/sdk/${filename}`, import.meta.url));
		if (createHash("sha256").update(archive).digest("hex") !== sha256) throw new Error(`SDK publication: local ${filename} differs from its immutable checksum.`);
		archiveSizes[filename] = archive.length;
	}
	const releases = [];
	for (let page = 1; page <= 100; page++) {
		const response = await fetch(`https://api.github.com/repos/thegarty/allauth-sdk/releases?per_page=100&page=${page}`, {
			headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "AllAuth-release-verification" },
			signal: AbortSignal.timeout(30_000),
		});
		if (!response.ok) throw new Error(`SDK publication: GitHub verification returned HTTP ${response.status}. Retry before publishing.`);
		const batch = await response.json();
		if (!Array.isArray(batch)) throw new Error("SDK publication: invalid GitHub release response.");
		releases.push(...batch);
		if (batch.length < 100) break;
	}
	console.log(`Verified ${verifyPublicSdkReleases(integrity, releases, archiveSizes)} immutable public SDK releases.`);
}
