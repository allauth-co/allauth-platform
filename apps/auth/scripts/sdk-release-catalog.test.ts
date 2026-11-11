import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { sdkReleases } from "../lib/notifications/releases";
import sdkPackage from "../sdk/package.json";

test("the default SDK release has immutable download metadata and customer-facing upgrade notes", async () => {
	const release = sdkReleases.find((candidate) => candidate.version === sdkPackage.version);
	assert.ok(release, "every new default SDK version needs a release notification");
	assert.equal(sdkReleases[0]?.version, sdkPackage.version);
	const archive = await readFile(new URL(`../public/sdk/allauth-react-${sdkPackage.version}.tgz`, import.meta.url));
	assert.equal(release.sha256, createHash("sha256").update(archive).digest("hex"));
	assert.equal(release.compatibility, "backward-compatible");
	assert.equal(release.announce, true, "the default SDK requires a customer announcement");
	assert.ok(release.publishedAt && Number.isFinite(Date.parse(release.publishedAt)));
	assert.equal(release.downloadUrl, `https://allauth.co/sdk/allauth-react-${sdkPackage.version}.tgz`);
	assert.ok(release.summary.trim().length > 20);
	for (const link of [release.upgradeUrl, release.changelogUrl]) assert.equal(new URL(link).origin, "https://allauth.co");
	assert.equal(new Set(sdkReleases.map((candidate) => candidate.id)).size, sdkReleases.length);
	assert.equal(new Set(sdkReleases.map((candidate) => candidate.version)).size, sdkReleases.length);
});

test("every immutable public SDK has versioned source, checksum and factual public release notes", async () => {
	const integrity = JSON.parse(await readFile(new URL("../public/sdk/integrity.json", import.meta.url), "utf8")) as Record<string, string>;
	assert.equal(sdkReleases.length, Object.keys(integrity).length);
	for (const [archiveName, sha256] of Object.entries(integrity)) {
		const version = archiveName.replace(/^allauth-react-/, "").replace(/\.tgz$/, "");
		const release = sdkReleases.find((candidate) => candidate.version === version);
		assert.ok(release, `Missing public release notes for ${version}`);
		assert.equal(release.sha256, sha256);
		assert.equal(release.downloadUrl, `https://allauth.co/sdk/${archiveName}`);
		assert.equal(release.sourceUrl, `https://github.com/thegarty/allauth-sdk/tree/v${version}/packages/react`);
		assert.ok(release.notes.length > 0);
		assert.equal(new URL(release.changelogUrl).pathname, `/releases/${release.slug}`);
		if (release.dateConfidence === "unknown") assert.equal(release.publishedAt, null);
		if (version !== sdkPackage.version) assert.equal(release.announce, false, "backfilling history must not notify customers");
	}
});
