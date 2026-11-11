import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { verifyPublicSdkReleases } from "./verify-public-sdk-releases.mjs";

const sha256 = "a".repeat(64);
const integrity = { "allauth-react-1.4.3.tgz": sha256 };
const archiveSizes = { "allauth-react-1.4.3.tgz": 123 };
const checksum = `${sha256}  allauth-react-1.4.3.tgz\n`;
const published = {
	tag_name: "v1.4.3", draft: false, prerelease: false, immutable: true,
	body: "Verified release notes.",
	html_url: "https://github.com/thegarty/allauth-sdk/releases/tag/v1.4.3",
	assets: [{ name: "allauth-react-1.4.3.tgz", digest: `sha256:${sha256}`, state: "uploaded", size: 123 }, { name: "allauth-react-1.4.3.tgz.sha256", digest: `sha256:${createHash("sha256").update(checksum).digest("hex")}`, state: "uploaded", size: checksum.length }],
};

test("release publication requires the immutable public tag and exact package digest", () => {
	assert.equal(verifyPublicSdkReleases(integrity, [published], archiveSizes), 1);
});

test("unpublished, draft, mutable, mismatched and incomplete releases block publication", () => {
	for (const releases of [[], [{ ...published, draft: true }], [{ ...published, immutable: false }], [{ ...published, assets: [{ name: "allauth-react-1.4.3.tgz", digest: `sha256:${"b".repeat(64)}` }] }], [{ ...published, assets: published.assets.slice(0, 1) }]]) {
		assert.throws(() => verifyPublicSdkReleases(integrity, releases, archiveSizes), /SDK publication/);
	}
});

test("a named checksum is insufficient when its contents, upload state or size differ", () => {
	for (const patch of [{ digest: `sha256:${"c".repeat(64)}` }, { state: "new" }, { size: checksum.length + 1 }]) {
		const release = { ...published, assets: [published.assets[0], { ...published.assets[1], ...patch }] };
		assert.throws(() => verifyPublicSdkReleases(integrity, [release], archiveSizes), /SDK publication/);
	}
});

test("previously public SDK versions cannot disappear from the service archive catalog", () => {
	assert.throws(() => verifyPublicSdkReleases({}, [published], {}), /SDK publication/);
	const previous = { ...published, tag_name: "v1.4.2", html_url: "https://github.com/thegarty/allauth-sdk/releases/tag/v1.4.2", assets: [{ name: "allauth-react-1.4.2.tgz", digest: `sha256:${"d".repeat(64)}` }] };
	assert.throws(() => verifyPublicSdkReleases(integrity, [previous, published], archiveSizes), /SDK publication/);
});
