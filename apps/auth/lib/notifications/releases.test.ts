import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import integrity from "../../public/sdk/integrity.json";
import {
	activeReleaseAnnouncements,
	activeSdkAnnouncements,
	normalizedSdkVersion,
	platformReleases,
	sdkReleases,
	sdkUpdateAvailable,
} from "./releases";

describe("SDK release observations", () => {
	it("accepts bounded package versions but ignores missing or malformed advisory headers", () => {
		expect(normalizedSdkVersion("1.4.3")).toBe("1.4.3");
		expect(normalizedSdkVersion("1.2.2-orgfix.1")).toBe("1.2.2-orgfix.1");
		for (const value of [
			undefined,
			"",
			"latest",
			"1.2",
			"1.4.3\nforged",
			"1.4.3\n",
			"1.2.3-" + "a".repeat(100),
		])
			expect(normalizedSdkVersion(value)).toBeNull();
	});
	it("keeps unknown versions unknown and never asks newer clients to downgrade", () => {
		expect(sdkUpdateAvailable(null, "1.4.3")).toBeNull();
		expect(sdkUpdateAvailable("1.2.2", "1.4.3")).toBe(true);
		expect(sdkUpdateAvailable("1.4.3", "1.4.3")).toBe(false);
		expect(sdkUpdateAvailable("1.5.0", "1.4.3")).toBe(false);
		expect(sdkUpdateAvailable("1.4.3-beta.1", "1.4.3")).toBe(true);
	});
});

describe("verified public release history", () => {
	it("covers every allowlisted immutable SDK archive with grounded notes and its real checksum", () => {
		expect(
			sdkReleases
				.map((release) => `allauth-react-${release.version}.tgz`)
				.sort(),
		).toEqual(Object.keys(integrity).sort());
		expect(sdkReleases.some((release) => release.version === "1.0.0")).toBe(
			true,
		);
		for (const release of sdkReleases) {
			const filename =
				`allauth-react-${release.version}.tgz` as keyof typeof integrity;
			const archive = readFileSync(
				new URL(`../../public/sdk/${filename}`, import.meta.url),
			);
			expect(createHash("sha256").update(archive).digest("hex")).toBe(
				integrity[filename],
			);
			expect(release.sha256).toBe(integrity[filename]);
			expect(release.notes.length).toBeGreaterThanOrEqual(2);
			expect(release.summary.length).toBeGreaterThan(20);
			expect(release.provenance.length).toBeGreaterThan(0);
			expect(release.slug).toBe(`sdk-${release.version.replaceAll(".", "-")}`);
			if (release.publishedAt === null)
				expect(release.dateConfidence).toBe("unknown");
		}
	});
	it("keeps release identifiers unique across SDK and platform read-state and email records", () => {
		const releases = [...sdkReleases, ...platformReleases];
		expect(new Set(releases.map((release) => release.id)).size).toBe(
			releases.length,
		);
		expect(new Set(releases.map((release) => release.slug)).size).toBe(
			releases.length,
		);
	});
	it("waits until an explicitly announced platform publication time and preserves historical suppression", () => {
		const original = { ...platformReleases[0] },
			now = new Date();
		try {
			Object.assign(platformReleases[0], {
				announce: true,
				publishedAt: new Date(now.getTime() + 60_000).toISOString(),
			});
			expect(
				activeReleaseAnnouncements(now).some(
					(release) => release.id === original.id,
				),
			).toBe(false);
			expect(
				activeReleaseAnnouncements(new Date(now.getTime() + 120_000)).some(
					(release) => release.id === original.id,
				),
			).toBe(true);
			Object.assign(platformReleases[0], { announce: false });
			expect(
				activeReleaseAnnouncements(new Date(now.getTime() + 120_000)).some(
					(release) => release.id === original.id,
				),
			).toBe(false);
		} finally {
			Object.assign(platformReleases[0], original);
		}
	});
	it("keeps retained releases and historical backfills out of dashboard unread counts and release email announcements", () => {
		const announcements = activeReleaseAnnouncements();
		expect(activeSdkAnnouncements().map((release) => release.version)).toEqual([
			sdkReleases[0].version,
		]);
		expect(
			announcements.filter((release) => release.kind === "sdk").map((release) => release.id),
		).toEqual([sdkReleases[0].id]);
		expect(sdkReleases.slice(1).every((release) => !release.announce)).toBe(true);
		expect(
			sdkReleases.find((release) => release.version === "1.4.6"),
		).toMatchObject({
			announce: false,
			compatibility: "backward-compatible",
			dateConfidence: "known",
			publishedAt: "2026-11-06T21:30:55Z",
		});
		const historical = platformReleases.find(
			(release) => release.id === "platform-release-notifications-2026-10-30",
		);
		expect(historical).toMatchObject({
			announce: false,
			dateConfidence: "known",
			compatibility: "platform-update",
			sourceUrl: null,
		});
		expect(
			announcements
				.filter((release) => release.kind === "platform")
				.map((release) => release.id),
		).toEqual([
			"platform-in-app-mfa-2026-11-07",
			"platform-support-cleanup-2026-11-06",
			"platform-support-introspection-2026-11-06",
			"platform-application-backends-2026-11-06",
		]);
	});
});
