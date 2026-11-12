import { render } from "@react-email/components";
import { createElement } from "react";
import { describe, expect, it } from "vitest";
import type { AnnouncedPlatformRelease } from "./catalog-types";
import { ReleaseNotificationEmail } from "./email";
import { platformReleases, sdkReleases } from "./releases";

describe("customer SDK release emails", () => {
	it("renders platform branding, compatibility guidance, release notes and preference recovery in HTML and text", async () => {
		const element = createElement(ReleaseNotificationEmail, {
			release: { ...sdkReleases[0], compatibility: "backward-compatible" },
			notificationsUrl: "https://allauth.co/admin/notifications",
		});
		const [html, text] = await Promise.all([
			render(element),
			render(element, { plainText: true }),
		]);
		for (const body of [html, text]) {
			expect(body).toContain("AllAuth");
			expect(body).toContain("backward-compatible");
			expect(body).toContain(sdkReleases[0].changelogUrl);
			expect(body).toContain("https://allauth.co/admin/notifications");
			expect(body).toContain("keeps working");
			expect(body).toContain("does not change");
		}
	});
	it("labels major SDK upgrades and gives customers control of the migration", async () => {
		const html = await render(createElement(ReleaseNotificationEmail, {
			release: { ...sdkReleases[0], version: "2.0.0", compatibility: "migration-required" },
			notificationsUrl: "https://allauth.co/admin/notifications",
		}));
		expect(html).toContain("major SDK upgrade requires application changes");
		expect(html).toContain("Your installed version keeps working");
		expect(html).not.toContain("backward-compatible SDK update");
	});
	it("renders an announced platform update without SDK installation claims", async () => {
		const release: AnnouncedPlatformRelease = {
			...platformReleases[0],
			announce: true,
			changelogUrl: "https://allauth.co/releases/platform-fixture-update",
		};
		const element = createElement(ReleaseNotificationEmail, {
			release,
			notificationsUrl: "https://allauth.co/admin/notifications",
		});
		const [html, text] = await Promise.all([
			render(element),
			render(element, { plainText: true }),
		]);
		for (const body of [html, text]) {
			expect(body).toContain("platform update");
			expect(body).toContain(release.changelogUrl);
			expect(body).toContain("https://allauth.co/admin/notifications");
			expect(body).not.toContain("update your pinned package");
			expect(body).not.toContain("backward-compatible SDK update");
		}
	});
	it("publishes an immutable download checksum for each compatible catalog release", () => {
		for (const release of sdkReleases.filter(
			(candidate) => candidate.announce,
		)) {
			expect(release.sha256).toMatch(/^[a-f0-9]{64}$/);
			expect(release.downloadUrl).toBe(
				`https://allauth.co/sdk/allauth-react-${release.version}.tgz`,
			);
			expect(["backward-compatible", "migration-required"]).toContain(release.compatibility);
		}
	});
});
