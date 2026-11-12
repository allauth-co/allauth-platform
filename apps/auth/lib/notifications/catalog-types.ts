/** Public provenance distinguishes reconstructed archive notes from a dated announcement. */
export interface ReleaseProvenance {
	kind: "archive" | "archive-diff" | "release" | "deployment";
	details: string;
	files: string[];
}
interface SdkReleaseBase {
	kind: "sdk";
	id: string;
	slug: string;
	version: string;
	title: string;
	summary: string;
	notes: string[];
	upgradeUrl: string;
	changelogUrl: string;
	downloadUrl: string;
	sha256: string;
	sourceUrl: string;
	provenance: ReleaseProvenance[];
}
export interface AnnouncedSdkRelease extends SdkReleaseBase {
	announce: true;
	publishedAt: string;
	dateConfidence: "known";
	compatibility: "backward-compatible";
}
export interface RetainedSdkRelease extends Omit<AnnouncedSdkRelease, "announce"> {
	announce: false;
}
export interface HistoricalSdkRelease extends SdkReleaseBase {
	announce: false;
	publishedAt: string | null;
	dateConfidence: "known" | "unknown";
	compatibility: "historical";
}
export type SdkRelease = AnnouncedSdkRelease | RetainedSdkRelease | HistoricalSdkRelease;

/** Public notes retain historical private-source releases and newly published platform source. */
interface PlatformReleaseBase {
	kind: "platform";
	id: string;
	slug: string;
	title: string;
	summary: string;
	notes: string[];
	publishedAt: string;
	dateConfidence: "known";
	compatibility: "platform-update";
	changelogUrl: string;
	sourceUrl: string | null;
	provenance: ReleaseProvenance[];
}

export interface AnnouncedPlatformRelease extends PlatformReleaseBase { announce: true }
export interface HistoricalPlatformRelease extends PlatformReleaseBase { announce: false }
export type PlatformRelease = AnnouncedPlatformRelease | HistoricalPlatformRelease;
export type AnnouncedRelease = AnnouncedSdkRelease | AnnouncedPlatformRelease;
