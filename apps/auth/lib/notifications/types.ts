import type { AnnouncedSdkRelease } from "./catalog-types";

/** Safe dashboard data. SDK observations are advisory application reports, never authentication evidence. */
export interface SdkObservation {
	projectId: string;
	projectName: string;
	projectSlug: string;
	environment: "development" | "production";
	version: string | null;
	lastSeenAt: string | null;
	updateAvailable: boolean | null;
}
interface ReleaseNotificationBase {
	id: string;
	title: string;
	body: string;
	createdAt: string;
	readAt: string | null;
}
export interface SdkReleaseNotification extends ReleaseNotificationBase {
	kind: "sdk-release";
	release: {
		version: string;
		compatibility: AnnouncedSdkRelease["compatibility"];
		summary: string;
		upgradeUrl: string;
		changelogUrl: string;
		downloadUrl: string;
		sha256: string | null;
	};
}
export interface PlatformReleaseNotification extends ReleaseNotificationBase {
	kind: "platform-release";
	release: { compatibility: "platform-update"; summary: string; changelogUrl: string };
}
export type ReleaseNotification = SdkReleaseNotification | PlatformReleaseNotification;
export interface NotificationsResponse {
	notifications: ReleaseNotification[];
	unreadCount: number;
	preferences: { releaseEmails: boolean };
	sdk: { latestVersion: string | null; observed: SdkObservation[] };
	pagination: { total: number; limit: number; offset: number };
}
