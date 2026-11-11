import type { Metadata } from "next";
import { ConsoleNotifications } from "@/components/console/notifications";
import { sdkReleases } from "@/lib/notifications/releases";

export const metadata: Metadata = { title: "Notifications · AllAuth" };

export default function NotificationsPage() {
	return <ConsoleNotifications latestRelease={sdkReleases[0] ?? null} />;
}
