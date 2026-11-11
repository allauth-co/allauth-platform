import { Link, Text } from "@react-email/components";
import { EmailAction, EmailLayout, emailMutedTextStyle, emailTextStyle } from "../email/layout";
import type { AnnouncedRelease } from "./releases";

/** Platform update mail contains public release notes and links; no tenant or repository data. */
export function ReleaseNotificationEmail({ release, notificationsUrl }: { release: AnnouncedRelease; notificationsUrl: string }) {
	return <EmailLayout title={release.title} preview={release.summary} footer={<Text style={emailMutedTextStyle}>You receive AllAuth release emails because you manage an AllAuth workspace. <Link href={notificationsUrl}>Manage update email preferences</Link>.</Text>}>
		<Text style={emailTextStyle}>{release.summary}</Text>
		{release.kind === "sdk" ? <Text style={emailTextStyle}>This is a backward-compatible SDK update. Your installed version keeps working. Review the release notes, update your pinned package, and rebuild and deploy your app when ready. AllAuth does not change your application dependencies automatically.</Text>
			: <Text style={emailTextStyle}>This is an AllAuth platform update. Review the release notes for hosted service changes and any optional configuration. This notice does not require changing an SDK package unless the release notes explicitly say so.</Text>}
		<EmailAction url={release.changelogUrl} label="Read release notes" />
		{release.kind === "sdk" && <Text style={emailMutedTextStyle}>The dashboard can show a version reported by a recent SDK request. Older SDKs may not report a version; no access to your application's source code is required to receive these notices.</Text>}
	</EmailLayout>;
}
