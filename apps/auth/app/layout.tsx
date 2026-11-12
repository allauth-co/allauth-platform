import "./globals.css";
import "@/components/console/console.css";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { headers } from "next/headers";
import { SiteFrame } from "@/components/console/site-frame";
import { HostedAccountHeader } from "@/components/hosted-account-header";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";
import { HostedProjectUnavailable } from "@/components/hosted-project-unavailable";
import { LegacyAccountHeader } from "@/components/legacy-auth-ui";
import Providers from "@/components/providers";
import { portalBranding } from "@/lib/branding/portal";
import { applicationMetadata } from "@/lib/branding/presentation";
import { hostedOrganizationPreview } from "@/lib/domains/hosted-organization-preview";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";

export async function generateMetadata() {
	const branding = await portalBranding(await headers()).catch((error: unknown) => {
		if (!isProjectWriterUnavailable(error)) throw error;
		return null;
	});
	return applicationMetadata(branding);
}
export default async function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	const preview = await hostedOrganizationPreview(await headers()).catch((error: unknown) => {
		if (!isProjectWriterUnavailable(error)) throw error;
		return null;
	});
	return (
		<html lang="en" suppressHydrationWarning>
			<body
				className={`${GeistSans.variable} ${GeistMono.variable} font-sans min-h-screen bg-background`}
			>
				{preview === null ? <HostedProjectUnavailable /> : <Providers hostedPreview={preview}>
					<HostedOrganizationProvider enabled={preview}>
						<SiteFrame
							header={
								preview ? <HostedAccountHeader /> : <LegacyAccountHeader />
							}
						>
							{children}
						</SiteFrame>
					</HostedOrganizationProvider>
				</Providers>}
			</body>
		</html>
	);
}
