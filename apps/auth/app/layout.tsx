import "./globals.css";
import "@/components/console/console.css";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { headers } from "next/headers";
import { SiteFrame } from "@/components/console/site-frame";
import { HostedOrganizationProvider } from "@/components/hosted-organization-client";
import Providers from "@/components/providers";
import { portalBranding } from "@/lib/branding/portal";
import { applicationMetadata } from "@/lib/branding/presentation";
import { hostedOrganizationPreview } from "@/lib/domains/hosted-organization-preview";

export async function generateMetadata() {
	return applicationMetadata(await portalBranding(await headers()));
}
export default async function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	const preview = await hostedOrganizationPreview(await headers());
	return (
		<html lang="en" suppressHydrationWarning>
			<body
				className={`${GeistSans.variable} ${GeistMono.variable} font-sans min-h-screen bg-background`}
			>
				<Providers>
					<HostedOrganizationProvider enabled={preview}>
						<SiteFrame>{children}</SiteFrame>
					</HostedOrganizationProvider>
				</Providers>
			</body>
		</html>
	);
}
