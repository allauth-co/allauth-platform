import "./globals.css";
import "@/components/console/console.css";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { headers } from "next/headers";
import { SiteFrame } from "@/components/console/site-frame";
import Providers from "@/components/providers";
import { portalBranding } from "@/lib/branding/portal";
import { applicationMetadata } from "@/lib/branding/presentation";

export async function generateMetadata() {
	return applicationMetadata(await portalBranding(await headers()));
}
export default function RootLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return (
		<html lang="en" suppressHydrationWarning>
			<body
				className={`${GeistSans.variable} ${GeistMono.variable} font-sans min-h-screen bg-background`}
			>
				<Providers>
					<SiteFrame>{children}</SiteFrame>
				</Providers>
			</body>
		</html>
	);
}
