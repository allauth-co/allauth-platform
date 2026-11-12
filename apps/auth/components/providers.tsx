"use client";
import { QueryClientProvider } from "@tanstack/react-query";
import { usePathname } from "next/navigation";
import { Suspense } from "react";
import { getQueryClient } from "@/data/query-client";
import { firstPartyHostedPath } from "@/lib/hosted-portal-paths";
import { isPublicProductPath } from "@/lib/public-site";
import { LegacyAuthUI } from "./legacy-auth-ui";
import { ThemeProvider } from "./theme-provider";
import { Toaster } from "./ui/sonner";
export default function Providers({
	children,
	hostedPreview = false,
}: {
	children: React.ReactNode;
	hostedPreview?: boolean;
}) {
	const pathname = usePathname();
	const firstParty = hostedPreview && firstPartyHostedPath(pathname);
	return (
		<ThemeProvider attribute="class" defaultTheme="light">
			<QueryClientProvider client={getQueryClient()}>
				<Toaster richColors closeButton />
				<Suspense
					fallback={
						<p role="status" className="p-5 text-muted-foreground">
							Loading AllAuth…
						</p>
					}
				>
					{isPublicProductPath(pathname) || firstParty ? (
						children
					) : (
						<LegacyAuthUI>{children}</LegacyAuthUI>
					)}
				</Suspense>
			</QueryClientProvider>
		</ThemeProvider>
	);
}
