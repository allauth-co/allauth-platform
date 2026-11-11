"use client";
import { QueryClientProvider } from "@tanstack/react-query";
import { getQueryClient } from "@/data/query-client";
import { ThemeProvider } from "./theme-provider";
import { Toaster } from "./ui/sonner";
import { Suspense } from "react";
import { usePathname } from "next/navigation";
import { AllAuthUIProvider } from "./better-auth-ui/allauth-provider";
import { isPublicProductPath } from "@/lib/public-site";
export default function Providers({ children }: { children: React.ReactNode }) {
	const pathname = usePathname();
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
					{isPublicProductPath(pathname) ? children : <AllAuthUIProvider>{children}</AllAuthUIProvider>}
				</Suspense>
			</QueryClientProvider>
		</ThemeProvider>
	);
}
