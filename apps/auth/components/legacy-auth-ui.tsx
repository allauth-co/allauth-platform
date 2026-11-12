"use client";

import type { ReactNode } from "react";
import { lazy } from "react";
import { useAllAuthUI } from "./better-auth-ui/lib/allauth-context";

const LegacyProvider = lazy(async () => ({
	default: (await import("./better-auth-ui/allauth-provider"))
		.AllAuthUIProvider,
}));

/** Load the legacy browser provider when a mounted view requires it. */
export function LegacyAuthUI({ children }: { children: ReactNode }) {
	return useAllAuthUI() ? (
		children
	) : (
		<LegacyProvider>{children}</LegacyProvider>
	);
}
