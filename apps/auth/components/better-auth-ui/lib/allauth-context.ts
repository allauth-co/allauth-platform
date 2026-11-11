"use client";
import { createContext, useContext } from "react";
import type { PasswordPolicy } from "@/lib/auth-policy/password";
import type { AllAuthPublicBranding } from "@/sdk/branding";
export interface AllAuthUIContextValue {
	origin: string;
	redirectTo: string;
	ready: boolean;
	error: string;
	complete: (data?: unknown) => Promise<void>;
	authURL: (path: string) => string;
	sessionsEndpoint: string;
	realmName?: string;
	branding?: AllAuthPublicBranding | null;
	/** Current environment registration policy, separate from password sign-in availability. */
	signUpEnabled?: boolean;
	passwordPolicy?: PasswordPolicy;
}
export const AllAuthUIContext = createContext<AllAuthUIContextValue | null>(
	null,
);
export function useAllAuthUI() {
	return useContext(AllAuthUIContext);
}
