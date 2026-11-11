"use client";
import { useQuery } from "@tanstack/react-query";
import { publicBranding } from "@/sdk/branding";
import type { PasswordPolicy } from "@/lib/auth-policy/password";
import type { AllAuthPublicBranding } from "@/sdk/branding";
export interface Configuration {
	google: boolean;
	apple?: boolean;
	appleProvider?: "apple" | null;
	googleProvider?: "google" | "allauth" | null;
	microsoft: boolean;
	microsoftProvider?: "microsoft" | null;
	github: boolean;
	email: boolean;
	emailPassword?: boolean;
	signUpEnabled?: boolean;
	emailVerificationRequired?: boolean;
	passwordPolicy?: PasswordPolicy;
	enterpriseSSO: boolean;
	apiKeys: boolean;
	scim: boolean;
	broker?: boolean;
	realmName?: string;
	platformOrigin?: string;
	branding?: AllAuthPublicBranding | null;
}
export function useConfiguration() {
	return useQuery({
		queryKey: ["configuration"],
		queryFn: async (): Promise<Configuration> => {
			const response = await fetch("/api/config", { cache: "no-store" });
			if (!response.ok)
				throw new Error("Unable to load authentication configuration");
			const data: Configuration = await response.json();
			return { ...data, ...(data.branding === undefined ? {} : { branding: publicBranding(data.branding) }) };
		},
		staleTime: 60_000,
	});
}
