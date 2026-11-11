import type { Metadata } from "next/types";

export function createMetadata(override: Metadata): Metadata {
	return {
		...override,
		openGraph: {
			title: override.title ?? undefined,
			description: override.description ?? undefined,
			url: "https://allauth.co",
			siteName: "AllAuth",
			...override.openGraph,
		},
		twitter: {
			card: "summary",
			title: override.title ?? undefined,
			description: override.description ?? undefined,
			...override.twitter,
		},
	};
}

export const baseUrl =
	new URL(process.env.BETTER_AUTH_URL || "https://allauth.co");
