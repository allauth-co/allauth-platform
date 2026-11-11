// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { getOrganizationCardKey } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import type { ComponentProps } from "react";

import { cn } from "cn";
import { OrganizationDangerZone } from "./organization-danger-zone";
import { OrganizationProfile } from "./organization-profile";

export type OrganizationSettingsProps = {
	className?: string;
	organizationId: string;
	organizationSlug: string;
};

/**
 * Organization settings UI: profile card, plugin-contributed cards
 * (`organizationCards`), then danger zone.
 */
export function OrganizationSettings({
	className,
	organizationId,
	organizationSlug,
	...props
}: OrganizationSettingsProps & ComponentProps<"div">) {
	const { plugins } = useAuth();

	return (
		<div className={cn("flex flex-col gap-4 md:gap-6", className)} {...props}>
			<OrganizationProfile />

			{plugins.flatMap((plugin) =>
				plugin.organizationCards?.map((Card) => (
					<Card
						key={getOrganizationCardKey(plugin.id, Card)}
						organizationId={organizationId}
						organizationSlug={organizationSlug}
					/>
				)),
			)}

			<OrganizationDangerZone />
		</div>
	);
}
