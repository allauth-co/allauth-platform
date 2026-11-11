// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import {
	Item,
	ItemContent,
	ItemMedia,
} from "@/components/better-auth-ui/ui/item";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Placeholder row matching `UserInvitationRow` while invitations load.
 */
export function UserInvitationRowSkeleton() {
	return (
		<Item>
			<ItemMedia>
				<Skeleton className="size-10 shrink-0 rounded-md" />
			</ItemMedia>
			<ItemContent>
				<Skeleton className="h-4 w-40 rounded-md" />
				<Skeleton className="h-3 w-28 rounded-md" />
			</ItemContent>
		</Item>
	);
}
