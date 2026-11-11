// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { getProviderId } from "@better-auth-ui/core";
import { useListAccounts, useSession } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { Fragment } from "react";
import { Card, CardContent } from "@/components/ui/card";
import {
	Item,
	ItemContent,
	ItemGroup,
	ItemMedia,
	ItemSeparator,
} from "@/components/better-auth-ui/ui/item";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "cn";
import { LinkedAccount } from "./linked-account";
import { AccountDataError, AccountSignInRequired } from "./account-data-state";

export type LinkedAccountsProps = {
	className?: string;
};

/**
 * Render a card showing linked social accounts and available social providers to link.
 *
 * Linked accounts (excluding the "credential" provider) are shown with an unlink control;
 * available providers are shown with a link control. Button states and labels reflect
 * ongoing link/unlink activity and use localization for provider-specific text.
 *
 * @returns A JSX element containing the linked accounts card
 */
export function LinkedAccounts({ className }: LinkedAccountsProps) {
	const {
		authClient,
		allowUnlinkingAllAccounts,
		localization,
		multipleAccountsPerProvider,
		socialProviders,
	} = useAuth();

	const session = useSession(authClient);
	const { data: accounts, isPending, error, refetch, isFetching } = useListAccounts(authClient);

	const linkedAccounts = accounts?.filter(
		(account) => account.providerId !== "credential",
	);
	const canUnlink =
		allowUnlinkingAllAccounts === true || (accounts?.length ?? 0) > 1;

	const linkedProviderIds = new Set(linkedAccounts?.map((a) => a.providerId));

	const availableProviders =
		multipleAccountsPerProvider === false
			? socialProviders?.filter(
					(provider) => !linkedProviderIds.has(getProviderId(provider)),
				)
			: socialProviders;

	const allRows = [
		...(linkedAccounts?.map((account) => ({
			key: account.id,
			account,
			provider:
				socialProviders?.find(
					(provider) => getProviderId(provider) === account.providerId,
				) ?? account.providerId,
		})) ?? []),
		...(availableProviders?.map((provider) => ({
			key: getProviderId(provider),
			account: undefined,
			provider,
		})) ?? []),
	];

	return (
		<div>
			<h2 className="text-sm font-semibold mb-3">
				{localization.settings.linkedAccounts}
			</h2>

			<Card className={cn("p-0", className)}>
				<CardContent className="p-0">
					{session.error ? (
						<AccountDataError message="Unable to load your account session." retry={() => session.refetch()} isFetching={session.isFetching} />
					) : !session.isPending && !session.data ? (
						<AccountSignInRequired />
					) : error ? (
						<AccountDataError message="Unable to load linked accounts." retry={() => refetch()} isFetching={isFetching} />
					) : <ItemGroup className="gap-0">
						{isPending
							? socialProviders?.map((provider, index) => (
									<Fragment key={getProviderId(provider)}>
										{index > 0 && <ItemSeparator />}
										<AccountRowSkeleton />
									</Fragment>
								))
							: allRows.map((row, index) => (
									<Fragment key={row.key}>
										{index > 0 && <ItemSeparator />}
										<LinkedAccount
											account={row.account}
											canUnlink={canUnlink}
											provider={row.provider}
										/>
									</Fragment>
								))}
					</ItemGroup>}
				</CardContent>
			</Card>
		</div>
	);
}

function AccountRowSkeleton() {
	return (
		<Item>
			<ItemMedia>
				<Skeleton className="size-10 rounded-md" />
			</ItemMedia>
			<ItemContent>
				<Skeleton className="h-4 w-20" />
				<Skeleton className="h-3 w-32" />
			</ItemContent>
		</Item>
	);
}
