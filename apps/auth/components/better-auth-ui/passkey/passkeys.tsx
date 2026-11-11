// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import type { PasskeyAuthClient } from "@better-auth-ui/core/plugins/passkey";
import { useAuthPlugin, useSession } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { useListPasskeys } from "@better-auth-ui/react/plugins/passkey";
import { Fragment, useState } from "react";

import { Button } from "@/components/better-auth-ui/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ItemGroup, ItemSeparator } from "@/components/better-auth-ui/ui/item";
import { passkeyPlugin } from "@/components/better-auth-ui/lib/passkey-plugin";
import { cn } from "cn";

import { AddPasskeyDialog } from "./add-passkey-dialog";
import { Passkey } from "./passkey";
import { PasskeySkeleton } from "./passkey-skeleton";
import { PasskeysEmpty } from "./passkeys-empty";
import { AccountDataError, AccountSignInRequired } from "../settings/security/account-data-state";

export type PasskeysProps = {
	className?: string;
};

export function Passkeys({ className }: PasskeysProps) {
	const { authClient } = useAuth<PasskeyAuthClient>();
	const { localization: passkeyLocalization } = useAuthPlugin(passkeyPlugin);

	const session = useSession(authClient);
	const { data: passkeys, isPending, error, refetch, isFetching } = useListPasskeys(authClient);

	const [addOpen, setAddOpen] = useState(false);

	return (
		<div className={cn("flex flex-col gap-3", className)}>
			<div className="flex items-end justify-between gap-3">
				<h2 className="truncate text-sm font-semibold">
					{passkeyLocalization.passkeys}
				</h2>

				<Button
					className="shrink-0"
					size="sm"
					disabled={isPending || Boolean(error) || Boolean(session.error) || !session.data}
					onClick={() => setAddOpen(true)}
				>
					{passkeyLocalization.addPasskey}
				</Button>
			</div>

			<Card className="p-0">
				<CardContent className="p-0">
					{session.error ? (
						<AccountDataError message="Unable to load your account session." retry={() => session.refetch()} isFetching={session.isFetching} />
					) : !session.isPending && !session.data ? (
						<AccountSignInRequired />
					) : error ? (
						<AccountDataError message="Unable to load your passkeys." retry={() => refetch()} isFetching={isFetching} />
					) : isPending ? (
						<PasskeySkeleton />
					) : !passkeys?.length ? (
						<PasskeysEmpty onAddPress={() => setAddOpen(true)} />
					) : (
						<ItemGroup className="gap-0">
							{passkeys.map((passkey, index) => (
								<Fragment key={passkey.id}>
									{index > 0 && <ItemSeparator />}
									<Passkey passkey={passkey} />
								</Fragment>
							))}
						</ItemGroup>
					)}
				</CardContent>
			</Card>

			<AddPasskeyDialog open={addOpen} onOpenChange={setAddOpen} />
		</div>
	);
}
