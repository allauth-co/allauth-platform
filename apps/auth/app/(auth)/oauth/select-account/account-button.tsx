"use client";

import Link from "next/link";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { useOAuthPicker } from "@/lib/oauth-picker-browser";
import type { OAuthAccountChoice } from "@/lib/oauth-picker-portal";

export function AccountChoices({
	accounts,
	query,
}: {
	accounts: OAuthAccountChoice[];
	query: string;
}) {
	const { choose, pending } = useOAuthPicker(query);
	return (
		<div aria-busy={pending}>
			{accounts.map((account) => (
				<Button
					key={account.id}
					type="button"
					className="w-full gap-2 h-12"
					variant="outline"
					disabled={pending}
					onClick={() =>
						void choose({
							kind: "account",
							id: account.id,
							sessionToken: account.sessionToken,
						})
					}
				>
					<Avatar className="mr-2 h-5 w-5">
						<AvatarImage src={account.image || undefined} alt={account.name} />
						<AvatarFallback>{account.name.charAt(0)}</AvatarFallback>
					</Avatar>
					<span className="flex flex-col text-start w-full">
						<span>{account.name}</span>
						<span className="text-xs">{account.email}</span>
					</span>
				</Button>
			))}
			<Button asChild className="w-full gap-2 h-12" variant="outline">
				<Link
					href={query ? `/sign-in?${query}` : "/sign-in"}
					aria-disabled={pending}
					onClick={(event) => {
						if (pending) event.preventDefault();
					}}
				>
					Another Account
				</Link>
			</Button>
		</div>
	);
}
