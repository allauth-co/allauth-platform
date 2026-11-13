"use client";

import { useRouter } from "next/navigation";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { useOAuthPicker } from "@/lib/oauth-picker-browser";
import type { OAuthOrganizationChoice } from "@/lib/oauth-picker-portal";

export function OrganizationChoices({
	organizations,
	query,
}: {
	organizations: OAuthOrganizationChoice[];
	query: string;
}) {
	const { choose, pending } = useOAuthPicker(query);
	return (
		<div aria-busy={pending}>
			{organizations.map((organization) => (
				<Button
					key={organization.id}
					type="button"
					className="w-full gap-2 h-12"
					variant="outline"
					disabled={pending}
					onClick={() =>
						void choose({ kind: "organization", id: organization.id })
					}
				>
					<Avatar className="mr-2 h-5 w-5">
						<AvatarImage
							src={organization.logo || undefined}
							alt={organization.name}
						/>
						<AvatarFallback>{organization.name.charAt(0)}</AvatarFallback>
					</Avatar>
					<span className="text-start w-full">{organization.name}</span>
				</Button>
			))}
		</div>
	);
}

export function GoBackBtn() {
	const router = useRouter();
	return (
		<Button
			type="button"
			className="w-full gap-2 h-12"
			variant="outline"
			onClick={() => router.back()}
		>
			Go Back
		</Button>
	);
}
