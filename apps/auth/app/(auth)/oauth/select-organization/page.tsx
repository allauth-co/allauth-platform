import type { Metadata } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
	oauthPickerQuery,
	readPortalOAuthOrganizations,
} from "@/lib/oauth-picker-portal";
import { GoBackBtn, OrganizationChoices } from "./org-buttons";

export const metadata: Metadata = {
	title: "Select Organization",
	description: "Specify which organization to authorize to this application",
};

export default async function SelectOrganizationPage({
	searchParams,
}: {
	searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
	const [requestHeaders, params] = await Promise.all([headers(), searchParams]);
	const query = oauthPickerQuery(params);
	const organizations = await readPortalOAuthOrganizations(requestHeaders);
	if (!organizations) redirect(query ? `/sign-in?${query}` : "/sign-in");

	return (
		<div className="w-full">
			<div className="w-full flex items-center flex-col justify-center md:py-10">
				<div className="md:w-[400px]">
					<Card className="w-full">
						<CardHeader>
							<CardTitle className="text-lg md:text-xl">
								Select Organization
							</CardTitle>
						</CardHeader>
						<CardContent className="p-6">
							{organizations.length ? (
								<OrganizationChoices
									organizations={organizations}
									query={query}
								/>
							) : (
								<div>
									<p>
										Application is requesting scopes for an organization but no
										organizations exist for this account.
									</p>
									<br />
									<div className="flex flex-col gap-1">
										<Button asChild className="w-full">
											<Link href="/organizations">Create Organization</Link>
										</Button>
										<GoBackBtn />
									</div>
								</div>
							)}
						</CardContent>
					</Card>
				</div>
			</div>
		</div>
	);
}
