import type { Metadata } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
	oauthPickerQuery,
	readPortalOAuthAccounts,
} from "@/lib/oauth-picker-portal";
import { AccountChoices } from "./account-button";

export const metadata: Metadata = {
	title: "Select Account",
	description: "Select account to authorize this application",
};

export default async function SelectAccountPage({
	searchParams,
}: {
	searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
	const [requestHeaders, params] = await Promise.all([headers(), searchParams]);
	const query = oauthPickerQuery(params);
	const accounts = await readPortalOAuthAccounts(requestHeaders);
	if (!accounts) redirect(query ? `/sign-in?${query}` : "/sign-in");

	return (
		<div className="w-full">
			<div className="w-full flex items-center flex-col justify-center md:py-10">
				<div className="md:w-[400px]">
					<Card className="w-full">
						<CardHeader>
							<CardTitle className="text-lg md:text-xl">
								Select Account
							</CardTitle>
						</CardHeader>
						<CardContent className="p-6">
							<AccountChoices accounts={accounts} query={query} />
						</CardContent>
					</Card>
				</div>
			</div>
		</div>
	);
}
