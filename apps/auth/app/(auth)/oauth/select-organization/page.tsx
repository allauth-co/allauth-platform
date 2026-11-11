import type { Metadata } from "next";
import { headers } from "next/headers";
import {redirect} from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { portalSession, withPortalHeaders } from "@/lib/domains/hosting";
import { GoBackBtn, SelectOrganizationBtn } from "./org-buttons";

export const metadata: Metadata = {
	title: "Select Organization",
	description: "Specify which organization to authorize to this application",
};

export default async function SelectOrganizationPage({searchParams}:{searchParams:Promise<Record<string,string|string[]|undefined>>}) {
 const requestHeaders=await headers();const session=await portalSession(requestHeaders);
 if(!session){const values=await searchParams;const query=new URLSearchParams();for(const [key,value] of Object.entries(values)){if(typeof value==="string")query.append(key,value);else if(Array.isArray(value))for(const part of value)query.append(key,part);}redirect(`/sign-in?${query}`);}

	const organizations = await withPortalHeaders(requestHeaders,(instance,bound)=>instance.api.listOrganizations({headers:bound}));
	return (
		<div className="w-full">
			<div className="flex items-center flex-col justify-center w-full md:py-10">
				<div className="md:w-[400px]">
					<Card className="w-full ">
						<CardHeader>
							<CardTitle className="text-lg md:text-xl">
								Select Organization
							</CardTitle>
						</CardHeader>
						<CardContent className="p-6">
							{organizations.length ? (
								organizations.map((o, i) => (
									<SelectOrganizationBtn key={o.id ?? i} organization={o} />
								))
							) : (
								<div>
									<p>
										Application is requesting scopes for an organization but no
										organizations exist for this account.
									</p>
									<br />
									<div className="flex flex-col gap-1">
										<Link href="/organizations">
											<Button className="w-full">Create Organization</Button>
										</Link>
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
