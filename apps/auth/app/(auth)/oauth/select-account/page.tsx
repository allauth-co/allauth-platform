import type { Metadata } from "next";
import { headers } from "next/headers";
import {redirect} from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { portalSession, withPortalHeaders } from "@/lib/domains/hosting";
import { AnotherAccountBtn, SelectAccountBtn } from "./account-button";

export const metadata: Metadata = {
	title: "Select Account",
	description: "Select account to authorize this application",
};

export default async function SelectAccountPage({searchParams}:{searchParams:Promise<Record<string,string|string[]|undefined>>}) {
 const requestHeaders=await headers();const session=await portalSession(requestHeaders);
 if(!session){const values=await searchParams;const query=new URLSearchParams();for(const [key,value] of Object.entries(values)){if(typeof value==="string")query.append(key,value);else if(Array.isArray(value))for(const part of value)query.append(key,part);}redirect(`/sign-in?${query}`);}

	const sessions = await withPortalHeaders(requestHeaders,(instance,bound)=>instance.api.listDeviceSessions({headers:bound}));
	return (
		<div className="w-full">
			<div className="flex items-center flex-col justify-center w-full md:py-10">
				<div className="md:w-[400px]">
					<Card className="w-full ">
						<CardHeader>
							<CardTitle className="text-lg md:text-xl">
								Select Account
							</CardTitle>
						</CardHeader>
						<CardContent className="p-6">
							{sessions.map((s, i) => (
								<SelectAccountBtn key={s.session.id ?? i} session={s} />
							))}
						</CardContent>
						<AnotherAccountBtn />
					</Card>
				</div>
			</div>
		</div>
	);
}
