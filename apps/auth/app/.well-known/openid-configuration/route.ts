import { NextResponse } from "next/server";
import { withPortalRequest } from "@/lib/domains/hosting";
import { discoveryDocument, discoveryHeaders } from "@/lib/discovery";

export async function GET(request:Request): Promise<NextResponse> {
	return withPortalRequest(request,async (auth)=>{const config=await auth.api.getOpenIdConfig();return NextResponse.json(discoveryDocument(config),{headers:discoveryHeaders});});
}
