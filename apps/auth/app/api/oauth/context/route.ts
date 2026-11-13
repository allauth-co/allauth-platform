import { apiResponse } from "@/lib/api";
import { readPortalIssuerContext } from "@/lib/domains/hosting";

export async function GET(request: Request) {
	return apiResponse(() => readPortalIssuerContext(request));
}
