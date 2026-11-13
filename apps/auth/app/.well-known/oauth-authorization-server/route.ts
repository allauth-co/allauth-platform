import { readPortalIssuerMetadata } from "@/lib/domains/hosting";

export function GET(request: Request) {
	return readPortalIssuerMetadata(request, "oauth");
}
