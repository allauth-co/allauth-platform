import { withPortalAuthEngine } from "@/lib/domains/hosting";

export function GET(request: Request) {
	return withPortalAuthEngine(request, (engine) =>
		engine.readIssuerMetadata("openid"),
	);
}
