import { apiResponse } from "@/lib/api";
import { withPortalAuthEngine } from "@/lib/domains/hosting";

export async function GET(request: Request) {
	return apiResponse(() =>
		withPortalAuthEngine(request, (engine, _env, bound) =>
			engine.readOAuthContext(bound),
		),
	);
}
