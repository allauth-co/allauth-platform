import { getAuthEnvironment } from "../auth";
import type { AuthEnvironment } from "../configuration";
import { edgeHeaders, portalHeader } from "../domains/edge";
import { withPortalHeadersEngine } from "../domains/hosting";
import { publicBranding } from "../../sdk/branding";
import type { AllAuthPublicBranding } from "../../sdk/branding";
import { readApplicationBranding } from "./repository";

/** Share validated public settings without exposing application or workspace authority. */
export async function readPublicApplicationBranding(projectId: string, env: AuthEnvironment): Promise<AllAuthPublicBranding> {
	const branding = publicBranding(await readApplicationBranding(projectId, env));
	if (!branding) throw new Error("Application branding is unavailable.");
	return branding;
}

/** Raw Host/query values never select branding; proxy-minted portal proofs are reverified. */
export async function portalBranding(headers: Headers): Promise<AllAuthPublicBranding | null> {
	if (!headers.has(portalHeader) && !edgeHeaders.some((name) => headers.has(name))) return null;
	return withPortalHeadersEngine(headers, async (_engine, _bound, binding) => {
		if (!binding) return null;
		return readPublicApplicationBranding(binding.project.id, await getAuthEnvironment());
	});
}
