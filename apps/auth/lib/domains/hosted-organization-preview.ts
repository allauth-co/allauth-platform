import { getAuthEnvironment } from "../auth";
import { setting } from "../configuration";
import { portalHeader, verifyPortalBinding } from "./edge";
import { hostedSdkSelected } from "./hosted-sdk-selection";
import { resolveHostedBinding } from "./hosting";

/** Enable the organization client for an eligible, verified project hostname. */
export async function hostedOrganizationPreview(headers: Headers) {
	const proof = headers.get(portalHeader);
	if (!proof) return false;
	const env = await getAuthEnvironment();
	const hostname = await verifyPortalBinding(
		proof,
		setting(env, "ALLAUTH_EDGE_SECRET"),
	);
	const binding = hostname ? await resolveHostedBinding(hostname, env) : null;
	if (!binding) return false;
	return hostedSdkSelected(env, binding.project, binding.kind);
}
