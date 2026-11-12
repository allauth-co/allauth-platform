import { getAuthEnvironment } from "../auth";
import { setting } from "../configuration";
import { portalHeader, verifyPortalBinding } from "./edge";
import {
	hasHostedSdkSelection,
	hostedSdkSelected,
} from "./hosted-sdk-selection";
import { resolveHostedBinding } from "./hosting";

/** Enable the organization client only for the verified, allowlisted accounts realm. */
export async function hostedOrganizationPreview(headers: Headers) {
	const proof = headers.get(portalHeader);
	if (!proof) return false;
	const env = await getAuthEnvironment();
	if (!hasHostedSdkSelection(env)) return false;
	const hostname = await verifyPortalBinding(
		proof,
		setting(env, "ALLAUTH_EDGE_SECRET"),
	);
	const binding = hostname ? await resolveHostedBinding(hostname, env) : null;
	return (
		binding?.kind === "accounts" && hostedSdkSelected(env, binding.project)
	);
}
