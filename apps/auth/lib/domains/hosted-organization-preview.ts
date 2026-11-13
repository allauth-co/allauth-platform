import { getAuthEnvironment } from "../auth";
import { setting } from "../configuration";
import { portalHeader, verifyPortalBinding } from "./edge";
import type { HostedPresentation } from "./hosted-presentation";
import { hostedSdkSelectionMode } from "./hosted-sdk-selection";
import { resolveHostedBinding } from "./hosting";

/** Resolve the presentation for the exact verified project hostname. */
export async function hostedPresentation(
	headers: Headers,
): Promise<HostedPresentation | undefined> {
	const proof = headers.get(portalHeader);
	if (!proof) return;
	const env = await getAuthEnvironment();
	const hostname = await verifyPortalBinding(
		proof,
		setting(env, "ALLAUTH_EDGE_SECRET"),
	);
	const binding = hostname ? await resolveHostedBinding(hostname, env) : null;
	if (!binding || binding.hostname !== hostname) return;
	return (
		(await hostedSdkSelectionMode(env, binding.project, binding.kind)) ??
		"legacy"
	);
}
