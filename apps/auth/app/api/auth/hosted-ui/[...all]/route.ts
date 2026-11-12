import { authOrigin } from "@/lib/configuration";
import { edgeHeaders } from "@/lib/domains/edge";
import { hostedSdkMagicLinkRequests } from "@/lib/domains/hosted-magic-link-requests";
import {
	hostedPasswordSignInRequests,
	hostedSocialSignInRequests,
} from "@/lib/domains/hosted-oauth-requests";
import { hostedScimConsoleRequest } from "@/lib/domains/hosted-scim-console";
import { hostedSdkEndpoint } from "@/lib/domains/hosted-sdk-policy";
import {
	hostedSdkFailure,
	hostedSdkResponse,
} from "@/lib/domains/hosted-sdk-response";
import { hostedSdkTransportEnabled } from "@/lib/domains/hosted-sdk-selection";
import { withPortalAuthEngine } from "@/lib/domains/hosting";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";
import { scimConsoleRoute } from "@/lib/scim-management";

async function handle(request: Request) {
	const endpoint = hostedSdkEndpoint(
		new URL(request.url).pathname,
		request.method,
	);
	if (
		!endpoint ||
		(endpoint !== "sdk/config" &&
			request.headers.get("accept") !== "application/json") ||
		!edgeHeaders.every((name) => request.headers.has(name))
	)
		return hostedSdkFailure(404, "Authentication route is unavailable.");

	return withPortalAuthEngine(request, async (engine, env, bound, binding) => {
		if (
			!binding ||
			binding.kind !== "accounts" ||
			!hostedSdkTransportEnabled(env, binding.project)
		)
			return hostedSdkFailure(404, "Authentication route is unavailable.");
		const url = new URL(bound.url);
		const requestOrigin = bound.headers.get("origin");
		if (
			bound.headers.get("sec-fetch-site") === "cross-site" ||
			((bound.method === "POST" || requestOrigin) &&
				requestOrigin !== url.origin)
		)
			return hostedSdkFailure(
				403,
				"A same-origin authentication request is required.",
			);

		if (endpoint === "email-otp/send-verification-otp") {
			const input: unknown = await bound
				.clone()
				.json()
				.catch(() => null);
			if (
				!input ||
				typeof input !== "object" ||
				!("type" in input) ||
				input.type !== "sign-in"
			)
				return hostedSdkFailure(400, "A sign-in code must be requested.");
		}
		if (endpoint === "account-info") {
			const accountId = url.searchParams.get("accountId");
			if (url.searchParams.size !== 1 || !accountId || accountId.length > 160)
				return hostedSdkFailure(400, "Select a linked account.");
		}
		if (
			(endpoint === "account-info" ||
				endpoint === "two-factor/enable" ||
				endpoint === "two-factor/generate-backup-codes") &&
			bound.headers.has("authorization")
		)
			return hostedSdkFailure(403, "A browser session is required.");
		if (endpoint.startsWith("sso/") && request.headers.has("authorization"))
			return hostedSdkFailure(403, "A browser session is required.");
		if (endpoint.startsWith("scim/")) {
			if (request.headers.has("authorization"))
				return hostedSdkFailure(403, "A browser session is required.");
			const operation = hostedScimConsoleRequest(
				bound,
				endpoint,
				binding.project.slug,
				authOrigin(env),
			);
			if (!operation)
				return hostedSdkFailure(400, "Invalid directory management request.");
			return hostedSdkResponse(
				await scimConsoleRoute(operation.request, operation.route),
				endpoint,
				url.origin,
				binding.project.slug,
			);
		}

		// The gateway verifies the original URL and body before this dispatch.
		url.pathname = `/api/auth/${endpoint}`;
		const nativeRequest = new Request(url, {
			method: bound.method,
			headers: bound.headers,
			body: bound.body,
			duplex: "half",
		} as RequestInit);
		if (endpoint === "sign-in/magic-link")
			hostedSdkMagicLinkRequests.add(nativeRequest);
		if (endpoint === "sign-in/social")
			hostedSocialSignInRequests.add(nativeRequest);
		if (endpoint === "sign-in/email" || endpoint === "sign-in/username")
			hostedPasswordSignInRequests.add(nativeRequest);
		return hostedSdkResponse(
			await engine.dispatch(nativeRequest),
			endpoint,
			url.origin,
			binding.project.slug,
		);
	}).catch((error: unknown) => {
		if (!isProjectWriterUnavailable(error)) throw error;
		return hostedSdkFailure(503, "Authentication is temporarily unavailable.");
	});
}

export const GET = handle;
export const POST = handle;
