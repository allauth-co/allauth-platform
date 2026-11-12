import { setting } from "@/lib/configuration";
import { edgeHeaders } from "@/lib/domains/edge";
import {
	hostedSdkEndpoint,
	hostedSdkProjectEnabled,
	hostedSdkProjectIdsSetting,
} from "@/lib/domains/hosted-sdk-policy";
import {
	hostedSdkFailure,
	hostedSdkResponse,
} from "@/lib/domains/hosted-sdk-response";
import { withPortalAuthEngine } from "@/lib/domains/hosting";

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
			!hostedSdkProjectEnabled(
				setting(env, hostedSdkProjectIdsSetting),
				binding.project,
			)
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

		// The gateway verifies the original URL and body before this dispatch.
		url.pathname = `/api/auth/${endpoint}`;
		const nativeRequest = new Request(url, {
			method: bound.method,
			headers: bound.headers,
			body: bound.body,
			duplex: "half",
		} as RequestInit);
		return hostedSdkResponse(
			await engine.dispatch(nativeRequest),
			endpoint,
			url.origin,
			binding.project.slug,
		);
	});
}

export const GET = handle;
export const POST = handle;
