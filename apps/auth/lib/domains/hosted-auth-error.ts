import { getAuthEnvironment } from "../auth";
import { oauthBrowserQuery, oauthBrowserReturnPath } from "../oauth-browser";
import { portalHeader } from "./edge";
import { verifiedHostedOAuthContinuation } from "./hosted-oauth-continuation";
import type { HostedSdkSearchParams } from "./hosted-sdk-policy";
import { hostedSdkReturnPath } from "./hosted-sdk-policy";
import {
	hasHostedSdkSelection,
	hostedSdkSelected,
} from "./hosted-sdk-selection";
import { withPortalHeadersEngine } from "./hosting";
import type { DomainKind } from "./types";

const signIn = "/sign-in";
const providerProof =
	/^(?:token|code|otp|error|errordescription|(?:access|refresh|id|session)token|sig|oauthquery|state)$/i;

function localRetry(callback: string, kind: DomainKind) {
	if (callback.length > 2048 || hostedSdkReturnPath(callback, kind) !== callback)
		return false;
	const target = new URL(callback, "https://allauth.invalid");
	return (
		(!target.hash || /^#[a-z\d_-]{1,100}$/i.test(target.hash)) &&
		![...target.searchParams.keys()].some((name) =>
			providerProof.test(name.replace(/[-_]/g, "")),
		)
	);
}

function retryIntent(params: HostedSdkSearchParams, kind: DomainKind) {
	const callback = params.callbackUrl;
	if (callback !== undefined) {
		if (
			typeof callback !== "string" ||
			params.client_id !== undefined ||
			params.sig !== undefined
		)
			return {};
		const continuation = oauthBrowserReturnPath(callback);
		if (continuation)
			return {
				query: new URL(
					continuation,
					"https://allauth.invalid",
				).searchParams.toString(),
			};
		if (localRetry(callback, kind)) return { callback };
		return {};
	}
	if (typeof params.client_id !== "string" || typeof params.sig !== "string")
		return {};
	const direct = new URLSearchParams();
	for (const [key, value] of Object.entries(params)) {
		if (typeof value === "string") direct.append(key, value);
		else for (const item of value ?? []) direct.append(key, item);
	}
	const query = oauthBrowserQuery(direct);
	return query ? { query: query.toString() } : {};
}

/** Error pages keep safe retry destinations only after proving the exact project realm. */
export async function hostedAuthErrorRetry(
	headers: Headers,
	params: HostedSdkSearchParams,
) {
	if (!headers.has(portalHeader) || params.interface !== undefined)
		return undefined;
	const env = await getAuthEnvironment();
	if (!hasHostedSdkSelection(env)) return undefined;
	return withPortalHeadersEngine(headers, async (engine, _bound, binding) => {
		if (
			!binding ||
			!(await hostedSdkSelected(env, binding.project, binding.kind))
		)
			return undefined;
		const { query, callback } = retryIntent(params, binding.kind);
		if (
			query &&
			(await verifiedHostedOAuthContinuation(engine, binding.hostname, query))
		)
			return `${signIn}?${query}`;
		return callback
			? `${signIn}?${new URLSearchParams({ callbackUrl: callback })}`
			: signIn;
	}).catch(() => undefined);
}
