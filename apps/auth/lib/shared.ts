import type { ReadonlyURLSearchParams } from "next/navigation";
import { authClient } from "./auth-client";
import { deviceProject } from "./features/device";
export function getCallbackURL(
	params: ReadonlyURLSearchParams | URLSearchParams,
): string {
	const path = params.get("callbackUrl");
	// The server entry resolves the authenticated realm: Console on AllAuth,
	// account settings on customer portals. Explicit callbacks remain authoritative.
	if (!path) return "/console";
	if (
		path &&
		path.startsWith("/") &&
		!path.startsWith("//") &&
		!path.includes("\\")
	) {
		const target = new URL(path, "https://allauth.co");
		if (target.origin === "https://allauth.co" && target.pathname === "/console" && path.split(/[?#]/, 1)[0] === target.pathname && !target.hash) return `${target.pathname}${target.search}`;
		if (target.origin === "https://allauth.co" && target.pathname === "/admin/workspaces" && !target.hash) return `${target.pathname}${target.search}`;
		if (target.origin === "https://allauth.co" && target.pathname === "/device" && !target.hash) {
			const selections = target.searchParams.getAll("project");
			try { deviceProject(selections.length === 1 ? selections[0] : selections.length ? selections : undefined); } catch { return "/account"; }
			return `${target.pathname}${target.search}`;
		}
		if (
			target.origin === "https://allauth.co" &&
			/^\/(account|organizations|accept-invitation)(\/|$)/.test(target.pathname)
		)
			return `${target.pathname}${target.search}${target.hash}`;
	}
	return "/account";
}
/** The OAuth provider verifies its signed query before continuing authorization. */
export async function completeAuthentication(
	params: ReadonlyURLSearchParams | URLSearchParams,
	primaryResponse?: unknown,
) {
	// Native authentication hooks may have already completed OAuth and returned
	// its redirect in the factor/primary response. The client follows it itself.
	if (primaryResponse && typeof primaryResponse === "object" &&
		"redirect" in primaryResponse && primaryResponse.redirect === true &&
		"url" in primaryResponse && typeof primaryResponse.url === "string") return;
	// The client plugin navigates to the native challenge. Never race it with an
	// account redirect or an OAuth continuation before verification has completed.
	if (
		primaryResponse &&
		typeof primaryResponse === "object" &&
		"twoFactorRedirect" in primaryResponse &&
		primaryResponse.twoFactorRedirect === true
	)
		return;
	if (params.has("client_id")) {
		const { data, error } = await authClient.oauth2.continue({
			selected: true,
		});
		if (error)
			throw new Error(error.message || "Unable to continue authorization");
		if (!data?.redirect || !data.url)
			throw new Error("The authorization server returned no continuation");
		// The native client's redirect plugin follows this one-use authorization
		// result. A second navigation can race it and redeem the same code twice.
		return;
	}
	window.location.assign(getCallbackURL(params));
}
export function errorMessage(error: unknown) {
	return error instanceof Error
		? error.message
		: "The request could not be completed";
}

export async function authenticationCallback(
	params: ReadonlyURLSearchParams | URLSearchParams,
): Promise<string> {
	if (!params.has("client_id"))
		return new URL(getCallbackURL(params), window.location.origin).href;
	const response = await fetch(`/api/oauth/context?${params.toString()}`, {
		cache: "no-store",
	});
	const context: { continueURL?: string; error?: string } =
		await response.json();
	if (!response.ok || !context.continueURL)
		throw new Error(
			context.error || "The authorization request has expired or is invalid",
		);
	const target = new URL(context.continueURL, window.location.origin);
	if (
		target.origin !== window.location.origin ||
		target.pathname !== "/oauth2/continue"
	)
		throw new Error("Invalid authorization continuation");
	return target.href;
}
