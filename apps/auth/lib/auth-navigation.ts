import {
	consoleReturnFromSearch,
	isAccountNavigationPath,
} from "@/lib/console/user-menu-navigation";
import { isAuthenticationPath } from "@/lib/hosted-portal-paths";

export { isAuthenticationPath } from "@/lib/hosted-portal-paths";

/** Registry links stay on this service; signed authorization parameters survive auth view changes. */
export function localNavigation(
	to: string,
	origin: string,
	current: URLSearchParams,
): string | null {
	if (!to || to.includes("\\") || to.startsWith("//")) return null;
	let target: URL;
	try {
		target = new URL(to, origin);
	} catch {
		return null;
	}
	if (target.origin !== origin || target.username || target.password)
		return null;
	if (target.pathname === "/account/account") target.pathname = "/account";
	if (
		!isAuthenticationPath(target.pathname) &&
		!/^\/(account|organizations|organization|admin|accept-invitation|device|oauth2\/continue)(\/|$)/.test(
			target.pathname,
		) &&
		target.pathname !== "/" &&
		target.pathname !== "/console"
	)
		return null;
	// Only preserve validated account and signed authorization continuations.
	target.searchParams.delete("redirectTo");
	const consoleReturnTo = consoleReturnFromSearch(
		target.searchParams.has("consoleReturnTo") ? target.searchParams : current,
	);
	target.searchParams.delete("consoleReturnTo");
	if (isAccountNavigationPath(target.pathname) && consoleReturnTo)
		target.searchParams.set("consoleReturnTo", consoleReturnTo);
	if (isAuthenticationPath(target.pathname)) {
		if (current.has("client_id")) {
			// Authorization extensions can share account-menu parameter names.
			// Preserve the provider's values and cardinality so its signature stays valid.
			const keys = new Set(
				Array.from(current.keys()).filter(
					(key) =>
						!["redirectTo", "token", "code", "otp", "error"].includes(key),
				),
			);
			for (const key of keys) target.searchParams.delete(key);
			for (const [key, value] of current) {
				if (keys.has(key)) target.searchParams.append(key, value);
			}
		} else if (current.has("callbackUrl"))
			target.searchParams.set("callbackUrl", current.get("callbackUrl") || "");
	}
	return `${target.pathname}${target.search}${target.hash}`;
}
