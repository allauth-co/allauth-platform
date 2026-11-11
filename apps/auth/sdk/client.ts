import {
	organizationClient,
	twoFactorClient,
} from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import { passkeyClient } from "@better-auth/passkey/client";
import { proxyBasePath } from "./helpers";
import sdkPackage from "./package.json";

const organizationReadPaths = new Set([
	"/organization/has-permission", "/organization/check-slug",
	"/organization/get-full-organization", "/organization/get-organization",
	"/organization/get-active-member", "/organization/get-active-member-role",
	"/organization/get-invitation", "/organization/get-role",
	"/organization/list", "/organization/list-members",
	"/organization/list-invitations", "/organization/list-user-invitations",
	"/organization/list-roles", "/organization/list-teams",
	"/organization/list-user-teams", "/organization/list-team-members",
]);

/** Create a native client that can only send requests through the app's own proxy. */
export function createAllAuthClient(
	basePath: string,
	onTwoFactorRedirect: (methods?: string[]) => void,
) {
	const path = proxyBasePath(basePath);
	const origin =
		typeof window === "undefined" ? "http://localhost" : window.location.origin;
	const organization = organizationClient({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } });
	return createAuthClient({
		baseURL: `${origin}${path}`,
		fetchOptions: {
			credentials: "same-origin",
			cache: "no-store",
			customFetchImpl: async (input, init) => {
				const url = new URL(
					input instanceof Request ? input.url : String(input),
					origin,
				);
				const appOrigin =
					typeof window === "undefined" ? origin : window.location.origin;
				if (
					url.origin !== appOrigin ||
					!(url.pathname === path || url.pathname.startsWith(`${path}/`))
				)
					throw new Error(
						"AllAuth requests must use the app's same-origin proxy.",
					);
				const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
				headers.set("x-allauth-sdk-version", sdkPackage.version);
				return fetch(input, {
					...init,
					headers,
					credentials: "same-origin",
					cache: "no-store",
				});
			},
		},
		plugins: [
			passkeyClient(),
			{ ...organization, atomListeners: [
				...organization.atomListeners.map((listener) => ({
					...listener,
					// Native reads cannot change the organisation. In particular, the
					// profile's permission checks must not each reload its active-org hook.
					matcher: (path: string) => !organizationReadPaths.has(path) && listener.matcher(path),
				})),
				{ matcher: (path: string) => path === "/organization/accept-invitation", signal: "$listOrg" },
			] },
			twoFactorClient({
				onTwoFactorRedirect: ({ twoFactorMethods }) =>
					onTwoFactorRedirect(twoFactorMethods),
			}),
		],
	});
}

export type AllAuthClient = ReturnType<typeof createAllAuthClient>;
