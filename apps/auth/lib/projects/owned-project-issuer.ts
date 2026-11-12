import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectIssuerAuthorizationOptions } from "./owned-project-issuer-authorization";
import { createOwnedProjectIssuerAuthorization } from "./owned-project-issuer-authorization";
import { createOwnedProjectIssuerDevice } from "./owned-project-issuer-device";
import { issuerJSON } from "./owned-project-issuer-http";
import { createOwnedProjectIssuerIntrospection } from "./owned-project-issuer-introspection";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import type { OwnedProjectIssuerLogoutOptions } from "./owned-project-issuer-logout";
import { createOwnedProjectIssuerLogout } from "./owned-project-issuer-logout";
import { createOwnedProjectIssuerToken } from "./owned-project-issuer-token";
import { createOwnedProjectIssuerUserInfo } from "./owned-project-issuer-userinfo";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";

const providerAdmission = new Map<string, { methods: string[]; max: number }>([
	["/oauth2/token", { methods: ["POST"], max: 20 }],
	["/oauth2/authorize", { methods: ["GET", "POST"], max: 30 }],
	["/oauth2/introspect", { methods: ["POST"], max: 100 }],
	["/oauth2/revoke", { methods: ["POST"], max: 30 }],
	["/oauth2/userinfo", { methods: ["GET", "POST"], max: 60 }],
	["/oauth2/continue", { methods: ["POST"], max: 100 }],
	["/oauth2/consent", { methods: ["POST"], max: 100 }],
	["/oauth2/end-session", { methods: ["GET", "POST"], max: 100 }],
	["/oauth2/end-session/confirm", { methods: ["POST"], max: 100 }],
	["/jwks", { methods: ["GET"], max: 100 }],
]);

export function createOwnedProjectIssuer(
	options: OwnedProjectIssuerAuthorizationOptions & {
		keys: LegacyMfaKeys;
		projectSlug: string;
		platformOrigin: string;
		trustedIP(request: Request): string | null;
		logout: Pick<
			OwnedProjectIssuerLogoutOptions,
			"sessionCookie" | "revokeSession" | "clearBrowserSession"
		>;
	},
) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	const authorization = createOwnedProjectIssuerAuthorization(options);
	const device = createOwnedProjectIssuerDevice(options);
	const logout = createOwnedProjectIssuerLogout({
		...options,
		...options.logout,
	});
	const keyring = createOwnedProjectIssuerKeys(options);
	const token = createOwnedProjectIssuerToken(options);
	const { activeAccess, introspect, revoke } =
		createOwnedProjectIssuerIntrospection(options);
	const userinfo = createOwnedProjectIssuerUserInfo({
		...options,
		activeAccess,
	});
	async function dispatch(path: string, request: Request) {
		const rule = providerAdmission.get(path);
		if (rule?.methods.includes(request.method)) {
			const denied = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: rule.max,
					windowMs: 60_000,
				}),
			);
			if (denied) return denied;
		}
		if (path === "/jwks" && request.method === "GET")
			return issuerJSON(await keyring.publicKeys());
		if (path === "/oauth2/token" && request.method === "POST")
			return token(request);
		if (path === "/oauth2/introspect" && request.method === "POST")
			return introspect(request);
		if (path === "/oauth2/revoke" && request.method === "POST")
			return revoke(request);
		if (path === "/oauth2/userinfo" && ["GET", "POST"].includes(request.method))
			return userinfo(request);
		return (
			(await authorization(path, request)) ??
			(await logout(path, request)) ??
			device(path, request)
		);
	}
	return { dispatch, readContext: authorization.readContext };
}
