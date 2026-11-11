import { apiKeyClient } from "@better-auth/api-key/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { ssoClient } from "@better-auth/sso/client";
import {
	adminClient,
	customSessionClient,
	emailOTPClient,
	lastLoginMethodClient,
	magicLinkClient,
	multiSessionClient,
	organizationClient,
	twoFactorClient,
} from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import type { auth } from "./auth";
import { allauthControlClient } from "./control/client";
import { extraClientPlugins } from "./features/client";

export function makeAuthClient(options: { basePath?: string; customFetchImpl?: typeof fetch } = {}) { return createAuthClient({
	basePath: options.basePath,
	fetchOptions: options.customFetchImpl ? { customFetchImpl: options.customFetchImpl } : undefined,
	plugins: [
		...extraClientPlugins({ project: Boolean(options.basePath?.startsWith("/api/projects/")) }),
		allauthControlClient(),
		adminClient(),
		organizationClient({
			teams: { enabled: true },
			dynamicAccessControl: { enabled: true },
		}),
		twoFactorClient({
			onTwoFactorRedirect() {
				window.location.href = `/two-factor${window.location.search}`;
			},
		}),
		passkeyClient(),
		multiSessionClient(),
		ssoClient({ domainVerification: { enabled: true } }),
		oauthProviderClient(),
		customSessionClient<typeof auth>(),
		lastLoginMethodClient(),
		magicLinkClient(),
		emailOTPClient(),
		apiKeyClient(),
	],
}); }
export const authClient = makeAuthClient();
