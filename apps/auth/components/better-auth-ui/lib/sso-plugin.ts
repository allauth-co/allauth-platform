// Adapted from Better Auth UI official radix-nova registry (MIT). See ../ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import { ssoPlugin as coreSsoPlugin } from "@better-auth-ui/core/plugins/sso";
import { EmailFirstSignIn } from "../sso/email-first-sign-in";
declare module "@better-auth-ui/core" {
	interface AuthViewPaths {
		enterpriseSSO?: string;
	}
}
// Keep existing username/email sign-in and organization directory management.
export const ssoPlugin = createAuthPlugin(coreSsoPlugin.id, () => ({
	...coreSsoPlugin({ emailFirst: false, organization: false }),
	viewPaths: { auth: { enterpriseSSO: "enterprise-sign-in" } },
	views: { auth: { enterpriseSSO: EmailFirstSignIn } },
}));
