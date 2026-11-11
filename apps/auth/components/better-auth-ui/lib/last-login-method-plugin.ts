// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import {
	lastLoginMethodPlugin as coreLastLoginMethodPlugin,
	type LastLoginMethodPluginOptions,
} from "@better-auth-ui/core/plugins/last-login-method";

export const lastLoginMethodPlugin = createAuthPlugin(
	coreLastLoginMethodPlugin.id,
	(options: LastLoginMethodPluginOptions = {}) => ({
		...coreLastLoginMethodPlugin(options),
	}),
);
