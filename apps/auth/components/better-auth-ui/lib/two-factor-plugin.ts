// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import {
	twoFactorPlugin as coreTwoFactorPlugin,
	type TwoFactorPluginOptions,
} from "@better-auth-ui/core/plugins/two-factor";

import { TwoFactorChallenge } from "@/components/better-auth-ui/two-factor/two-factor-challenge";
import { TwoFactorSettings } from "@/components/better-auth-ui/two-factor/two-factor-settings";

export const twoFactorPlugin = createAuthPlugin(
	coreTwoFactorPlugin.id,
	(options: TwoFactorPluginOptions = {}) => ({
		...coreTwoFactorPlugin(options),
		securityCards: [TwoFactorSettings],
		views: {
			auth: { twoFactor: TwoFactorChallenge },
		},
	}),
);
