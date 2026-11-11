// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import {
	passkeyPlugin as corePasskeyPlugin,
	type PasskeyPluginOptions,
} from "@better-auth-ui/core/plugins/passkey";

import { PasskeyButton } from "@/components/better-auth-ui/passkey/passkey-button";
import { Passkeys } from "@/components/better-auth-ui/passkey/passkeys";

export const passkeyPlugin = createAuthPlugin(
	corePasskeyPlugin.id,
	(options: PasskeyPluginOptions = {}) => ({
		...corePasskeyPlugin(options),
		authButtons: [PasskeyButton],
		securityCards: [Passkeys],
	}),
);
