// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
import { createAuthPlugin } from "@better-auth-ui/core";
import {
	deleteUserPlugin as coreDeleteUserPlugin,
	type DeleteUserPluginOptions,
} from "@better-auth-ui/core/plugins/delete-user";

import { DangerZone } from "@/components/better-auth-ui/delete-user/danger-zone";

export const deleteUserPlugin = createAuthPlugin(
	coreDeleteUserPlugin.id,
	(options: DeleteUserPluginOptions = {}) => ({
		...coreDeleteUserPlugin(options),
		securityCards: [DangerZone],
	}),
);
