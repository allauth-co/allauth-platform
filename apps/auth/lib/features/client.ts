import { agentAuthClient } from "@better-auth/agent-auth/client";
import { i18nClient } from "@better-auth/i18n/client";
import { oauthDeviceAuthorizationClient } from "@better-auth/oauth-provider/client";
import {
	anonymousClient,
	oneTapClient,
	oneTimeTokenClient,
	siweClient,
	usernameClient,
} from "better-auth/client/plugins";

/** Extra browser methods use the same cookie-authenticated client; no bearer plugin is exposed. */
export function extraClientPlugins(
	options: { googleClientId?: string; project?: boolean } = {},
) {
	return [
		usernameClient(),
		anonymousClient(),
		oneTimeTokenClient(),
		siweClient(),
		i18nClient(),
		agentAuthClient(),
		oauthDeviceAuthorizationClient(),
		...(!options.project && options.googleClientId
			? ([
					oneTapClient({ clientId: options.googleClientId, autoSelect: false }),
				] as const)
			: ([] as const)),
	] as const;
}
