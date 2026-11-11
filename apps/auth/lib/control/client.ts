import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { allauthControl } from "./index";

/** Typed browser bindings for the self-hosted AllAuth control-plane endpoints. */
export function allauthControlClient() {
	return {
		id: "allauth-control", version: "1.0.0",
		$InferServerPlugin: {} as ReturnType<typeof allauthControl>,
		pathMethods: {
			"/control/overview": "GET", "/control/events": "GET", "/control/sessions": "GET", "/control/revoke-session": "POST",
			"/control/analytics": "GET", "/control/analytics/entities": "GET",
			"/control/security": "GET", "/control/security/update": "POST", "/control/security/rules/add": "POST", "/control/security/rules/remove": "POST",
			"/control/webhooks": "GET", "/control/webhooks/create": "POST", "/control/webhooks/rotate": "POST", "/control/webhooks/delete": "POST", "/control/webhooks/deliveries": "GET", "/control/webhooks/retry": "POST",
		},
	} satisfies BetterAuthClientPlugin;
}
