const callbackCodes = new Set([
	"AUTHENTICATION_FAILED",
	"ALLAUTH_SECURITY_BLOCKED",
	"account_not_linked",
	"account_ownership_conflict",
	"directory_identity_inactive",
	"directory_provider_mismatch",
	"internal_server_error",
	"invalid_callback_request",
	"invalid_code",
	"invalid_provider",
	"invalid_request",
	"invalid_saml_response",
	"invalid_state",
	"replay_detected",
	"saml_error",
	"state_mismatch",
	"state_not_found",
	"validation_failed",
]);
const failures = new WeakMap<Response, string>();

/** Retain a local failure code without reading redirect URLs or exposing an internal header. */
export function markOwnedCallbackFailure(response: Response, code: string) {
	failures.set(
		response,
		callbackCodes.has(code) ? code : "AUTHENTICATION_FAILED",
	);
	return response;
}

export function ownedCallbackFailureCode(response: Response) {
	return (
		failures.get(response) ??
		(response.status >= 400 ? "AUTHENTICATION_FAILED" : undefined)
	);
}
