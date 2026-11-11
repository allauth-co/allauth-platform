/** Managed public clients work with DCR disabled; advertise their supported auth method. */
export function discoveryDocument<T extends { token_endpoint_auth_methods_supported?: string[] }>(document: T) {
	return { ...document, token_endpoint_auth_methods_supported: [...new Set([...(document.token_endpoint_auth_methods_supported || []), "none"])] };
}
export const discoveryHeaders = { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" };
