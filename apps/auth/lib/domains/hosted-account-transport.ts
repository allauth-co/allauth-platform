import { authError } from "@/sdk/helpers";
import { hostedSdkBasePath } from "./hosted-sdk-policy";

type AccountEndpoint =
	| "update-user"
	| "api-key/list"
	| "api-key/create"
	| "api-key/delete"
	| "account-info"
	| "delete-user"
	| "unlink-account"
	| "sso/providers"
	| "sso/register"
	| "sso/update-provider"
	| "sso/request-domain-verification"
	| "sso/verify-domain"
	| "sso/delete-provider";

/** Use the verified accounts gateway for browser operations outside the published SDK types. */
export async function hostedAccountRequest(
	endpoint: AccountEndpoint,
	body?: object,
	signal?: AbortSignal,
	query?: URLSearchParams,
): Promise<unknown> {
	const headers = new Headers({ accept: "application/json" });
	if (body) headers.set("content-type", "application/json");
	const path = `${hostedSdkBasePath}/${endpoint}${query?.size ? `?${query}` : ""}`;
	const response = await fetch(path, {
		method: body ? "POST" : "GET",
		headers,
		...(body && { body: JSON.stringify(body) }),
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
		signal,
	});
	const result: unknown = await response.json().catch(() => null);
	if (!response.ok) {
		const code =
			result &&
			typeof result === "object" &&
			"code" in result &&
			typeof result.code === "string"
				? result.code
				: undefined;
		throw Object.assign(new Error(authError(result)), { code });
	}
	return result;
}
