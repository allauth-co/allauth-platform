import { authError } from "@/sdk/helpers";
import { hostedSdkBasePath } from "./hosted-sdk-policy";

type AccountEndpoint =
	| "update-user"
	| "api-key/list"
	| "api-key/create"
	| "api-key/delete";

/** Use the verified accounts gateway for browser operations outside the published SDK types. */
export async function hostedAccountRequest(
	endpoint: AccountEndpoint,
	body?: object,
	signal?: AbortSignal,
): Promise<unknown> {
	const headers = new Headers({ accept: "application/json" });
	if (body) headers.set("content-type", "application/json");
	const response = await fetch(`${hostedSdkBasePath}/${endpoint}`, {
		method: body ? "POST" : "GET",
		headers,
		...(body && { body: JSON.stringify(body) }),
		credentials: "same-origin",
		cache: "no-store",
		redirect: "error",
		signal,
	});
	const result: unknown = await response.json().catch(() => null);
	if (!response.ok) throw new Error(authError(result));
	return result;
}
