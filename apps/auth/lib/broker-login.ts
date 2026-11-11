import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import type { AuthInstance } from "./api";
import { authConfiguration, authOrigin } from "./configuration";
import type { AuthEnvironment } from "./configuration";

/** Validate the native authorization request before choosing a platform login strategy. */
export async function brokerLogin(request: Request, instance: AuthInstance, env: AuthEnvironment): Promise<Response> {
	const query = new URL(request.url).searchParams;
	const serialized = query.toString();
	if (!(await verifyOAuthQueryParams(serialized, (await instance.$context).secret))) throw new APIError("BAD_REQUEST", { message: "The authorization request is invalid or expired." });
	const clientId = query.get("client_id");
	if (!clientId || query.getAll("client_id").length !== 1 || query.getAll("redirect_uri").length !== 1) throw new APIError("BAD_REQUEST", { message: "The authorization request contains invalid client fields." });
	await instance.api.getOAuthClientPublicPrelogin({ headers: request.headers, body: { client_id: clientId, oauth_query: serialized } });
	const origin = authOrigin(env);
	const hints = query.getAll("idp_hint");
	const responseHeaders = new Headers({ "Cache-Control": "no-store", Pragma: "no-cache", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" });
	if (!hints.length) {
		responseHeaders.set("Location", `${origin}/sign-in?${serialized}`);
		return new Response(null, { status: 302, headers: responseHeaders });
	}
	if (hints.length !== 1 || hints[0] !== "google" || !query.getAll("ba_param").includes("idp_hint")) throw new APIError("BAD_REQUEST", { message: "The requested sign-in provider is invalid." });
	if (!authConfiguration(env).google) throw new APIError("BAD_REQUEST", { message: "Google sign-in is not available." });
	// This is a server-owned initiation after signed-request and native-client
	// validation. Outer cross-site navigation metadata is not a native POST.
	const nativeHeaders = new Headers({ Origin: origin, "Content-Type": "application/json", Accept: "application/json" });
	for (const name of ["cookie", "user-agent", "x-real-ip"]) {
		const value = request.headers.get(name);
		if (value) nativeHeaders.set(name, value);
	}
	const native = await instance.handler(new Request(`${origin}/api/auth/sign-in/social`, {
		method: "POST",
		headers: nativeHeaders,
		body: JSON.stringify({ provider: "google", oauth_query: serialized, callbackURL: `${origin}/oauth2/continue?${serialized}`, errorCallbackURL: `${origin}/auth-error`, disableRedirect: true }),
	}));
	// Keep the native handler's rate-limit and security rejection authoritative.
	if (!native.ok) throw new APIError(native.status === 429 ? "TOO_MANY_REQUESTS" : "BAD_GATEWAY", { message: "Google sign-in could not be started. Please try again." });
	const result: unknown = await native.json();
	if (!result || typeof result !== "object" || !("url" in result) || typeof result.url !== "string") throw new APIError("BAD_GATEWAY", { message: "Google sign-in returned no authorization destination." });
	const destination = new URL(result.url);
	if (destination.origin !== "https://accounts.google.com" || destination.pathname !== "/o/oauth2/v2/auth" || destination.username || destination.password || destination.hash || destination.searchParams.get("redirect_uri") !== `${origin}/api/auth/callback/google`) throw new APIError("BAD_GATEWAY", { message: "Google sign-in returned an invalid authorization destination." });
	for (const cookie of native.headers.getSetCookie()) responseHeaders.append("Set-Cookie", cookie);
	responseHeaders.set("Location", destination.href);
	return new Response(null, { status: 302, headers: responseHeaders });
}
