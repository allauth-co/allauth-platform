import type { AllAuthSession } from "@/sdk/client";
import { authError } from "@/sdk/helpers";
import { hostedSdkBasePath } from "./hosted-sdk-policy";

/** This field is supplied by the native hosted browser session, when applicable. */
export function hostedImpersonatingActor(session: AllAuthSession | null) {
	const fields = session?.session;
	return fields &&
		"impersonatedBy" in fields &&
		typeof fields.impersonatedBy === "string" &&
		fields.impersonatedBy
		? fields.impersonatedBy
		: null;
}

/** End an existing native hosted impersonation and verify the restored account. */
export async function stopHostedImpersonation(actorId: string) {
	const response = await fetch(
		`${hostedSdkBasePath}/admin/stop-impersonating`,
		{
			method: "POST",
			headers: {
				accept: "application/json",
				"content-type": "application/json",
			},
			body: "{}",
			credentials: "same-origin",
			cache: "no-store",
			redirect: "error",
		},
	);
	const result: unknown = await response.json().catch(() => null);
	if (!response.ok) throw new Error(authError(result));
	if (
		!result ||
		typeof result !== "object" ||
		!("user" in result) ||
		!result.user ||
		typeof result.user !== "object" ||
		!("id" in result.user) ||
		result.user.id !== actorId ||
		!("session" in result) ||
		!result.session ||
		typeof result.session !== "object" ||
		!("id" in result.session) ||
		typeof result.session.id !== "string" ||
		("impersonatedBy" in result.session && result.session.impersonatedBy)
	)
		throw new Error("The original account could not be confirmed.");
}
