import { oauthBrowserReturnPath } from "../oauth-browser";
import { hostedSdkReturnPath } from "./hosted-sdk-policy";

const privateFields = new Set([
	"token",
	"otp",
	"backupcodes",
	"sessiontoken",
	"accesstoken",
	"refreshtoken",
	"idtoken",
	"bearertoken",
	"privatemetadata",
	"authorization",
	"password",
	"passwordhash",
	"clientsecret",
	"privatekey",
	"encryptedprivatekey",
	"apikey",
]);

function browserValue(value: unknown, depth = 0): unknown {
	if (depth > 64) return null;
	if (Array.isArray(value))
		return value.map((entry) => browserValue(entry, depth + 1));
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.filter(
				([key]) => !privateFields.has(key.toLowerCase().replace(/[-_]/g, "")),
			)
			.map(([key, entry]) => [key, browserValue(entry, depth + 1)]),
	);
}

export function hostedSdkFailure(status: number, message: string) {
	return Response.json(
		{ error: { message } },
		{ status, headers: { "cache-control": "no-store" } },
	);
}

function ownCookies(response: Response, slug: string) {
	const prefix = `allauth_project_${slug}.`;
	return response.headers
		.getSetCookie()
		.filter((cookie) =>
			cookie
				.split("=", 1)[0]
				?.replace(/^__Secure-/, "")
				.startsWith(prefix),
		)
		.map((cookie) => cookie.replace(/;\s*Domain=[^;]*/gi, ""));
}

function hasPendingFactor(cookies: string[], slug: string) {
	const prefix = `allauth_project_${slug}.two_factor=`;
	return cookies.some((cookie) => {
		const pair = cookie.split(";", 1)[0]?.replace(/^__Secure-/, "");
		return (
			pair?.startsWith(prefix) &&
			pair.length > prefix.length &&
			!/;\s*max-age=0(?:;|$)/i.test(cookie)
		);
	});
}

/** Preserve verified hosted cookies and translate native MFA into the v2 browser contract. */
export async function hostedSdkResponse(
	response: Response,
	endpoint: string,
	origin: string,
	slug: string,
) {
	const headers = new Headers({
		"cache-control": "no-store",
		pragma: "no-cache",
		"x-content-type-options": "nosniff",
	});
	const retryAfter = response.headers.get("retry-after");
	if (retryAfter) headers.set("retry-after", retryAfter);
	const cookies = ownCookies(response, slug);
	for (const cookie of cookies) headers.append("set-cookie", cookie);

	const location = response.headers.get("location");
	if (
		response.status === 302 &&
		location &&
		(endpoint === "sign-in/email" ||
			endpoint === "sign-in/username" ||
			endpoint === "sign-in/email-otp" ||
			endpoint === "passkey/verify-authentication") &&
		hasPendingFactor(cookies, slug)
	) {
		try {
			const target = new URL(location, origin);
			const callback = target.searchParams.get("callbackUrl");
			if (
				target.origin === origin &&
				!target.username &&
				!target.password &&
				target.pathname === "/two-factor" &&
				!target.hash &&
				[...target.searchParams.keys()].every(
					(name) => name === "callbackUrl",
				) &&
				target.searchParams.getAll("callbackUrl").length <= 1 &&
				(callback === null ||
					hostedSdkReturnPath(callback) === callback ||
					oauthBrowserReturnPath(callback) === callback)
			) {
				return Response.json({ twoFactorRedirect: true }, { headers });
			}
		} catch {
			/* An unrecognized native continuation is handled below. */
		}
	}
	if (response.status >= 300 && response.status < 400)
		return hostedSdkFailure(502, "Use the other sign-in options to continue.");
	if (response.status === 204 || response.status === 205)
		return new Response(null, { status: response.status, headers });
	if (!response.headers.get("content-type")?.includes("application/json"))
		return Response.json(
			{ error: { message: "Authentication could not be completed." } },
			{
				status: response.ok ? 502 : response.status,
				headers,
			},
		);

	try {
		const data: unknown = await response.json();
		// The hosted page has a dedicated AllAuth broker control, independent of Google readiness.
		if (
			endpoint === "sdk/config" &&
			data &&
			typeof data === "object" &&
			"googleProvider" in data &&
			data.googleProvider === "allauth"
		) {
			return Response.json(
				browserValue({ ...data, google: false, googleProvider: null }),
				{ status: response.status, headers },
			);
		}
		return Response.json(browserValue(data), {
			status: response.status,
			headers,
		});
	} catch {
		return hostedSdkFailure(502, "Authentication could not be completed.");
	}
}
