import { oauthBrowserReturnPath } from "../oauth-browser";
import { hostedSdkReturnPath } from "./hosted-sdk-policy";

const privateFields = new Set([
	"token",
	"tokendigest",
	"otp",
	"backupcodes",
	"totpuri",
	"sessiontoken",
	"accesstoken",
	"refreshtoken",
	"idtoken",
	"bearertoken",
	"privatemetadata",
	"authorization",
	"password",
	"passwordhash",
	"secret",
	"clientsecret",
	"privatekey",
	"encryptedprivatekey",
	"domainverificationtoken",
	"apikey",
]);

function browserValue(value: unknown, depth = 0, stripKey = false): unknown {
	if (depth > 64) return null;
	if (Array.isArray(value))
		return value.map((entry) => browserValue(entry, depth + 1, stripKey));
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.filter(([key]) => {
				const field = key.toLowerCase().replace(/[-_]/g, "");
				return !privateFields.has(field) && (!stripKey || field !== "key");
			})
			.map(([key, entry]) => [key, browserValue(entry, depth + 1, stripKey)]),
	);
}

function hostedPersonalKeyValue(data: unknown, issued: boolean) {
	const clean = browserValue(data, 0, true);
	if (
		!issued ||
		!data ||
		typeof data !== "object" ||
		!("key" in data) ||
		typeof data.key !== "string" ||
		!data.key ||
		!clean ||
		typeof clean !== "object"
	)
		return clean;
	return { ...clean, key: data.key };
}

function record(value: unknown) {
	return value && typeof value === "object" && !Array.isArray(value)
		? (Object.fromEntries(Object.entries(value)) as Record<string, unknown>)
		: {};
}

function linkedAccountValue(value: unknown) {
	const { data, user } = record(value);
	function displayFields(fields: unknown, keys: string[]) {
		return Object.fromEntries(
			Object.entries(record(fields)).filter(
				([key, entry]) =>
					keys.includes(key) &&
					typeof entry === "string" &&
					entry.length <= 512,
			),
		);
	}
	return {
		data: displayFields(data, ["login", "username"]),
		user: displayFields(user, ["email", "name"]),
	};
}

function issuedTotpUri(value: unknown) {
	if (typeof value !== "string" || value.length > 4096) return undefined;
	try {
		const uri = new URL(value);
		const secrets = uri.searchParams.getAll("secret");
		if (
			uri.protocol === "otpauth:" &&
			uri.hostname === "totp" &&
			uri.pathname !== "/" &&
			!uri.username &&
			!uri.password &&
			!uri.port &&
			!uri.hash &&
			secrets.length === 1 &&
			/^[a-z2-7]+=*$/i.test(secrets[0] ?? "")
		)
			return value;
	} catch {
		return undefined;
	}
}

function hostedMfaIssueValue(data: unknown, enrollment: boolean) {
	const { backupCodes, method, status, totpURI } = record(data);
	const codes =
		Array.isArray(backupCodes) &&
		backupCodes.length > 0 &&
		backupCodes.length <= 64 &&
		backupCodes.every(
			(code: unknown) =>
				typeof code === "string" && /^[a-z\d-]{1,128}$/i.test(code),
		)
			? backupCodes
			: undefined;
	const uri = enrollment ? issuedTotpUri(totpURI) : undefined;
	return enrollment
		? {
				...(method === "totp" && { method }),
				...(uri && codes && { totpURI: uri, backupCodes: codes }),
			}
		: {
				...(status === true && {
					status,
					...(codes && { backupCodes: codes }),
				}),
			};
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
		if (endpoint.startsWith("scim/") && response.ok) {
			const input = record(data);
			const visible = record(browserValue(data));
			if (input && visible) {
				if (typeof input.baseURL === "string")
					visible.baseURL = `${origin}/api/auth/scim/v2`;
				if (
					(endpoint === "scim/create" || endpoint === "scim/rotate") &&
					typeof input.token === "string" &&
					input.token
				)
					visible.token = input.token;
				return Response.json(visible, { status: response.status, headers });
			}
		}
		if (
			response.ok &&
			(endpoint === "sso/register" ||
				endpoint === "sso/request-domain-verification") &&
			data &&
			typeof data === "object" &&
			"domainVerificationToken" in data &&
			typeof data.domainVerificationToken === "string"
		) {
			return Response.json(
				{
					...record(browserValue(data)),
					domainVerificationToken: data.domainVerificationToken,
				},
				{ status: response.status, headers },
			);
		}
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
		const value = endpoint.startsWith("api-key/")
			? hostedPersonalKeyValue(
					data,
					endpoint === "api-key/create" && response.ok,
				)
			: response.ok && endpoint === "account-info"
				? linkedAccountValue(data)
				: response.ok &&
						(endpoint === "two-factor/enable" ||
							endpoint === "two-factor/generate-backup-codes")
					? hostedMfaIssueValue(data, endpoint === "two-factor/enable")
					: browserValue(data);
		return Response.json(value, {
			status: response.status,
			headers,
		});
	} catch {
		return hostedSdkFailure(502, "Authentication could not be completed.");
	}
}
