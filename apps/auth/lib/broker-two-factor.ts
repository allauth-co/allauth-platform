import type { GenericEndpointContext } from "@better-auth/core";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import {
	constantTimeEqual,
	symmetricDecrypt,
	symmetricEncrypt,
} from "better-auth/crypto";
import * as z from "zod";
import type { AuthInstance } from "./api";

const opaque = z.string().regex(/^[a-f0-9]{64}$/);
const identitySchema = z.object({
	clientId: z.string(),
	slug: z.string(),
	origin: z.string().url(),
});
const pendingSchema = z.object({
	identity: identitySchema,
	bindingHash: opaque,
	query: z.string(),
	cookie: z.string(),
	cookieName: z.string(),
	verificationCookies: z.string(),
});
const receiptSchema = z.object({
	cookie: z.string(),
	cookieName: z.string(),
	cookies: z.array(z.string()),
	origin: z.string().url(),
	query: z.string(),
});
export const brokerTwoFactorInput = z
	.object({
		ticket: opaque,
		binding: opaque,
		code: z.string().min(1).max(128),
		method: z.enum(["totp", "backup"]),
	})
	.strict();
type Identity = z.infer<typeof identitySchema>;
type Client = {
	disabled?: boolean;
	redirectUris: string[];
	metadata?: unknown;
};
const lifetime = 5 * 60 * 1000;
const random = () =>
	Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
const hash = async (value: string) =>
	Array.from(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
		),
		(byte) => byte.toString(16).padStart(2, "0"),
	).join("");
const cookiePair = (cookie: string) => cookie.split(";", 1)[0]!;
const namedCookie = (header: string, name: string) => {
	const matches = header
		.split(";")
		.map((value) => value.trim())
		.filter((value) => value.startsWith(`${name}=`));
	return matches.length === 1 ? matches[0] : undefined;
};

function brokerMetadata(client: Client): Record<string, unknown> | undefined {
	try {
		const metadata: unknown =
			typeof client.metadata === "string"
				? JSON.parse(client.metadata)
				: client.metadata;
		return metadata && typeof metadata === "object" && !Array.isArray(metadata)
			? (metadata as Record<string, unknown>)
			: undefined;
	} catch {
		return;
	}
}

/** Continue JSON-based primary sign-ins from the hosted page using a live signed pending cookie. */
export function brokerTwoFactorBrowserEndpoint() {
	return createAuthEndpoint(
		"/broker-two-factor/browser-handoff",
		{
			method: "GET",
			requireHeaders: true,
			query: z.object({ oauth_query: z.string().max(16_384) }),
		},
		async (ctx) => {
			ctx.setHeader("Cache-Control", "no-store");
			ctx.setHeader("Referrer-Policy", "no-referrer");
			const query = new URLSearchParams(ctx.query.oauth_query);
			if (query.get("allauth_mfa") !== "app-v1") return ctx.json({ url: null });
			const name = ctx.context.createAuthCookie("two_factor").name;
			const identifier = await ctx.getSignedCookie(name, ctx.context.secret);
			if (!identifier) return ctx.json({ url: null });
			const pending =
				await ctx.context.internalAdapter.findVerificationValue(identifier);
			if (!pending || pending.expiresAt.getTime() <= Date.now())
				return ctx.json({ url: null });
			const cookie = namedCookie(ctx.headers.get("cookie") || "", name);
			if (!cookie) return ctx.json({ url: null });
			// The HTTP callback path receives this cookie from native MFA's response;
			// the page continuation instead proves it against the signed live challenge.
			const responseHeaders = new Headers({ "set-cookie": cookie });
			const url = await brokerTwoFactorHandoff(ctx, query, responseHeaders);
			return ctx.json({ url: url || null });
		},
	);
}

/** Only a signed, registered BFF authorization request may opt into an app challenge. */
export async function brokerTwoFactorHandoff(
	ctx: GenericEndpointContext,
	query: URLSearchParams,
	responseHeaders: Headers | undefined,
): Promise<string | undefined> {
	const signed = query.getAll("ba_param");
	if (
		query.getAll("allauth_mfa").length !== 1 ||
		query.get("allauth_mfa") !== "app-v1" ||
		!signed.includes("allauth_mfa") ||
		!signed.includes("allauth_mfa_binding") ||
		query.getAll("allauth_mfa_binding").length !== 1 ||
		!opaque.safeParse(query.get("allauth_mfa_binding")).success
	)
		return;
	if (!(await verifyOAuthQueryParams(query.toString(), ctx.context.secret)))
		return;
	const clientId = query.get("client_id");
	if (
		!clientId ||
		query.getAll("client_id").length !== 1 ||
		query.getAll("redirect_uri").length !== 1
	)
		return;
	const client = await ctx.context.adapter.findOne<Client>({
		model: "oauthClient",
		where: [{ field: "clientId", value: clientId }],
	});
	if (
		!client ||
		client.disabled ||
		!client.redirectUris.includes(query.get("redirect_uri") || "")
	)
		return;
	const metadata = brokerMetadata(client);
	if (
		typeof metadata?.allauthProjectBroker !== "string" ||
		typeof metadata.allauthWorkspaceId !== "string"
	)
		return;
	const callback = new URL(query.get("redirect_uri")!);
	// Hosted portals and other OAuth clients retain their existing challenge.
	if (
		callback.pathname !== "/api/allauth/callback/allauth" ||
		callback.search ||
		callback.hash ||
		callback.username ||
		callback.password ||
		!(
			callback.protocol === "https:" ||
			(callback.protocol === "http:" &&
				["localhost", "127.0.0.1", "[::1]"].includes(callback.hostname))
		)
	)
		return;
	const cookieName = ctx.context.createAuthCookie("two_factor").name;
	const cookie = responseHeaders
		?.getSetCookie()
		.find((value) => value.startsWith(`${cookieName}=`));
	if (!cookie || !cookiePair(cookie).slice(cookieName.length + 1)) return;
	const rememberName = ctx.context.authCookies.dontRememberToken.name;
	const outgoingRemember = responseHeaders
		?.getSetCookie()
		.filter((value) => value.startsWith(`${rememberName}=`))
		.at(-1);
	const remember = outgoingRemember
		? /;\s*Max-Age=0(?:;|$)/i.test(outgoingRemember)
			? undefined
			: cookiePair(outgoingRemember)
		: namedCookie(ctx.headers?.get("cookie") || "", rememberName);
	const ticket = random();
	const data: z.infer<typeof pendingSchema> = {
		identity: {
			clientId,
			slug: metadata.allauthProjectBroker,
			origin: callback.origin,
		},
		bindingHash: query.get("allauth_mfa_binding")!,
		query: query.toString(),
		cookie: cookiePair(cookie),
		cookieName,
		verificationCookies: [cookiePair(cookie), remember]
			.filter(Boolean)
			.join("; "),
	};
	await ctx.context.internalAdapter.createVerificationValue({
		identifier: `broker-mfa:${await hash(ticket)}`,
		value: await symmetricEncrypt({
			key: ctx.context.secretConfig,
			data: JSON.stringify(data),
		}),
		expiresAt: new Date(Date.now() + lifetime),
	});
	return `${callback.origin}/api/allauth/broker-two-factor/accept?ticket=${ticket}`;
}

/** Called only after verifying the application's signed proxy transport, with its stored broker identity. */
export async function verifyBrokerTwoFactor(
	instance: AuthInstance,
	origin: string,
	identity: Identity,
	input: z.infer<typeof brokerTwoFactorInput>,
	incoming: Headers,
	dispatchFactor?: (request: Request) => Promise<Response>,
): Promise<{ url: string }> {
	const body = brokerTwoFactorInput.parse(input);
	const context = await instance.$context;
	const key = `broker-mfa:${await hash(body.ticket)}`;
	const row = await context.internalAdapter.findVerificationValue(key);
	if (!row || row.expiresAt.getTime() <= Date.now())
		throw new APIError("UNAUTHORIZED", {
			message: "This sign-in has expired. Start again.",
		});
	const pending = pendingSchema.parse(
		JSON.parse(
			await symmetricDecrypt({ key: context.secretConfig, data: row.value }),
		),
	);
	if (
		pending.identity.clientId !== identity.clientId ||
		pending.identity.slug !== identity.slug ||
		pending.identity.origin !== identity.origin ||
		!constantTimeEqual(pending.bindingHash, await hash(body.binding))
	)
		throw new APIError("FORBIDDEN");
	// Recheck client revocation/redirect registration before verifying the factor.
	const query = new URLSearchParams(pending.query);
	await instance.api.getOAuthClientPublicPrelogin({
		body: { client_id: identity.clientId, oauth_query: pending.query },
		headers: new Headers(),
	});
	const client = await context.adapter.findOne<Client>({
		model: "oauthClient",
		where: [{ field: "clientId", value: identity.clientId }],
	});
	if (
		!client ||
		client.disabled ||
		brokerMetadata(client)?.allauthProjectBroker !== identity.slug ||
		!client.redirectUris.includes(query.get("redirect_uri")!)
	)
		throw new APIError("FORBIDDEN");
	const headers = new Headers({
		origin,
		"content-type": "application/json",
		cookie: pending.verificationCookies,
	});
	for (const name of ["user-agent", "x-real-ip"]) {
		const value = incoming.get(name);
		if (value) headers.set(name, value);
	}
	const factorRequest = new Request(
		`${origin}/api/auth/two-factor/${body.method === "backup" ? "verify-backup-code" : "verify-totp"}`,
		{
			method: "POST",
			headers,
			body: JSON.stringify({ code: body.code, trustDevice: false }),
		},
	);
	const verified = await (dispatchFactor
		? dispatchFactor(factorRequest)
		: instance.handler(factorRequest));
	if (!verified.ok)
		throw new APIError(
			verified.status === 429 ? "TOO_MANY_REQUESTS" : "UNAUTHORIZED",
			{ message: "Unable to verify this code. Try again or restart sign-in." },
		);
	// Native MFA atomically burns the challenge; this independently burns its handoff.
	if (!(await context.internalAdapter.consumeVerificationValue(key)))
		throw new APIError("UNAUTHORIZED");
	const cookies = verified.headers.getSetCookie();
	const receipt = random();
	const receiptData: z.infer<typeof receiptSchema> = {
		cookie: pending.cookie,
		cookieName: pending.cookieName,
		cookies,
		origin,
		query: pending.query,
	};
	await context.internalAdapter.createVerificationValue({
		identifier: `broker-mfa-receipt:${await hash(receipt)}`,
		value: await symmetricEncrypt({
			key: context.secretConfig,
			data: JSON.stringify(receiptData),
		}),
		expiresAt: new Date(Date.now() + 60_000),
	});
	return { url: `${origin}/api/broker-two-factor/complete?receipt=${receipt}` };
}

/** Restore native cookies only in the platform browser which owned the pending challenge, once. */
export async function completeBrokerTwoFactor(
	instance: AuthInstance,
	request: Request,
	dispatchContinuation?: (request: Request) => Promise<Response | undefined>,
): Promise<Response> {
	const query = new URL(request.url).searchParams;
	const receipt = query.get("receipt");
	if (
		query.getAll("receipt").length !== 1 ||
		!opaque.safeParse(receipt).success
	)
		throw new APIError("BAD_REQUEST");
	const context = await instance.$context;
	const key = `broker-mfa-receipt:${await hash(receipt!)}`;
	const row = await context.internalAdapter.findVerificationValue(key);
	if (!row || row.expiresAt.getTime() <= Date.now())
		throw new APIError("UNAUTHORIZED");
	const data = receiptSchema.parse(
		JSON.parse(
			await symmetricDecrypt({ key: context.secretConfig, data: row.value }),
		),
	);
	if (
		!constantTimeEqual(
			namedCookie(request.headers.get("cookie") || "", data.cookieName) || "",
			data.cookie,
		)
	)
		throw new APIError("FORBIDDEN");
	if (!(await context.internalAdapter.consumeVerificationValue(key)))
		throw new APIError("UNAUTHORIZED");
	const nativeHeaders = new Headers({
		origin: data.origin,
		"content-type": "application/json",
		cookie: data.cookies.map(cookiePair).join("; "),
	});
	for (const name of ["user-agent", "x-real-ip"]) {
		const value = request.headers.get(name);
		if (value) nativeHeaders.set(name, value);
	}
	const continuation = new Request(`${data.origin}/api/auth/oauth2/continue`, {
		method: "POST",
		headers: nativeHeaders,
		body: JSON.stringify({ selected: true, oauth_query: data.query }),
	});
	const resumed =
		(await dispatchContinuation?.(continuation.clone() as Request)) ??
		(await instance.handler(continuation));
	const result: unknown = await resumed.json().catch(() => null);
	if (
		!resumed.ok ||
		!result ||
		typeof result !== "object" ||
		!("redirect" in result) ||
		result.redirect !== true ||
		!("url" in result) ||
		typeof result.url !== "string"
	)
		throw new APIError("BAD_REQUEST", {
			message: "Unable to resume sign-in. Start again.",
		});
	const destination = new URL(result.url, data.origin);
	const callback = new URL(
		new URLSearchParams(data.query).get("redirect_uri")!,
	);
	if (
		!(
			(destination.origin === callback.origin &&
				destination.pathname === callback.pathname) ||
			(destination.origin === data.origin &&
				["/oauth/consent", "/oauth/select-organization"].includes(
					destination.pathname,
				))
		)
	)
		throw new APIError("BAD_REQUEST");
	const headers = new Headers({
		location: destination.href,
		"cache-control": "no-store",
		pragma: "no-cache",
		"referrer-policy": "no-referrer",
		"x-content-type-options": "nosniff",
	});
	for (const cookie of [...data.cookies, ...resumed.headers.getSetCookie()])
		headers.append("set-cookie", cookie);
	return new Response(null, { status: 302, headers });
}
