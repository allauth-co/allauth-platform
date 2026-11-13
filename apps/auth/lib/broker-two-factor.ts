import type { GenericEndpointContext } from "@better-auth/core";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuthEndpoint } from "better-auth/api";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import * as z from "zod";
import type { AuthInstance } from "./api";
import type {
	BrokerTwoFactorClient,
	BrokerTwoFactorIdentity,
	BrokerTwoFactorStore,
} from "./broker-two-factor-protocol";
import {
	brokerTwoFactorInput,
	completeStoredBrokerTwoFactor,
	issueBrokerTwoFactor,
	namedCookie,
	verifyStoredBrokerTwoFactor,
} from "./broker-two-factor-protocol";

export { brokerTwoFactorInput };

async function legacyStore(
	instance: AuthInstance,
): Promise<BrokerTwoFactorStore> {
	const context = await instance.$context;
	return {
		read: (identifier) =>
			context.internalAdapter.findVerificationValue(identifier),
		consume: (identifier) =>
			context.internalAdapter.consumeVerificationValue(identifier),
		write: (row) => context.internalAdapter.createVerificationValue(row),
		client: (clientId) =>
			context.adapter.findOne<BrokerTwoFactorClient>({
				model: "oauthClient",
				where: [{ field: "clientId", value: clientId }],
			}),
		open: (data) => symmetricDecrypt({ key: context.secretConfig, data }),
		seal: (data) => symmetricEncrypt({ key: context.secretConfig, data }),
	};
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
	const signed = await verifyOAuthQueryParams(
		query.toString(),
		ctx.context.secret,
	);
	return issueBrokerTwoFactor(
		query,
		signed,
		(clientId) =>
			ctx.context.adapter.findOne<BrokerTwoFactorClient>({
				model: "oauthClient",
				where: [{ field: "clientId", value: clientId }],
			}),
		ctx.context.createAuthCookie("two_factor").name,
		ctx.context.authCookies.dontRememberToken.name,
		ctx.headers,
		responseHeaders,
		async (identifier, data, expiresAt) =>
			ctx.context.internalAdapter.createVerificationValue({
				identifier,
				value: await symmetricEncrypt({ key: ctx.context.secretConfig, data }),
				expiresAt,
			}),
	);
}

/** Called only after verifying the application's signed proxy transport, with its stored broker identity. */
export async function verifyBrokerTwoFactor(
	instance: AuthInstance,
	origin: string,
	identity: BrokerTwoFactorIdentity,
	input: z.infer<typeof brokerTwoFactorInput>,
	incoming: Headers,
	dispatchFactor?: (request: Request) => Promise<Response>,
): Promise<{ url: string }> {
	return verifyStoredBrokerTwoFactor(
		await legacyStore(instance),
		origin,
		identity,
		input,
		incoming,
		dispatchFactor ?? ((request) => instance.handler(request)),
		async (clientId, oauth_query) => {
			await instance.api.getOAuthClientPublicPrelogin({
				body: { client_id: clientId, oauth_query },
				headers: new Headers(),
			});
		},
	);
}

/** Restore native cookies only in the platform browser which owned the pending challenge, once. */
export async function completeBrokerTwoFactor(
	instance: AuthInstance,
	request: Request,
	dispatchContinuation?: (request: Request) => Promise<Response | undefined>,
): Promise<Response> {
	return completeStoredBrokerTwoFactor(
		await legacyStore(instance),
		request,
		async (input) =>
			(await dispatchContinuation?.(input.clone() as Request)) ??
			instance.handler(input),
	);
}
