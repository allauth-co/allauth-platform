import { timingSafeEqual } from "node:crypto";
import * as z from "zod";
import { ConsoleRequestError } from "./console/request-error";

function constantTimeEqual(a: string, b: string) {
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	return left.length === right.length && timingSafeEqual(left, right);
}

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
export type BrokerTwoFactorAttempt = z.infer<typeof brokerTwoFactorInput>;
export type BrokerTwoFactorIdentity = z.infer<typeof identitySchema>;
export type BrokerTwoFactorClient = {
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
export const namedCookie = (header: string, name: string) => {
	const matches = header
		.split(";")
		.map((value) => value.trim())
		.filter((value) => value.startsWith(`${name}=`));
	return matches.length === 1 ? matches[0] : undefined;
};

function brokerMetadata(
	client: BrokerTwoFactorClient,
): Record<string, unknown> | undefined {
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

export interface BrokerTwoFactorStore {
	read(identifier: string): Promise<{ value: string; expiresAt: Date } | null>;
	consume(identifier: string): Promise<unknown>;
	write(row: {
		identifier: string;
		value: string;
		expiresAt: Date;
	}): Promise<unknown>;
	client(clientId: string): Promise<BrokerTwoFactorClient | null>;
	open(value: string): Promise<string>;
	seal(value: string): Promise<string>;
}

export async function issueBrokerTwoFactor(
	query: URLSearchParams,
	verified: boolean,
	readClient: BrokerTwoFactorStore["client"],
	cookieName: string,
	rememberName: string,
	requestHeaders: Headers | undefined,
	responseHeaders: Headers | undefined,
	save: (identifier: string, data: string, expiresAt: Date) => Promise<unknown>,
) {
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
	if (!verified) return;
	const clientId = query.get("client_id");
	if (
		!clientId ||
		query.getAll("client_id").length !== 1 ||
		query.getAll("redirect_uri").length !== 1
	)
		return;
	const client = await readClient(clientId);
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
	const cookie = responseHeaders
		?.getSetCookie()
		.find((value) => value.startsWith(`${cookieName}=`));
	if (!cookie || !cookiePair(cookie).slice(cookieName.length + 1)) return;
	const outgoingRemember = responseHeaders
		?.getSetCookie()
		.filter((value) => value.startsWith(`${rememberName}=`))
		.at(-1);
	const remember = outgoingRemember
		? /;\s*Max-Age=0(?:;|$)/i.test(outgoingRemember)
			? undefined
			: cookiePair(outgoingRemember)
		: namedCookie(requestHeaders?.get("cookie") || "", rememberName);
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
	await save(
		`broker-mfa:${await hash(ticket)}`,
		JSON.stringify(data),
		new Date(Date.now() + lifetime),
	);
	return `${callback.origin}/api/allauth/broker-two-factor/accept?ticket=${ticket}`;
}

export async function verifyStoredBrokerTwoFactor(
	store: BrokerTwoFactorStore,
	origin: string,
	identity: BrokerTwoFactorIdentity,
	input: BrokerTwoFactorAttempt,
	incoming: Headers,
	dispatchFactor: (request: Request) => Promise<Response>,
	validateQuery: (clientId: string, query: string) => Promise<void>,
): Promise<{ url: string }> {
	const body = brokerTwoFactorInput.parse(input);
	const key = `broker-mfa:${await hash(body.ticket)}`;
	const row = await store.read(key);
	if (!row || row.expiresAt.getTime() <= Date.now())
		throw new ConsoleRequestError(
			401,
			"This sign-in has expired. Start again.",
		);
	const pending = pendingSchema.parse(JSON.parse(await store.open(row.value)));
	if (
		pending.identity.clientId !== identity.clientId ||
		pending.identity.slug !== identity.slug ||
		pending.identity.origin !== identity.origin ||
		!constantTimeEqual(pending.bindingHash, await hash(body.binding))
	)
		throw new ConsoleRequestError(403);
	// Recheck client revocation/redirect registration before verifying the factor.
	const query = new URLSearchParams(pending.query);
	await validateQuery(identity.clientId, pending.query);
	const client = await store.client(identity.clientId);
	if (
		!client ||
		client.disabled ||
		brokerMetadata(client)?.allauthProjectBroker !== identity.slug ||
		!client.redirectUris.includes(query.get("redirect_uri")!)
	)
		throw new ConsoleRequestError(403);
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
	const verified = await dispatchFactor(factorRequest);
	if (!verified.ok)
		throw new ConsoleRequestError(
			verified.status === 429 ? 429 : 401,
			"Unable to verify this code. Try again or restart sign-in.",
		);
	// Native MFA atomically burns the challenge; this independently burns its handoff.
	if (!(await store.consume(key))) throw new ConsoleRequestError(401);
	const cookies = verified.headers.getSetCookie();
	const receipt = random();
	const receiptData: z.infer<typeof receiptSchema> = {
		cookie: pending.cookie,
		cookieName: pending.cookieName,
		cookies,
		origin,
		query: pending.query,
	};
	await store.write({
		identifier: `broker-mfa-receipt:${await hash(receipt)}`,
		value: await store.seal(JSON.stringify(receiptData)),
		expiresAt: new Date(Date.now() + 60_000),
	});
	return { url: `${origin}/api/broker-two-factor/complete?receipt=${receipt}` };
}

export async function completeStoredBrokerTwoFactor(
	store: BrokerTwoFactorStore,
	request: Request,
	dispatchContinuation: (request: Request) => Promise<Response | undefined>,
): Promise<Response> {
	const query = new URL(request.url).searchParams;
	const receipt = query.get("receipt");
	if (
		query.getAll("receipt").length !== 1 ||
		!opaque.safeParse(receipt).success
	)
		throw new ConsoleRequestError(400);
	const key = `broker-mfa-receipt:${await hash(receipt!)}`;
	const row = await store.read(key);
	if (!row || row.expiresAt.getTime() <= Date.now())
		throw new ConsoleRequestError(401);
	const data = receiptSchema.parse(JSON.parse(await store.open(row.value)));
	if (
		!constantTimeEqual(
			namedCookie(request.headers.get("cookie") || "", data.cookieName) || "",
			data.cookie,
		)
	)
		throw new ConsoleRequestError(403);
	if (!(await store.consume(key))) throw new ConsoleRequestError(401);
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
	const resumed = await dispatchContinuation(continuation);
	const result: unknown = await resumed?.json().catch(() => null);
	if (
		!resumed?.ok ||
		!result ||
		typeof result !== "object" ||
		!("redirect" in result) ||
		result.redirect !== true ||
		!("url" in result) ||
		typeof result.url !== "string"
	)
		throw new ConsoleRequestError(
			400,
			"Unable to resume sign-in. Start again.",
		);
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
		throw new ConsoleRequestError(400);
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
