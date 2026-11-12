import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import type { OwnedProjectSsoOptions } from "./owned-project-sso";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import { verifyOwnedSaml } from "./owned-project-sso-saml-protocol";
import type {
	createProjectSsoStore,
	SsoProvider,
	SsoState,
} from "./owned-project-sso-store";
import {
	sameSsoProvider,
	ssoProviderReference,
	ssoReferenceSchema,
	ssoStateSchema,
} from "./owned-project-sso-store";

const requestAge = 5 * 60 * 1000;
const relayAge = 10 * 60 * 1000;
const relayId = /^[A-Za-z0-9_-]{32,80}$/;
const requestId = /^[A-Za-z_][A-Za-z0-9._:-]{0,255}$/;
const formSize = 3 * 256 * 1024 + 4096;
const requestRecord = z.object({
	id: z.string().regex(requestId),
	providerId: z.string(),
	providerReference: ssoReferenceSchema,
	createdAt: z.number().int(),
	expiresAt: z.number().int(),
	relayHash: z
		.string()
		.regex(/^[A-Za-z0-9_-]{43}$/)
		.optional(),
});

type SsoStore = ReturnType<typeof createProjectSsoStore>;
type StartFlow = Pick<
	SsoState,
	"callbackURL" | "newUserURL" | "errorURL" | "requestSignUp"
>;

function digest(value: string) {
	return createHash("sha256").update(value).digest("base64url");
}

function parse<T>(value: string, schema: z.ZodType<T>) {
	try {
		return schema.parse(JSON.parse(value));
	} catch {
		return null;
	}
}

async function postForm(request: Request) {
	if (
		!request.body ||
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== "application/x-www-form-urlencoded"
	)
		return null;
	const reader = request.body.getReader();
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let size = 0;
	let body = "";
	try {
		for (;;) {
			const item = await reader.read();
			if (item.done) break;
			size += item.value.byteLength;
			if (size > formSize) {
				void reader.cancel().catch(() => {});
				return null;
			}
			body += decoder.decode(item.value, { stream: true });
		}
		const data = new URLSearchParams(body + decoder.decode());
		const responses = data.getAll("SAMLResponse");
		const states = data.getAll("RelayState");
		if (
			responses.length !== 1 ||
			!responses[0] ||
			states.length > 1 ||
			(states[0] && !relayId.test(states[0]))
		)
			return null;
		return { response: responses[0], relay: states[0] || undefined };
	} catch {
		return null;
	} finally {
		reader.releaseLock();
	}
}

async function verification(client: PoolClient, identifier: string) {
	const { rows } = await client.query<{
		id: string;
		value: string;
		live: boolean;
	}>(
		`SELECT id, value, "expiresAt" > clock_timestamp() AS live FROM "verification"
		 WHERE identifier = $1 ORDER BY id LIMIT 2 FOR UPDATE`,
		[identifier],
	);
	return rows.length === 1 && rows[0]?.live ? rows[0] : null;
}

function json(value: unknown, status: number, headers = new Headers()) {
	headers.set("cache-control", "no-store");
	return Response.json(value, { status, headers });
}

/** Realm-scoped SP-initiated SAML sign-in and assertion consumer. */
export function createOwnedProjectSaml(options: {
	origin: string;
	basePath: string;
	cookieName: string;
	cookieAttributes: string;
	signingSecret: string;
	signUpEnabled: boolean;
	generatedSPOnly?: boolean;
	customTransport?: ProjectCustomSamlTransport;
	allowEncrypted(provider: SsoProvider): boolean;
	defaultError: URL;
	store: SsoStore;
	allowedReturn(value: string): URL | null;
	complete: OwnedProjectSsoOptions["complete"];
}) {
	const { store } = options;
	const acs = (providerId: string) =>
		`${options.origin}${options.basePath}/sso/saml2/sp/acs/${providerId}`;
	const clear = `${options.cookieName}=; Max-Age=0; ${options.cookieAttributes}`;

	function currentProviderMatches(
		provider: SsoProvider | null,
		reference: ReturnType<typeof ssoProviderReference>,
	): provider is SsoProvider {
		if (!provider?.samlConfig || !sameSsoProvider(provider, reference))
			return false;
		try {
			options.allowEncrypted(provider);
			return true;
		} catch {
			return false;
		}
	}

	function finish(response: Response) {
		const headers = new Headers(response.headers);
		headers.append("set-cookie", clear);
		headers.set("cache-control", "no-store");
		headers.set("referrer-policy", "no-referrer");
		return new Response(response.body, { status: response.status, headers });
	}

	function returnURL(value?: string, receiver?: string) {
		if (!value) return null;
		const url = options.allowedReturn(value);
		if (
			receiver &&
			url?.origin === options.origin &&
			url.pathname === new URL(receiver).pathname
		)
			return null;
		return url;
	}

	function failure(code: string, flow?: SsoState, receiver?: string) {
		const destination =
			returnURL(flow?.errorURL, receiver) ||
			returnURL(flow?.callbackURL, receiver) ||
			new URL(options.defaultError.href);
		destination.searchParams.set("error", code);
		return finish(
			new Response(null, {
				status: 302,
				headers: { location: destination.href },
			}),
		);
	}

	async function start(provider: SsoProvider, flow: StartFlow) {
		try {
			if (!provider.samlConfig) throw new Error("Invalid SAML provider.");
			const relay = randomBytes(32).toString("base64url");
			const { configured } = await configureProjectSamlTransport(
				{ ...provider, samlConfig: provider.samlConfig },
				acs(provider.providerId),
				{
					relayState: relay,
					generatedSPOnly: options.generatedSPOnly,
					customTransport: options.customTransport,
					allowEncrypted: options.allowEncrypted(provider),
				},
			);
			const login = configured.service.createLoginRequest(
				configured.idp,
				"redirect",
			);
			if (typeof login.context !== "string" || !requestId.test(login.id))
				throw new Error("Invalid SAML request.");
			const target = new URL(login.context);
			if (
				target.searchParams.get("RelayState") !== relay ||
				!target.searchParams.get("SAMLRequest") ||
				(configured.requestsSigned &&
					(!target.searchParams.get("SigAlg") ||
						!target.searchParams.get("Signature")))
			)
				throw new Error("Invalid SAML request.");
			const reference = ssoProviderReference(provider);
			const issued = await store.transaction(async (client) => {
				const current = await store.getProvider(provider.providerId, client);
				if (!currentProviderMatches(current, reference)) return false;
				const now = Date.now();
				await client.query(
					`INSERT INTO "verification"(id, identifier, value, "expiresAt")
					 VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)`,
					[
						randomUUID(),
						`auth-state:${relay}`,
						JSON.stringify({
							...flow,
							codeVerifier: randomBytes(32).toString("base64url"),
							oauthState: relay,
							expiresAt: now + relayAge,
							serverContext: {
								ssoProviderReference: reference,
								allauthSamlRequestId: login.id,
							},
						}),
						new Date(now + relayAge),
						randomUUID(),
						`saml-authn-request:${login.id}`,
						JSON.stringify({
							id: login.id,
							providerId: provider.providerId,
							providerReference: reference,
							createdAt: now,
							expiresAt: now + requestAge,
							relayHash: digest(relay),
						}),
						new Date(now + requestAge),
					],
				);
				return true;
			});
			if (!issued) throw new Error("SAML provider changed.");
			const signature = createHmac("sha256", options.signingSecret)
				.update(relay)
				.digest("base64");
			return json(
				{ url: target.href, redirect: true },
				200,
				new Headers({
					"set-cookie": `${options.cookieName}=${encodeURIComponent(`${relay}.${signature}`)}; Max-Age=300; ${options.cookieAttributes}`,
				}),
			);
		} catch {
			return json(
				{
					code: "INVALID_SAML_CONFIGURATION",
					message: "Enterprise sign-in is unavailable.",
				},
				400,
			);
		}
	}

	async function consume(
		provider: SsoProvider,
		proof: Awaited<ReturnType<typeof verifyOwnedSaml>>,
		relay: string | undefined,
	) {
		const providerId = provider.providerId;
		const reference = ssoProviderReference(provider);
		return store.transaction(async (client) => {
			const current = await store.getProvider(providerId, client);
			if (!currentProviderMatches(current, reference))
				return "invalid_state" as const;
			const requestRow = await verification(
				client,
				`saml-authn-request:${proof.requestId}`,
			);
			if (!requestRow) return "invalid_saml_response" as const;
			const transaction = parse(requestRow.value, requestRecord);
			const now = Date.now();
			if (
				!transaction ||
				transaction.id !== proof.requestId ||
				transaction.expiresAt <= now ||
				transaction.providerId !== providerId ||
				!sameSsoProvider(current, transaction.providerReference)
			)
				return "invalid_saml_response" as const;
			if (
				transaction.relayHash &&
				(!relay || digest(relay) !== transaction.relayHash)
			)
				return "invalid_state" as const;
			const stateRow = relay
				? await verification(client, `auth-state:${relay}`)
				: null;
			const flow = stateRow && parse(stateRow.value, ssoStateSchema);
			if (
				relay &&
				(!flow ||
					flow.expiresAt <= now ||
					flow.idTokenNonce !== undefined ||
					(flow.oauthState !== undefined && flow.oauthState !== relay) ||
					(flow.serverContext.allauthSamlRequestId !== undefined &&
						flow.serverContext.allauthSamlRequestId !== proof.requestId) ||
					!sameSsoProvider(current, flow.serverContext.ssoProviderReference))
			)
				return "invalid_state" as const;
			if (proof.replayExpiresAt <= now) return "invalid_saml_response" as const;
			const identifier = `saml-used-assertion:${proof.assertionId}`;
			const reserved = await client.query(
				`INSERT INTO "verification"(id, identifier, value, "expiresAt") VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING`,
				[
					digest(`reserve:${identifier}`),
					identifier,
					JSON.stringify({
						assertionId: proof.assertionId,
						issuer: proof.issuer,
						providerId,
						usedAt: now,
						expiresAt: proof.replayExpiresAt,
					}),
					new Date(proof.replayExpiresAt),
				],
			);
			if (!reserved.rowCount) return "replay_detected" as const;
			await client.query(
				'DELETE FROM "verification" WHERE id = ANY($1::text[])',
				[[requestRow.id, ...(stateRow ? [stateRow.id] : [])]],
			);
			return { flow, reference };
		});
	}

	async function callback(request: Request, providerId: string) {
		const form = await postForm(request);
		if (!form)
			return json(
				{ code: "INVALID_SAML_RESPONSE", message: "Invalid SAML response." },
				400,
			);
		const provider = await store.getProvider(providerId);
		if (!provider?.samlConfig) return failure("invalid_provider");
		let selected: Awaited<ReturnType<typeof configureProjectSamlTransport>>;
		let proof: Awaited<ReturnType<typeof verifyOwnedSaml>>;
		try {
			selected = await configureProjectSamlTransport(
				{ ...provider, samlConfig: provider.samlConfig },
				acs(providerId),
				{
					generatedSPOnly: options.generatedSPOnly,
					customTransport: options.customTransport,
					allowEncrypted: options.allowEncrypted(provider),
				},
			);
			if (selected.custom && request.url !== selected.acs)
				throw new Error("This transport is not the registered SAML receiver.");
			proof = await verifyOwnedSaml(form.response, selected.configured);
		} catch {
			return json(
				{ code: "INVALID_SAML_RESPONSE", message: "Invalid SAML response." },
				400,
			);
		}
		let flow: SsoState | undefined;
		const abort = Symbol("SAML sign-in refused");
		let rejection = "account_not_linked";
		try {
			const consumed = await consume(provider, proof, form.relay);
			if (typeof consumed === "string") return failure(consumed);
			flow = consumed.flow ?? undefined;
			const fallback =
				selected.configured.saved.idpInitiatedCallbackUrl ||
				selected.configured.saved.callbackUrl;
			const receiver = selected.custom ? selected.acs : undefined;
			let destination = returnURL(flow?.callbackURL, receiver)?.href;
			if (!destination && (selected.custom || !flow)) {
				destination =
					returnURL(fallback, receiver)?.href ??
					(selected.custom ? options.origin : new URL(options.origin).href);
			}
			if (!destination) return failure("invalid_state", flow, receiver);
			return finish(
				await store.transaction(async (client) => {
					const current = await store.getProvider(providerId, client);
					if (!currentProviderMatches(current, consumed.reference)) {
						rejection = "invalid_state";
						throw abort;
					}
					const linked = await store.bind(
						client,
						current,
						proof.identity,
						options.signUpEnabled,
						"saml",
					);
					if (typeof linked === "string") {
						rejection = linked;
						throw abort;
					}
					const response = await options.complete(client, {
						request,
						...linked,
						providerId,
						destination,
						protocol: "saml",
					});
					if (response.status >= 400) throw abort;
					return response;
				}),
			);
		} catch (error) {
			return failure(
				error === abort ? rejection : "internal_server_error",
				flow,
				selected.custom ? selected.acs : undefined,
			);
		}
	}

	return { start, callback };
}
