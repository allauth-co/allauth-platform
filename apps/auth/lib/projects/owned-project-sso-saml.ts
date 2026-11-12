import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { markOwnedCallbackFailure } from "./owned-project-callback-failure";
import type { OwnedProjectSsoOptions } from "./owned-project-sso";
import type { ProjectSsoAdmission } from "./owned-project-sso-admission";
import {
	createSsoProfileAdmission,
	ssoPolicyErrorDescription,
	ssoSessionErrorCode,
} from "./owned-project-sso-admission";
import type { ProjectEncryptedSamlApproval } from "./owned-project-sso-saml-approval";
import { configureApprovedProjectSaml } from "./owned-project-sso-saml-approval";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import {
	isSamlRelativeRedirect,
	verifyOwnedSaml,
} from "./owned-project-sso-saml-protocol";
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
const postBodySize = 3 * 256 * 1024 + 4096;
const jsonResponse = z.object({
	SAMLResponse: z.string(),
	RelayState: z.string().optional(),
});
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
type VerifiedSaml = Awaited<ReturnType<typeof verifyOwnedSaml>>;
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

function samlFormResponse(body: string) {
	const data = new URLSearchParams(body);
	const responses = data.getAll("SAMLResponse");
	const states = data.getAll("RelayState");
	if (responses.length !== 1 || states.length > 1) return null;
	return { SAMLResponse: responses[0], RelayState: states[0] };
}

async function samlPostResponse(request: Request) {
	const media = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	if (
		!request.body ||
		(media !== "application/x-www-form-urlencoded" &&
			media !== "application/json")
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
			if (size > postBodySize) {
				void reader.cancel().catch(() => {});
				return null;
			}
			body += decoder.decode(item.value, { stream: true });
		}
		body += decoder.decode();
		const payload =
			media === "application/json"
				? parse(body, jsonResponse)
				: samlFormResponse(body);
		const relay = payload?.RelayState;
		if (!payload?.SAMLResponse || (relay && !relayId.test(relay))) return null;
		return { response: payload.SAMLResponse, relay: relay || undefined };
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
	encryptedApproval?: ProjectEncryptedSamlApproval;
	allowEncrypted(provider: SsoProvider): boolean;
	defaultError: URL;
	store: SsoStore;
	allowedReturn(value: string): URL | null;
	complete: OwnedProjectSsoOptions["complete"];
	profilePolicy: ProjectSsoAdmission;
}) {
	const { store } = options;
	const acs = (providerId: string) =>
		`${options.origin}${options.basePath}/sso/saml2/sp/acs/${providerId}`;
	const clear = `${options.cookieName}=; Max-Age=0; ${options.cookieAttributes}`;

	async function approvalIsCurrent(provider: SsoProvider) {
		const approval = options.encryptedApproval;
		if (approval?.providerId !== provider.providerId) return true;
		try {
			approval.assertProvider(provider);
			return Boolean(
				await options.customTransport?.authorizeAcs(
					approval.receiver,
					provider.providerId,
				),
			);
		} catch {
			return false;
		}
	}

	async function currentProviderMatches(
		provider: SsoProvider,
		reference: ReturnType<typeof ssoProviderReference>,
	) {
		if (!provider.samlConfig || !sameSsoProvider(provider, reference))
			return false;
		try {
			options.allowEncrypted(provider);
			return await approvalIsCurrent(provider);
		} catch {
			return false;
		}
	}

	function configure(
		provider: SsoProvider & { samlConfig: Record<string, unknown> },
		relayState?: string,
	) {
		const approval = options.encryptedApproval;
		if (approval?.providerId === provider.providerId)
			return configureApprovedProjectSaml(
				approval,
				provider,
				options.customTransport,
				relayState,
			);
		return configureProjectSamlTransport(provider, acs(provider.providerId), {
			relayState,
			generatedSPOnly: options.generatedSPOnly,
			customTransport: options.customTransport,
			allowEncrypted: options.allowEncrypted(provider),
		});
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

	function configuredReturn(
		receiver: string,
		...destinations: (string | undefined)[]
	) {
		for (const destination of destinations) {
			if (
				destination &&
				(!destination.startsWith("/") || isSamlRelativeRedirect(destination)) &&
				returnURL(destination, receiver)
			)
				return destination;
		}
		return options.origin;
	}

	function refuseUnsolicited(destination: string) {
		const code = "unsolicited_response";
		const description = "IdP-initiated SSO not allowed";
		let location: string;
		if (isSamlRelativeRedirect(destination)) {
			const hashIndex = destination.indexOf("#");
			const path =
				hashIndex < 0 ? destination : destination.slice(0, hashIndex);
			const fragment = hashIndex < 0 ? "" : destination.slice(hashIndex);
			const delimiter = path.includes("?") ? "&" : "?";
			location = `${path}${delimiter}error=${code}&error_description=${encodeURIComponent(description)}${fragment}`;
		} else {
			const target = new URL(destination);
			target.searchParams.set("error", code);
			target.searchParams.set("error_description", description);
			location = target.href;
		}
		return markOwnedCallbackFailure(
			new Response(null, {
				status: 302,
				headers: {
					location,
					"cache-control": "no-store",
					"referrer-policy": "no-referrer",
				},
			}),
			code,
		);
	}

	function failure(
		code: string,
		flow?: SsoState,
		receiver?: string,
		signedDestination?: string,
	) {
		const description = ssoPolicyErrorDescription(code);
		const destination =
			returnURL(flow?.errorURL, receiver) ||
			(description
				? !flow && returnURL(signedDestination, receiver)
				: returnURL(flow?.callbackURL, receiver)) ||
			new URL(options.defaultError.href);
		destination.searchParams.set("error", code);
		if (description)
			destination.searchParams.set("error_description", description);
		const response = finish(
			new Response(null, {
				status: 302,
				headers: { location: destination.href },
			}),
		);
		return markOwnedCallbackFailure(response, code);
	}

	async function start(provider: SsoProvider, flow: StartFlow) {
		try {
			if (!provider.samlConfig) throw new Error("Invalid SAML provider.");
			const relay = randomBytes(32).toString("base64url");
			const { configured } = await configure(
				{ ...provider, samlConfig: provider.samlConfig },
				relay,
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
				if (!current || !(await currentProviderMatches(current, reference)))
					return false;
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
		proof: Extract<VerifiedSaml, { requestId: string }>,
		relay: string | undefined,
	) {
		const providerId = provider.providerId;
		const reference = ssoProviderReference(provider);
		return store.transaction(async (client) => {
			const current = await store.getProvider(providerId, client);
			if (!current || !(await currentProviderMatches(current, reference)))
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
		const payload = await samlPostResponse(request);
		if (!payload)
			return json(
				{ code: "INVALID_SAML_RESPONSE", message: "Invalid SAML response." },
				400,
			);
		const provider = await store.getProvider(providerId);
		if (!provider?.samlConfig) return failure("invalid_provider");
		let selected: Awaited<ReturnType<typeof configureProjectSamlTransport>>;
		let proof: VerifiedSaml;
		try {
			selected = await configure({
				...provider,
				samlConfig: provider.samlConfig,
			});
			if (selected.custom && request.url !== selected.acs)
				throw new Error("This transport is not the registered SAML receiver.");
			proof = await verifyOwnedSaml(payload.response, selected.configured);
			const approval = options.encryptedApproval;
			if (
				approval?.providerId === providerId &&
				(!proof.requestId ||
					!proof.encryption ||
					!approval.acceptsProfile(proof.encryption))
			)
				throw new Error("This response is outside the approved SAML profile.");
		} catch {
			return markOwnedCallbackFailure(
				json(
					{ code: "INVALID_SAML_RESPONSE", message: "Invalid SAML response." },
					400,
				),
				"saml_error",
			);
		}
		const saved = selected.configured.saved;
		const receiver =
			selected.custom || saved.idpInitiatedCallbackUrl
				? selected.acs
				: undefined;
		if (proof.requestId === null)
			return refuseUnsolicited(
				configuredReturn(
					selected.acs,
					saved.idpInitiatedCallbackUrl,
					saved.callbackUrl,
				),
			);
		let flow: SsoState | undefined;
		let signedDestination: string | undefined;
		const abort = Symbol("SAML sign-in refused");
		let rejection = "account_not_linked";
		try {
			const consumed = await consume(provider, proof, payload.relay);
			if (typeof consumed === "string") return failure(consumed);
			flow = consumed.flow ?? undefined;
			let destination = saved.idpInitiatedCallbackUrl
				? configuredReturn(
						selected.acs,
						flow?.callbackURL,
						saved.idpInitiatedCallbackUrl,
						saved.callbackUrl,
					)
				: returnURL(flow?.callbackURL, receiver)?.href;
			if (!destination && (selected.custom || !flow)) {
				destination =
					returnURL(saved.callbackUrl, receiver)?.href ??
					(selected.custom ? options.origin : new URL(options.origin).href);
			}
			if (!destination) return failure("invalid_state", flow, receiver);
			signedDestination = destination;
			const absoluteDestination = new URL(destination, options.origin).href;
			const result = await store.transaction(async (client) => {
				const current = await store.getProvider(providerId, client);
				if (
					!current ||
					!(await currentProviderMatches(current, consumed.reference))
				) {
					rejection = "invalid_state";
					throw abort;
				}
				const { state: admission, denyProfile } = createSsoProfileAdmission(
					options.profilePolicy,
					client,
					request,
				);
				try {
					const linked = await store.bind(
						client,
						current,
						proof.identity,
						options.signUpEnabled,
						"saml",
						denyProfile,
					);
					if (typeof linked === "string") {
						if (admission.commitDenial) return linked;
						rejection = linked;
						throw abort;
					}
					const response = await options.complete(client, {
						request,
						...linked,
						providerId,
						destination: absoluteDestination,
						protocol: "saml",
					});
					if (response.status >= 400) {
						rejection = await ssoSessionErrorCode(response);
						throw abort;
					}
					if (
						destination !== absoluteDestination &&
						response.headers.get("location") === absoluteDestination
					) {
						const headers = new Headers(response.headers);
						headers.set("location", destination);
						return new Response(response.body, {
							status: response.status,
							headers,
						});
					}
					return response;
				} catch (error) {
					if (!admission.rollback) throw error;
					await admission.rollback();
					return error === abort ? rejection : "internal_server_error";
				}
			});
			return typeof result === "string"
				? failure(result, flow, receiver, signedDestination)
				: finish(result);
		} catch (error) {
			return failure(
				error === abort ? rejection : "internal_server_error",
				flow,
				receiver,
				signedDestination,
			);
		}
	}

	return { start, callback, approvalIsCurrent };
}
