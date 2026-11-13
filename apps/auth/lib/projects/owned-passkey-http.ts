import { randomBytes, randomUUID } from "node:crypto";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
} from "@simplewebauthn/server";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ControlEventInput } from "../control/types";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import {
	createProjectEngineStore,
	recordOwnedProjectEvent,
} from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { StoredProjectPasskey } from "./passkey-store";
import { projectPasskeyStore } from "./passkey-store";
import type { ProjectPasskeyChallenge } from "./passkey-verification";
import { projectPasskeyVerification } from "./passkey-verification";
import { timedProjectProtocolStream } from "./project-protocol-body";
import { checkedProjectSchema } from "./validation";

const challengeMaxAge = 300;
const webAuthnBytes = 262144;
const name = z.string().trim();
const encoded = z
	.string()
	.min(1)
	.regex(/^[A-Za-z0-9_-]+={0,2}$/);
const transports = z.enum([
	"ble",
	"cable",
	"hybrid",
	"internal",
	"nfc",
	"smart-card",
	"usb",
]);
const credentialResponse = z.object({
	id: encoded.max(2048),
	rawId: encoded.max(2048),
	type: z.literal("public-key"),
	clientExtensionResults: z.object({}).passthrough().default({}),
	authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
});
const registration = z.object({
	response: z.unknown(),
	name: name.optional(),
	createSession: z.boolean().optional(),
});
const registrationProof = credentialResponse.extend({
	response: z.object({
		clientDataJSON: encoded,
		attestationObject: encoded,
		transports: z.array(transports).max(8).optional(),
	}),
});
const authenticationEnvelope = z.object({
	response: z.record(z.string(), z.unknown()),
});
const authentication = z.object({
	response: credentialResponse.extend({
		response: z.object({
			clientDataJSON: encoded,
			authenticatorData: encoded,
			signature: encoded,
			userHandle: z.preprocess(
				(value) => (value === null ? undefined : value),
				encoded.optional(),
			),
		}),
	}),
});
const challengeShape = z.object({
	type: z.enum(["authentication", "registration"]),
	expectedChallenge: encoded,
	userData: z.object({ id: z.string().max(160) }),
});
const passkeyMutationEvents = {
	"/passkey/verify-registration": "passkey.registered",
	"/passkey/delete-passkey": "passkey.deleted",
	"/passkey/update-passkey": "passkey.updated",
} as const;
type PasskeyMutationPath = keyof typeof passkeyMutationEvents;
const passkeyTarget = z.object({ id: z.string() });
const passkeyUpdate = passkeyTarget.extend({ name: name.min(1) });
const eventError = z.object({ code: z.string().regex(/^[A-Z0-9_-]{1,100}$/) });

interface PasskeySession {
	userId: string;
	email: string;
	fresh: boolean;
}

interface Options {
	database: Pool;
	schemaName: string;
	transaction?: <T>(work: (client: PoolClient) => Promise<T>) => Promise<T>;
	cookiePrefix: string;
	signingSecret: string;
	rp: {
		id: string;
		name: string;
		origins: readonly string[];
		requireUserVerification: boolean;
	};
	readBody: (request: Request, limit: number) => Promise<unknown>;
	auditContext(
		request: Request,
	): Pick<ControlEventInput, "ipAddress" | "userAgent">;
	writeCookie: (
		headers: Headers,
		name: string,
		value: string,
		maxAge?: number,
	) => void;
	readSession: (request: Request) => Promise<PasskeySession | null>;
	withSession: <T>(
		request: Request,
		userId: string,
		fresh: boolean,
		work: (client: PoolClient) => Promise<T>,
	) => Promise<T | null>;
	admit: (
		request: Request,
		operation: "options" | "verification",
	) => Promise<Response | null>;
	recordFailedAuthentication: (request: Request) => Promise<void>;
	completeSignIn: (
		request: Request,
		userId: string,
		record: (client: PoolClient) => Promise<boolean>,
	) => Promise<Response | null>;
	completeRegistration: (
		client: PoolClient,
		request: Request,
		userId: string,
	) => Promise<Response>;
}

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

const invalid = () =>
	json({ code: "INVALID_BODY", message: "Invalid passkey request." }, 400);
const unauthorized = () =>
	json({ code: "UNAUTHORIZED", message: "Unauthorized" }, 401);
const staleSession = () =>
	json({ code: "SESSION_NOT_FRESH", message: "Session is not fresh" }, 403);
const notFound = () =>
	json({ code: "PASSKEY_NOT_FOUND", message: "Passkey not found" }, 404);
const challengeNotFound = () =>
	json({ code: "CHALLENGE_NOT_FOUND", message: "Challenge not found" }, 400);
const verificationFailed = () =>
	json(
		{
			code: "FAILED_TO_VERIFY_REGISTRATION",
			message: "Failed to verify registration",
		},
		400,
	);

function validationFailure(issues: readonly z.core.$ZodIssue[]) {
	const message = issues
		.map((issue) => `[${["body", ...issue.path].join(".")}] ${issue.message}`)
		.join("; ");
	return json({ code: "VALIDATION_ERROR", message }, 400);
}

function descriptors(rows: StoredProjectPasskey[]) {
	return rows.map((row) => ({
		id: row.credentialID,
		transports: (row.transports?.split(",") ?? []).flatMap(
			(value): AuthenticatorTransportFuture[] => {
				const parsed = transports.safeParse(value);
				return parsed.success ? [parsed.data] : [];
			},
		),
	}));
}

function withExpiredCookie(
	response: Response,
	clear: (headers: Headers) => void,
) {
	const headers = new Headers(response.headers);
	clear(headers);
	return new Response(response.body, { status: response.status, headers });
}

/** Own the project passkey HTTP contract while accepting in-flight legacy ceremonies. */
export function createOwnedProjectPasskeyHttp(options: Options) {
	const schema =
		options.schemaName === "public"
			? "public"
			: checkedProjectSchema(options.schemaName);
	const store = projectPasskeyStore(options.database, schema);
	const transaction =
		options.transaction ??
		createProjectEngineStore(options.database, schema).transaction;
	const cookie = `${options.cookiePrefix}better-auth-passkey`;
	const verify = projectPasskeyVerification(store, {
		rpId: options.rp.id,
		origins: options.rp.origins,
		requireUserVerification: options.rp.requireUserVerification,
		async consumeChallenge(token) {
			if (!/^[A-Za-z0-9_-]{32}$/.test(token)) return null;
			const result = await options.database.query<{
				value: string;
				live: boolean;
			}>(
				`DELETE FROM "${schema}"."verification" WHERE identifier = $1
				RETURNING value, "expiresAt" > statement_timestamp() AS live`,
				[token],
			);
			const row = result.rows[0];
			if (result.rows.length !== 1 || !row?.live) return null;
			try {
				const parsed = challengeShape.safeParse(JSON.parse(row.value));
				return parsed.success ? parsed.data : null;
			} catch {
				return null;
			}
		},
	});

	function recordMutation(
		client: PoolClient,
		request: Request,
		path: PasskeyMutationPath,
		outcome: { userId?: string; targetId?: string; errorCode?: string },
	) {
		return recordOwnedProjectEvent(client, {
			...options.auditContext(request),
			type: passkeyMutationEvents[path],
			outcome: outcome.errorCode ? "failure" : "success",
			actorId: outcome.userId,
			userId: outcome.userId,
			targetId: outcome.targetId,
			metadata: {
				path,
				...(outcome.errorCode ? { errorCode: outcome.errorCode } : {}),
			},
		});
	}

	async function failedMutation(
		request: Request,
		path: PasskeyMutationPath,
		response: Response,
		userId?: string,
		targetId?: string,
	) {
		const parsed = eventError.safeParse(
			await response
				.clone()
				.json()
				.catch(() => null),
		);
		await transaction((client) =>
			recordMutation(client, request, path, {
				userId,
				targetId,
				errorCode: parsed.success ? parsed.data.code : "AUTHENTICATION_FAILED",
			}),
		);
		return response;
	}

	function readMutationBody(request: Request, limit: number) {
		if (
			!request.body ||
			request.headers
				.get("content-type")
				?.split(";", 1)[0]
				?.trim()
				.toLowerCase() !== "application/json"
		)
			return options.readBody(request, limit);
		// Classify the native DTO before authentication without holding a realm
		// request open indefinitely on an unauthenticated body stream.
		const timed = timedProjectProtocolStream(request.body);
		return options.readBody(
			new Request(request, {
				body: timed.stream,
				duplex: "half",
			} as RequestInit),
			limit,
		);
	}

	async function issueChallenge(
		challenge: ProjectPasskeyChallenge,
		display?: { name: string; displayName: string; context: string | null },
	) {
		const token = randomBytes(24).toString("base64url");
		await options.database.query(
			`INSERT INTO "${schema}"."verification"(id, identifier, value, "expiresAt")
			VALUES ($1,$2,$3,statement_timestamp() + $4::int * interval '1 second')`,
			[
				randomUUID(),
				token,
				JSON.stringify({
					...challenge,
					...(display
						? {
								userData: {
									id: challenge.userData.id,
									name: display.name,
									displayName: display.displayName,
								},
								context: display.context,
							}
						: {}),
				}),
				challengeMaxAge,
			],
		);
		const headers = new Headers();
		options.writeCookie(headers, cookie, token, challengeMaxAge);
		return headers;
	}

	async function generateRegistration(request: Request) {
		const session = await options.readSession(request);
		if (!session) return unauthorized();
		if (!session.fresh) return staleSession();
		const refused = await options.admit(request, "options");
		if (refused) return refused;
		const query = new URL(request.url).searchParams;
		const attachment = z
			.enum(["platform", "cross-platform"])
			.optional()
			.safeParse(query.get("authenticatorAttachment") ?? undefined);
		const title = z
			.string()
			.max(256)
			.optional()
			.safeParse(query.get("name") ?? undefined);
		const context = z
			.string()
			.max(2048)
			.optional()
			.safeParse(query.get("context") ?? undefined);
		if (!attachment.success || !title.success || !context.success)
			return invalid();
		const existing = await store.listForUser(session.userId);
		const user = session.email || session.userId;
		const ceremony = await generateRegistrationOptions({
			rpName: options.rp.name,
			rpID: options.rp.id,
			userID: Uint8Array.from(randomBytes(32)),
			userName: title.data || user,
			userDisplayName: user,
			attestationType: "none",
			excludeCredentials: descriptors(existing),
			authenticatorSelection: {
				residentKey: options.rp.requireUserVerification
					? "required"
					: "preferred",
				userVerification: options.rp.requireUserVerification
					? "required"
					: "preferred",
				...(options.rp.requireUserVerification
					? { requireResidentKey: true }
					: {}),
				...(attachment.data
					? { authenticatorAttachment: attachment.data }
					: {}),
			},
		});
		const headers = await issueChallenge(
			{
				type: "registration",
				expectedChallenge: ceremony.challenge,
				userData: { id: session.userId },
			},
			{ name: user, displayName: user, context: context.data ?? null },
		);
		return json(ceremony, 200, headers);
	}

	async function generateAuthentication(request: Request) {
		const refused = await options.admit(request, "options");
		if (refused) return refused;
		const session = await options.readSession(request);
		const existing = session ? await store.listForUser(session.userId) : [];
		const ceremony = await generateAuthenticationOptions({
			rpID: options.rp.id,
			userVerification: options.rp.requireUserVerification
				? "required"
				: "preferred",
			...(existing.length ? { allowCredentials: descriptors(existing) } : {}),
		});
		return json(
			ceremony,
			200,
			await issueChallenge({
				type: "authentication",
				expectedChallenge: ceremony.challenge,
				userData: { id: session?.userId ?? "" },
			}),
		);
	}

	const clear = (headers: Headers) =>
		options.writeCookie(headers, cookie, "", 0);

	async function verifyAuthentication(request: Request) {
		const refused = await options.admit(request, "verification");
		if (refused) return refused;
		const envelope = authenticationEnvelope.safeParse(
			await options.readBody(request, webAuthnBytes),
		);
		if (!envelope.success) return invalid();
		async function outcome(response: Response) {
			if (
				response.status >= 400 &&
				response.status < 500 &&
				response.status !== 429
			)
				await options.recordFailedAuthentication(request);
			return response;
		}
		const token = readLegacySessionCookie(
			request.headers,
			cookie,
			options.signingSecret,
		);
		if (!token) return outcome(challengeNotFound());
		const input = authentication.safeParse(envelope.data);
		if (!input.success) return outcome(invalid());
		let response: Response | null = null;
		const result = await verify.authenticate({
			token,
			response: input.data.response satisfies AuthenticationResponseJSON,
			async commitAssertion(credential, counter) {
				response = await options.completeSignIn(
					request,
					credential.userId,
					(client) => store.recordAssertion(credential, counter, client),
				);
				return response !== null;
			},
		});
		if (result.ok && response)
			return outcome(withExpiredCookie(response, clear));
		const failed =
			!result.ok && result.reason === "challenge"
				? challengeNotFound()
				: json(
						{ code: "AUTHENTICATION_FAILED", message: "Authentication failed" },
						401,
					);
		return outcome(withExpiredCookie(failed, clear));
	}

	async function verifyRegistration(request: Request) {
		const path = "/passkey/verify-registration";
		const session = await options.readSession(request);
		const body = await readMutationBody(request, webAuthnBytes);
		if (body === undefined) return invalid();
		const input = registration.safeParse(body);
		if (!input.success)
			return failedMutation(
				request,
				path,
				validationFailure(input.error.issues),
				session?.userId,
			);
		if (!session) return failedMutation(request, path, unauthorized());
		if (!session.fresh)
			return failedMutation(request, path, staleSession(), session.userId);
		const refused = await options.admit(request, "verification");
		if (refused) return refused;
		const token = readLegacySessionCookie(
			request.headers,
			cookie,
			options.signingSecret,
		);
		if (!token)
			return failedMutation(request, path, challengeNotFound(), session.userId);
		const proof = registrationProof.safeParse(input.data.response);
		if (!proof.success)
			return failedMutation(
				request,
				path,
				verificationFailed(),
				session.userId,
			);
		let signIn: Response | undefined;
		const registrationRefused = Symbol("Session issuance was refused");
		const result = await verify
			.register({
				token,
				name: input.data.name,
				response: proof.data satisfies RegistrationResponseJSON,
				freshUserId: async () => session.userId,
				async registerCredential(userId, credential) {
					return options.withSession(request, userId, true, async (client) => {
						const saved = await store.registerForUser(
							userId,
							credential,
							client,
						);
						if (saved && input.data.createSession) {
							signIn = await options.completeRegistration(
								client,
								request,
								userId,
							);
							if (!signIn.ok) throw registrationRefused;
						}
						if (saved) await recordMutation(client, request, path, { userId });
						return saved;
					});
				},
			})
			.catch((error: unknown) => {
				if (error === registrationRefused) return null;
				throw error;
			});
		if (!result && signIn)
			return failedMutation(
				request,
				path,
				withExpiredCookie(signIn, clear),
				session.userId,
			);
		if (!result)
			return failedMutation(
				request,
				path,
				withExpiredCookie(challengeNotFound(), clear),
				session.userId,
			);
		if (!result.ok) {
			const failed =
				result.reason === "challenge"
					? challengeNotFound()
					: verificationFailed();
			return failedMutation(
				request,
				path,
				withExpiredCookie(failed, clear),
				session.userId,
			);
		}
		const headers = new Headers(signIn?.headers);
		clear(headers);
		const data = signIn
			? ((await signIn.json()) as Record<string, unknown>)
			: {};
		if (data.twoFactorRedirect === true) return json(data, 200, headers);
		return json({ ...result.value, ...data }, 200, headers);
	}

	return async (path: string, request: Request): Promise<Response | null> => {
		if (request.method === "GET") {
			if (path === "/passkey/generate-register-options")
				return generateRegistration(request);
			if (path === "/passkey/generate-authenticate-options")
				return generateAuthentication(request);
			if (path === "/passkey/list-user-passkeys") {
				const current = await options.readSession(request);
				return current
					? json(await store.listForUser(current.userId))
					: unauthorized();
			}
		}
		if (request.method === "POST") {
			if (Object.hasOwn(passkeyMutationEvents, path)) {
				const ip = options.auditContext(request).ipAddress ?? null;
				const refused = await transaction((client) =>
					admitOwnedProjectNativeRoute(client, ip, path, {
						max: 100,
						windowMs: 60_000,
					}),
				);
				if (refused) return refused;
			}
			if (path === "/passkey/verify-registration")
				return verifyRegistration(request);
			if (path === "/passkey/verify-authentication")
				return verifyAuthentication(request);
			if (
				path !== "/passkey/delete-passkey" &&
				path !== "/passkey/update-passkey"
			)
				return null;
			const current = await options.readSession(request);
			const body = await readMutationBody(request, 8192);
			if (body === undefined) return invalid();
			const mutation =
				path === "/passkey/delete-passkey"
					? ({ kind: "delete", input: passkeyTarget.safeParse(body) } as const)
					: ({ kind: "rename", input: passkeyUpdate.safeParse(body) } as const);
			if (!mutation.input.success) {
				const target = passkeyTarget.safeParse(body);
				return failedMutation(
					request,
					path,
					validationFailure(mutation.input.error.issues),
					current?.userId,
					target.success ? target.data.id : undefined,
				);
			}
			const { id } = mutation.input.data;
			if (!current)
				return failedMutation(request, path, unauthorized(), undefined, id);
			if (!id)
				return failedMutation(
					request,
					path,
					json({ message: "Missing required parameter: id" }, 400),
					current.userId,
				);
			if (mutation.kind === "delete") {
				const response = await options.withSession(
					request,
					current.userId,
					false,
					async (client) => {
						const removed = await store.removeForUser(
							current.userId,
							id,
							client,
						);
						await recordMutation(client, request, path, {
							userId: current.userId,
							targetId: id,
							errorCode: removed ? undefined : "PASSKEY_NOT_FOUND",
						});
						return removed ? json({ status: true }) : notFound();
					},
				);
				return (
					response ??
					failedMutation(request, path, notFound(), current.userId, id)
				);
			}
			const { name: updatedName } = mutation.input.data;
			const response = await options.withSession(
				request,
				current.userId,
				false,
				async (client) => {
					const updated = await store.renameForUser(
						current.userId,
						id,
						updatedName,
						client,
					);
					await recordMutation(client, request, path, {
						userId: current.userId,
						targetId: id,
						errorCode: updated ? undefined : "PASSKEY_NOT_FOUND",
					});
					return updated ? json({ passkey: updated }) : notFound();
				},
			);
			return (
				response ??
				failedMutation(request, path, notFound(), current.userId, id)
			);
		}
		return null;
	};
}
