import { randomBytes, randomUUID } from "node:crypto";
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
} from "@simplewebauthn/server";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { projectPasskeyStore } from "./passkey-store";
import type { StoredProjectPasskey } from "./passkey-store";
import { projectPasskeyVerification } from "./passkey-verification";
import type { ProjectPasskeyChallenge } from "./passkey-verification";
import { checkedProjectSchema } from "./validation";

const challengeMaxAge = 300;
const webAuthnBytes = 262144;
const identifier = z.string().min(1).max(160);
const name = z.string().trim().min(1).max(256);
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
	response: credentialResponse.extend({
		response: z.object({
			clientDataJSON: encoded,
			attestationObject: encoded,
			transports: z.array(transports).max(8).optional(),
		}),
	}),
	name: name.optional(),
	createSession: z.boolean().optional(),
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

interface PasskeySession {
	userId: string;
	email: string;
}

interface Options {
	database: Pool;
	schemaName: string;
	cookiePrefix: string;
	signingSecret: string;
	rp: {
		id: string;
		name: string;
		origins: readonly string[];
		requireUserVerification: boolean;
	};
	readBody: (request: Request, limit: number) => Promise<unknown>;
	writeCookie: (
		headers: Headers,
		name: string,
		value: string,
		maxAge?: number,
	) => void;
	readSession: (
		request: Request,
		fresh: boolean,
	) => Promise<PasskeySession | null>;
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
	json({ code: "UNAUTHORIZED", message: "Authentication required." }, 401);
const notFound = () =>
	json({ code: "PASSKEY_NOT_FOUND", message: "Passkey not found" }, 404);
const challengeNotFound = () =>
	json({ code: "CHALLENGE_NOT_FOUND", message: "Challenge not found" }, 400);

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
	const schema = checkedProjectSchema(options.schemaName);
	const store = projectPasskeyStore(options.database, schema);
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
		const session = await options.readSession(request, true);
		if (!session) return unauthorized();
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
		const session = await options.readSession(request, false);
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
		const input = authentication.safeParse(
			await options.readBody(request, webAuthnBytes),
		);
		if (!input.success) return invalid();
		const token = readLegacySessionCookie(
			request.headers,
			cookie,
			options.signingSecret,
		);
		if (!token) return challengeNotFound();
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
		if (result.ok && response) return withExpiredCookie(response, clear);
		const failed =
			!result.ok && result.reason === "challenge"
				? challengeNotFound()
				: json(
						{ code: "AUTHENTICATION_FAILED", message: "Authentication failed" },
						401,
					);
		return withExpiredCookie(failed, clear);
	}

	async function verifyRegistration(request: Request) {
		const session = await options.readSession(request, true);
		if (!session) return unauthorized();
		const refused = await options.admit(request, "verification");
		if (refused) return refused;
		const input = registration.safeParse(
			await options.readBody(request, webAuthnBytes),
		);
		if (!input.success) return invalid();
		const token = readLegacySessionCookie(
			request.headers,
			cookie,
			options.signingSecret,
		);
		if (!token) return challengeNotFound();
		let signIn: Response | undefined;
		const registrationRefused = Symbol("Session issuance was refused");
		const result = await verify
			.register({
				token,
				name: input.data.name,
				response: input.data.response satisfies RegistrationResponseJSON,
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
						return saved;
					});
				},
			})
			.catch((error: unknown) => {
				if (error === registrationRefused) return null;
				throw error;
			});
		if (!result && signIn) return withExpiredCookie(signIn, clear);
		if (!result) return withExpiredCookie(challengeNotFound(), clear);
		if (!result.ok) {
			const failed =
				result.reason === "challenge"
					? challengeNotFound()
					: json(
							{
								code: "FAILED_TO_VERIFY_REGISTRATION",
								message: "Failed to verify registration",
							},
							400,
						);
			return withExpiredCookie(failed, clear);
		}
		const headers = new Headers(signIn?.headers);
		clear(headers);
		const data = signIn
			? ((await signIn.json()) as Record<string, unknown>)
			: {};
		return json({ ...result.value, ...data }, 200, headers);
	}

	return async (path: string, request: Request): Promise<Response | null> => {
		if (request.method === "GET") {
			if (path === "/passkey/generate-register-options")
				return generateRegistration(request);
			if (path === "/passkey/generate-authenticate-options")
				return generateAuthentication(request);
			if (path === "/passkey/list-user-passkeys") {
				const current = await options.readSession(request, false);
				return current
					? json(await store.listForUser(current.userId))
					: unauthorized();
			}
		}
		if (request.method === "POST") {
			if (path === "/passkey/verify-registration")
				return verifyRegistration(request);
			if (path === "/passkey/verify-authentication")
				return verifyAuthentication(request);
			if (
				path !== "/passkey/delete-passkey" &&
				path !== "/passkey/update-passkey"
			)
				return null;
			const current = await options.readSession(request, false);
			if (!current) return unauthorized();
			const input = z
				.object({ id: identifier, name: name.optional() })
				.safeParse(await options.readBody(request, 8192));
			if (!input.success) return invalid();
			const { id, name: updatedName } = input.data;
			if (path === "/passkey/delete-passkey") {
				const removed = await options.withSession(
					request,
					current.userId,
					false,
					(client) => store.removeForUser(current.userId, id, client),
				);
				return removed ? json({ status: true }) : notFound();
			}
			if (!updatedName) return invalid();
			const updated = await options.withSession(
				request,
				current.userId,
				false,
				(client) =>
					store.renameForUser(current.userId, id, updatedName, client),
			);
			return updated ? json({ passkey: updated }) : notFound();
		}
		return null;
	};
}
