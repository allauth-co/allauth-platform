import { createHash, randomUUID } from "node:crypto";
import { jwtVerify, SignJWT } from "jose";
import { JWTExpired } from "jose/errors";
import type { PoolClient } from "pg";
import type { ControlEventInput } from "../control/types";
import { DatabaseError } from "pg";
import * as z from "zod";
import type {
	ProjectAccountAuthority,
	ProjectAccountLinkOptions,
} from "./owned-project-account-links";
import {
	accountLinkError,
	accountLinkHeaders,
	accountLinkJson,
	accountLinkRedirect,
	createProjectAccountLinks,
} from "./owned-project-account-links";
import type { ProjectUser } from "./owned-project-engine-store";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";

const age = 3600;
const purpose = "allauth-email-change";
const address = z.email().max(320);
const change = z.object({
	newEmail: address,
	callbackURL: z.string().max(2048).optional(),
});
const stages = z.enum([
	"change-email-confirmation",
	"change-email-verification",
]);
const claims = z.object({
	email: address,
	updateTo: address,
	requestType: stages,
	iat: z.number().int().nonnegative(),
	exp: z.number().int().nonnegative(),
	sub: z.string().min(1).max(160).optional(),
	purpose: z.literal(purpose).optional(),
	issuedAtMS: z.number().int().nonnegative().optional(),
});
type Stage = z.infer<typeof stages>;
type Proof = z.infer<typeof claims>;

export interface OwnedProjectEmailChangeOptions
	extends ProjectAccountLinkOptions {
	signingSecret: string;
	auditContext?(
		request: Request,
	): Pick<ControlEventInput, "ipAddress" | "userAgent">;
	/** Meter change links after their purpose is authenticated. */
	admitVerification?(request: Request): Promise<Response | null>;
	/** Retain the live session or use the project's normal MFA/session admission for a new browser. */
	complete(
		client: PoolClient,
		input: {
			request: Request;
			user: ProjectUser;
			current: ProjectAccountAuthority | null;
			callbackURL?: string;
		},
	): Promise<Headers | Response>;
}

function allowed(user: ProjectUser | null): user is ProjectUser {
	return Boolean(
		user &&
			!user.banned &&
			!user.isAnonymous &&
			!user.directoryDisabled &&
			!user.directoryManaged,
	);
}

function failed(code: string, callback?: URL) {
	if (!callback)
		return accountLinkError(
			401,
			code,
			"Invalid or expired email change token.",
		);
	callback.searchParams.set("error", code);
	return accountLinkRedirect(callback);
}

/** Native-readable email change proofs and authoritative, single-use account updates. */
export function createOwnedProjectEmailChange(
	options: OwnedProjectEmailChangeOptions,
) {
	const links = createProjectAccountLinks(options);
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);
	if (options.signingSecret.length < 32)
		throw new Error("Invalid email change signing secret.");
	const secret = new TextEncoder().encode(options.signingSecret);

	function issue(user: ProjectUser, newEmail: string, requestType: Stage) {
		const issuedAtMS = Date.now();
		const now = Math.floor(issuedAtMS / 1000);
		return new SignJWT({
			email: user.email,
			updateTo: newEmail,
			requestType,
			purpose,
			issuedAtMS,
		})
			.setSubject(user.id)
			.setJti(randomUUID())
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt(now)
			.setExpirationTime(now + age)
			.sign(secret);
	}

	async function deletionPending(client: PoolClient, userId: string) {
		return Boolean(
			(
				await client.query(
					'SELECT 1 FROM "verification" WHERE id=$1 AND "expiresAt" > clock_timestamp()',
					[`allauth-account-deletion:${userId}`],
				)
			).rowCount,
		);
	}

	async function targetExists(client: PoolClient, email: string) {
		return Boolean(
			(await client.query('SELECT 1 FROM "user" WHERE email=$1', [email]))
				.rowCount,
		);
	}

	async function start(request: Request, input: unknown) {
		if (!links.requestURL(request, "POST", "/change-email"))
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		const parsed = change.safeParse(input);
		if (!parsed.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"Supply a valid new email address.",
			);
		const destination = links.callback(
			parsed.data.callbackURL,
			request.headers.get("origin") ?? undefined,
		);
		if (!destination)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication destination is not permitted.",
			);
		const newEmail = parsed.data.newEmail.toLowerCase();
		const result = await store.transaction(async (client) => {
			const current = await options.authority(client, request);
			const audit = {
				type: "user.email-change-requested",
				...options.auditContext?.(request),
			};
			if (!current) {
				await store.recordEvent(client, {
					...audit,
					outcome: "failure",
					metadata: { path: "/change-email", errorCode: "UNAUTHORIZED" },
				});
				return accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
			}
			if (current.impersonatedBy || current.eligible === false)
				return accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
			const user = await store.lockUser(client, current.userId);
			if (
				!allowed(user) ||
				!(await store.lockSession(client, current.token, user.id, false))
			)
				return accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
			if (await deletionPending(client, user.id))
				return accountLinkError(
					409,
					"DELETION_PENDING",
					"Account deletion is already being processed.",
				);
			const attributed = {
				...audit,
				actorId: user.id,
				userId: user.id,
			};
			if (newEmail === user.email) {
				await store.recordEvent(client, {
					...attributed,
					outcome: "failure",
					metadata: {
						path: "/change-email",
						errorCode: "AUTHENTICATION_FAILED",
					},
				});
				return accountLinkError(400, "BAD_REQUEST", "Email is the same");
			}
			await store.recordEvent(client, {
				...attributed,
				outcome: "success",
				metadata: { path: "/change-email" },
			});
			const kind = user.emailVerified
				? "change-email-confirmation"
				: "change-email-verification";
			const token = await issue(user, newEmail, kind);
			if (await targetExists(client, newEmail)) return null;

			return {
				kind,
				user: {
					id: user.id,
					name: user.name,
					email: user.emailVerified ? user.email : newEmail,
				},
				url: links.mail("/verify-email", token, destination),
			} as const;
		});
		if (result instanceof Response) return result;
		if (result) links.schedule(result);
		return accountLinkJson({ status: true });
	}

	async function verify(request: Request) {
		const url = links.requestURL(request, "GET", "/verify-email");
		if (!url) return null;
		const tokens = url.searchParams.getAll("token");
		if (tokens.length !== 1 || !tokens[0] || tokens[0].length > 2048)
			return null;
		const token = tokens[0];
		let proof: Proof;
		let expired = false;
		try {
			const verified = await jwtVerify(token, secret, {
				algorithms: ["HS256"],
				requiredClaims: ["iat", "exp"],
				maxTokenAge: age,
			});
			if (
				verified.payload.updateTo === undefined &&
				!stages.safeParse(verified.payload.requestType).success
			)
				return null;
			const parsed = claims.safeParse(verified.payload);
			if (!parsed.success) return failed("INVALID_TOKEN");
			proof = parsed.data;
		} catch (error) {
			if (!(error instanceof JWTExpired)) return null;
			const parsed = claims.safeParse(error.payload);
			if (!parsed.success) return null;
			proof = parsed.data;
			expired = true;
		}
		const callbacks = url.searchParams.getAll("callbackURL");
		const destination = callbacks[0] ? links.callback(callbacks[0]) : undefined;
		if (callbacks.length > 1 || destination === null)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication destination is not permitted.",
			);
		const deniedAdmission = await options.admitVerification?.(request);
		if (deniedAdmission) return deniedAdmission;
		if (expired) return failed("TOKEN_EXPIRED", destination);
		const oldEmail = proof.email.toLowerCase();
		const newEmail = proof.updateTo.toLowerCase();
		if (
			oldEmail === newEmail ||
			proof.exp <= proof.iat ||
			proof.exp - proof.iat > age ||
			(proof.purpose === purpose &&
				(!proof.sub ||
					proof.issuedAtMS === undefined ||
					Math.floor(proof.issuedAtMS / 1000) !== proof.iat)) ||
			(proof.purpose === undefined &&
				(proof.sub !== undefined || proof.issuedAtMS !== undefined))
		)
			return failed("INVALID_TOKEN", destination);
		const reservation = `allauth-change-email-used:${createHash("sha256").update(token).digest("base64url")}`;
		const abort = Symbol("email change session admission failed");
		let denied: Response | undefined;
		try {
			const result = await store.transaction(async (client) => {
				const found = await client.query<{ id: string; createdAt: Date }>(
					'SELECT id, "createdAt" FROM "user" WHERE email=$1 AND ($2::text IS NULL OR id=$2) FOR UPDATE',
					[oldEmail, proof.sub ?? null],
				);
				const owner = found.rows[0];
				if (!owner || Math.floor(owner.createdAt.getTime() / 1000) > proof.iat)
					return failed("USER_NOT_FOUND", destination);
				const user = await store.lockUser(client, owner.id);
				if (
					!allowed(user) ||
					user.email !== oldEmail ||
					(await deletionPending(client, user.id))
				)
					return failed("INVALID_USER", destination);
				const current = await options.authority(client, request);
				if (
					current &&
					(current.impersonatedBy ||
						current.eligible === false ||
						current.userId !== user.id ||
						!(await store.lockSession(client, current.token, user.id, false)))
				)
					return failed("INVALID_USER", destination);
				const generationKey = `allauth-change-email-generation:${user.id}`;
				const generation = await client.query<{ value: string }>(
					'SELECT value FROM "verification" WHERE id=$1 AND "expiresAt" > statement_timestamp()',
					[generationKey],
				);
				const lastChanged = Number(generation.rows[0]?.value ?? 0);
				if (
					(proof.issuedAtMS ?? proof.iat * 1000) <= lastChanged ||
					(await targetExists(client, newEmail))
				)
					return failed("INVALID_TOKEN", destination);
				const consumed = await client.query(
					`INSERT INTO "verification"(id,identifier,value,"expiresAt") VALUES ($1,$1,$2,$3) ON CONFLICT (id) DO NOTHING`,
					[reservation, user.id, new Date(proof.exp * 1000)],
				);
				if (!consumed.rowCount) return failed("INVALID_TOKEN", destination);
				if (proof.requestType === "change-email-confirmation") {
					const next = await issue(user, newEmail, "change-email-verification");
					return {
						kind: "change-email-verification",
						user: { id: user.id, email: newEmail, name: user.name },
						url: links.mail(
							"/verify-email",
							next,
							destination ?? links.callback(undefined)!,
						),
					} as const;
				}
				await client.query(
					'UPDATE "user" SET email=$1, "emailVerified"=TRUE, "updatedAt"=statement_timestamp() WHERE id=$2',
					[newEmail, user.id],
				);
				// Recovery and deletion links from the former mailbox are bound to the user ID.
				await client.query(
					`DELETE FROM "verification" WHERE value=$1 AND (starts_with(identifier, 'reset-password:') OR starts_with(identifier, 'delete-account-'))`,
					[user.id],
				);
				await client.query(
					`INSERT INTO "verification"(id,identifier,value,"expiresAt") VALUES ($1,$1,$2,statement_timestamp() + interval '1 hour')
					 ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, "expiresAt"=EXCLUDED."expiresAt", "updatedAt"=statement_timestamp()`,
					[generationKey, String(Date.now())],
				);
				const updated = await store.lockUser(client, user.id);
				if (!updated) throw abort;
				await store.record(
					client,
					"user.updated",
					"success",
					"/verify-email",
					user.id,
					user.id,
				);
				await store.recordEvent(client, {
					type: "user.email-verified",
					outcome: "success",
					actorId: user.id,
					userId: user.id,
					targetId: user.id,
					...options.auditContext?.(request),
					metadata: { path: "/verify-email" },
				});
				const completed = await options.complete(client, {
					request,
					user: updated,
					current,
					callbackURL: destination?.href,
				});
				if (completed instanceof Response) {
					if (completed.status >= 400) {
						denied = completed;
						throw abort;
					}
					return new Response(completed.body, {
						status: completed.status,
						headers: accountLinkHeaders(new Headers(completed.headers)),
					});
				}
				return destination
					? accountLinkRedirect(destination, completed)
					: accountLinkJson(
							{ status: true, user: projectUserResponse(updated) },
							200,
							completed,
						);
			});
			if (result instanceof Response) return result;
			links.schedule(result);
			return destination
				? accountLinkRedirect(destination)
				: accountLinkJson({ status: true });
		} catch (error) {
			if (error === abort) return denied ?? failed("INVALID_USER", destination);
			if (
				error instanceof DatabaseError &&
				error.code === "23505" &&
				error.constraint === "user_email_key"
			)
				return failed("INVALID_TOKEN", destination);
			throw error;
		}
	}

	return { start, verify };
}
