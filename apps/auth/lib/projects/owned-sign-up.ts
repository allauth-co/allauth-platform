import { randomInt } from "node:crypto";
import type { Pool } from "pg";
import * as z from "zod";
import { passwordPolicyError } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { validAvatarPath } from "../avatars/protocol";
import { clerkCompatiblePasswords } from "../clerk-password";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";
import type { SessionCheckAdmission } from "./session-introspection-admission";
import { checkedProjectSchema, projectOrigin, projectSlug } from "./validation";

const alphabet =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const signUpInput = z.object({
	name: z.string().max(256),
	email: z.email().max(320),
	password: z.string().min(1),
	image: z.string().max(2048).optional(),
	callbackURL: z.string().max(2048).optional(),
	rememberMe: z.boolean().optional(),
	username: z.string().max(256).optional(),
	displayUsername: z.string().max(256).optional(),
});
const availabilityInput = z.object({ username: z.string().max(256) });

type SignUpOperation = "sign-up/email" | "is-username-available";
type PasswordSafety = "allowed" | "breached" | "unavailable";

export interface SignUpVerification {
	callbackURLs: readonly string[];
	/** Schedule approved mail work after the response without awaiting it. */
	defer(work: () => Promise<void>): void;
	send(
		user: { id: string; email: string; name: string },
		callbackURL: string,
	): Promise<void>;
	onFailure?(): void;
}

export interface OwnedSignUpOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	policy: AuthPolicy;
	checkPasswordSafety(password: string): Promise<PasswordSafety>;
	/** Meter trusted ingress and enforce signup security policy before password hashing. */
	admit(
		request: Request,
		operation: SignUpOperation,
		normalizedIdentity: string,
	): Promise<SessionCheckAdmission | Response>;
	verification?: SignUpVerification;
}

function randomId() {
	return Array.from(
		{ length: 32 },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
}

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

function failure(
	status: number,
	code: string,
	message: string,
	headers?: Headers,
) {
	return json({ code, message }, status, headers);
}

function unavailable() {
	return failure(
		503,
		"SIGN_UP_UNAVAILABLE",
		"Sign-up is temporarily unavailable.",
	);
}

function rateLimited(retryAfter: number) {
	return failure(
		429,
		"TOO_MANY_REQUESTS",
		"Too many requests.",
		new Headers({
			"Retry-After": String(
				Number.isFinite(retryAfter) ? Math.max(1, Math.ceil(retryAfter)) : 1,
			),
		}),
	);
}

function usernameError(username: string) {
	if (!username)
		return { code: "INVALID_USERNAME", message: "Username is invalid" };
	if (username.length < 3)
		return { code: "USERNAME_TOO_SHORT", message: "Username is too short" };
	if (username.length > 30)
		return { code: "USERNAME_TOO_LONG", message: "Username is too long" };
	if (!/^[a-zA-Z0-9_.]+$/.test(username))
		return { code: "INVALID_USERNAME", message: "Username is invalid" };
	return null;
}

function safeCallback(value: string, caller: string) {
	if (!value || value.startsWith("//") || /[\\\u0000-\u0020\u007f]/.test(value))
		return null;
	try {
		const url = new URL(value, caller);
		return url.username || url.password ? null : url;
	} catch {
		return null;
	}
}

async function readBody(request: Request, form: boolean): Promise<unknown> {
	const contentType = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		.trim()
		.toLowerCase();
	const isForm = form && contentType === "application/x-www-form-urlencoded";
	if (!isForm && contentType !== "application/json") return undefined;
	const reader = request.body?.getReader();
	if (!reader) return undefined;
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let length = 0;
	let body = "";
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > 8192) {
				void reader.cancel().catch(() => {});
				return undefined;
			}
			body += decoder.decode(value, { stream: true });
		}
		body += decoder.decode();
		if (!isForm) return JSON.parse(body);
		const fields = new URLSearchParams(body);
		const keys = [...fields.keys()];
		if (keys.length !== new Set(keys).size) return undefined;
		return Object.fromEntries(
			[...fields].map(([key, value]) =>
				key === "rememberMe" && (value === "true" || value === "false")
					? [key, value === "true"]
					: [key, value],
			),
		);
	} catch {
		return undefined;
	} finally {
		reader.releaseLock();
	}
}

/** Own signup for the already authenticated ingress/realm without minting a session. */
export function createOwnedSignUpHttp(options: OwnedSignUpOptions) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	const schema = checkedProjectSchema(options.project.schemaName);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid owned sign-up route.");
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEngineStore(options.database, schema);
	const verification = options.verification;
	const callbacks =
		verification?.callbackURLs.map((value) => {
			const url = safeCallback(value, origin);
			if (
				!url ||
				!origins.has(url.origin) ||
				url.hash ||
				value.length > 2048 ||
				url.searchParams.has("token") ||
				url.searchParams.has("error")
			)
				throw new Error("Invalid sign-up verification callback.");
			return url.href;
		}) ?? [];

	function scheduleVerification(
		user: { id: string; email: string; name: string } | null,
		callbackURL: string,
	) {
		try {
			verification?.defer(async () => {
				if (!user) return;
				try {
					await verification.send(user, callbackURL);
				} catch {
					verification.onFailure?.();
				}
			});
		} catch {
			verification?.onFailure?.();
		}
	}

	async function signUp(request: Request, caller: string) {
		if (!policy.signUpEnabled || !policy.emailAndPasswordEnabled)
			return failure(
				400,
				"EMAIL_PASSWORD_SIGN_UP_DISABLED",
				"Email and password sign up is not enabled",
			);
		const parsed = signUpInput.safeParse(await readBody(request, true));
		if (!parsed.success)
			return failure(
				400,
				"INVALID_BODY",
				"Supply a valid name, email and password.",
			);
		const input = parsed.data;
		const error = passwordPolicyError(input.password, policy.passwordPolicy);
		if (error) {
			const code =
				input.password.length < policy.passwordPolicy.minLength
					? "PASSWORD_TOO_SHORT"
					: input.password.length > policy.passwordPolicy.maxLength
						? "PASSWORD_TOO_LONG"
						: "PASSWORD_REQUIREMENTS_NOT_MET";
			return failure(400, code, error);
		}
		const unnormalized =
			input.username ??
			(input.displayUsername && !usernameError(input.displayUsername)
				? input.displayUsername
				: undefined);
		if (unnormalized !== undefined) {
			const invalid = usernameError(unnormalized);
			if (invalid) return json(invalid, 400);
		}
		if (input.image) {
			try {
				if (validAvatarPath(new URL(input.image, caller).pathname))
					return failure(
						400,
						"INVALID_PROFILE_IMAGE",
						"Choose the original profile photo uploaded for your current account.",
					);
			} catch {
				// Preserve opaque external profile-image values from the existing contract.
			}
		}
		const selectedCallback =
			input.callbackURL === undefined
				? (callbacks[0] ?? null)
				: (safeCallback(input.callbackURL, caller)?.href ?? null);
		if (
			input.callbackURL !== undefined &&
			(!selectedCallback ||
				!origins.has(new URL(selectedCallback).origin) ||
				(policy.requireEmailVerification &&
					!callbacks.includes(selectedCallback)))
		)
			return failure(
				403,
				"FORBIDDEN",
				"This authentication callback is not permitted.",
			);
		if (policy.requireEmailVerification && (!verification || !selectedCallback))
			return unavailable();

		const address = input.email.toLowerCase();
		const decision = await options.admit(request, "sign-up/email", address);
		if (decision instanceof Response) return decision;
		if (!decision.allowed && decision.retryAfter !== 0)
			return rateLimited(decision.retryAfter);
		const now = new Date();
		const user = {
			id: randomId(),
			name: input.name,
			email: address,
			image: input.image ?? null,
			emailVerified: false,
			createdAt: now,
			updatedAt: now,
			role: "user",
			banned: false,
			banReason: null,
			banExpires: null,
			twoFactorEnabled: false,
			isAnonymous: false,
			publicMetadata: null,
			username: unnormalized?.toLowerCase() ?? null,
			displayUsername: input.displayUsername || unnormalized || null,
		};
		if (!decision.allowed) {
			if (policy.requireEmailVerification && selectedCallback)
				scheduleVerification(null, selectedCallback);
			return json({ token: null, user });
		}
		let safe: PasswordSafety;
		try {
			safe = await options.checkPasswordSafety(input.password);
		} catch {
			return unavailable();
		}
		if (safe === "breached")
			return failure(
				400,
				"PASSWORD_COMPROMISED",
				"The password you entered has been compromised. Please choose a different password.",
			);
		if (safe !== "allowed") return unavailable();

		// Hash before the uniqueness gate so the duplicate email takes the same password work.
		const hashed = await clerkCompatiblePasswords.hash(input.password);
		const outcome = await store.transaction(async (client) => {
			const inserted = await client.query<{ id: string }>(
				`INSERT INTO "user" (id,name,email,image,"emailVerified","createdAt","updatedAt",role,banned,
					"twoFactorEnabled","isAnonymous","directoryManaged","directoryDisabled",username,"displayUsername")
				VALUES ($1,$2,$3,$4,false,$5,$5,'user',false,false,false,false,false,$6,$7)
				ON CONFLICT DO NOTHING RETURNING id`,
				[
					user.id,
					user.name,
					user.email,
					user.image,
					now,
					user.username,
					user.displayUsername,
				],
			);
			if (!inserted.rows[0]) {
				if (user.username) {
					const conflict = await client.query<{ found: boolean }>(
						'SELECT EXISTS (SELECT 1 FROM "user" WHERE username = $1) AS found',
						[user.username],
					);
					if (conflict.rows[0]?.found) return "username-taken";
				}
				return "duplicate";
			}
			const accountId = randomId();
			await client.query(
				`INSERT INTO "account" (id,"accountId","providerId","userId",password,"createdAt","updatedAt")
				VALUES ($1,$2,'credential',$2,$3,$4,$4)`,
				[accountId, user.id, hashed, now],
			);
			await store.record(
				client,
				"user.created",
				"success",
				"/sign-up/email",
				user.id,
				user.id,
			);
			await store.record(
				client,
				"account.linked",
				"success",
				"/sign-up/email",
				user.id,
				accountId,
			);
			return "created";
		});
		if (outcome === "username-taken")
			return failure(
				400,
				"USERNAME_IS_ALREADY_TAKEN",
				"Username is already taken. Please try another.",
			);
		if (policy.requireEmailVerification && selectedCallback)
			scheduleVerification(
				outcome === "created"
					? { id: user.id, email: user.email, name: user.name }
					: null,
				selectedCallback,
			);
		return json({ token: null, user });
	}

	async function availability(request: Request) {
		const input = availabilityInput.safeParse(await readBody(request, false));
		if (!input.success)
			return failure(400, "INVALID_BODY", "Supply a username.");
		const invalid = usernameError(input.data.username);
		if (invalid) return json(invalid, 422);
		const normalized = input.data.username.toLowerCase();
		const decision = await options.admit(
			request,
			"is-username-available",
			normalized,
		);
		if (decision instanceof Response) return decision;
		if (!decision.allowed) return rateLimited(decision.retryAfter);
		const result = await options.database.query<{ available: boolean }>(
			`SELECT NOT EXISTS (SELECT 1 FROM "${schema}"."user" WHERE username = $1) AS available`,
			[normalized],
		);
		return json({ available: result.rows[0]?.available === true });
	}

	return async function dispatch(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(`${options.basePath}/`)) return null;
		const path = url.pathname.slice(options.basePath.length + 1);
		if (path !== "sign-up/email" && path !== "is-username-available")
			return null;
		if (request.method !== "POST")
			return failure(
				405,
				"METHOD_NOT_ALLOWED",
				"Method not allowed.",
				new Headers({ Allow: "POST" }),
			);
		const caller = request.headers.get("origin");
		if (
			url.origin !== origin ||
			!caller ||
			!origins.has(caller) ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			return failure(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		return path === "sign-up/email"
			? signUp(request, caller)
			: availability(request);
	};
}
