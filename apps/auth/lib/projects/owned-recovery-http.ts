import { randomInt, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import * as z from "zod";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import type { ApplicationBranding } from "../branding/types";
import type { ControlEventInput } from "../control/types";
import {
	hostedPasswordSignInRequests,
	hostedVerificationLinkRequests,
} from "../domains/hosted-oauth-requests";
import { authenticationEmail } from "../email/authentication";
import type { EmailEnvironment } from "../email/send";
import { emailConfigured, sendAuthEmail } from "../email/send";
import type { CompleteOwnedEmailVerification } from "./owned-email-verification";
import { createOwnedEmailVerification } from "./owned-email-verification";
import {
	createOwnedPasswordReset,
	findOwnedPasswordResetUser,
	isLegacyPasswordResetToken,
} from "./owned-password-reset";
import type { OwnedEmailCallbackPolicy } from "./owned-project-email-callback";
import type { OwnedProjectEmailAliases, ProjectEmailIdentity } from "./owned-project-email-aliases";
import { scheduleOwnedEmailDelivery } from "./owned-project-email-delivery";
import type {
	EmailOTPRecoveryIssueOperation,
	EmailOTPRecoveryOperation,
} from "./owned-project-email-otp-recovery";
import { createOwnedEmailOTPRecovery } from "./owned-project-email-otp-recovery";
import { readProjectEmailProofBody, readSharedProjectEmailOtpBody } from "./owned-project-email-proof-body";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";
import type { SessionCheckAdmission } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const alphabet =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const email = z.email().max(320);
const maximumCallbackLength = 2048;
const maximumHostedEmailURLLength = 16_384;
const maximumHostedResetBodyBytes = maximumHostedEmailURLLength + 1024;
const resetTokenLength = 24;
const callback = z.string().max(maximumCallbackLength).optional();
const resetRequest = z.object({ email, redirectTo: callback }).strict();
const hostedResetRequest = resetRequest.extend({
	redirectTo: z.string().max(maximumHostedEmailURLLength).optional(),
});
const verifyRequest = z.object({ email, callbackURL: callback }).strict();
const resetInput = z
	.object({
		newPassword: z.string(),
		token: z.string().max(128).optional(),
	})
	.strict();

export type RecoveryOperation =
	| "request-password-reset"
	| "reset-password-callback"
	| "reset-password"
	| "send-verification-email"
	| "verify-email"
	| EmailOTPRecoveryOperation;

export interface RecoveryHttpOptions {
	database: Pool;
	emailAliases?: OwnedProjectEmailAliases;
	project: Pick<Project, "schemaName" | "slug">;
	policy: AuthPolicy;
	signingSecret: string;
	baseURL: string;
	basePath: string;
	/** Canonical auth route used in mail. This can be the project's app proxy. */
	publicLinkBaseURL: string;
	trustedOrigins: readonly string[];
	resetCallbackURLs: readonly string[];
	verificationCallbackURLs: readonly string[];
	callbackPolicy?: OwnedEmailCallbackPolicy;
	verifyHostedVerificationContinuation?(target: URL): Promise<boolean>;
	auditContext?(
		request: Request,
	): Pick<ControlEventInput, "ipAddress" | "userAgent">;
	email: { environment: EmailEnvironment; branding?: ApplicationBranding };
	checkPasswordSafety: Parameters<
		typeof createOwnedPasswordReset
	>[0]["checkPasswordSafety"];
	/** Check trusted ingress and meter each operation before any state or email work. */
	admit(
		request: Request,
		operation: RecoveryOperation,
		normalizedEmail?: string,
	): Promise<SessionCheckAdmission | Response>;
	/** Schedule the callback after the response without awaiting delivery in the request. */
	defer(delivery: () => Promise<void>): void;
	onDeliveryFailure?(
		operation:
			| "request-password-reset"
			| "send-verification-email"
			| EmailOTPRecoveryIssueOperation,
	): void;
	completeVerification?: CompleteOwnedEmailVerification;
}

function privateHeaders(headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	headers.set("Referrer-Policy", "no-referrer");
	return headers;
}

function json(value: unknown, status = 200, headers?: Headers) {
	return Response.json(value, { status, headers: privateHeaders(headers) });
}

function failure(
	status: number,
	code: string,
	message: string,
	headers?: Headers,
) {
	return json({ code, message }, status, headers);
}

function forbidden() {
	return failure(
		403,
		"FORBIDDEN",
		"This authentication request is not permitted.",
	);
}

function redirect(callbackURL: URL, name?: string, value?: string) {
	if (name && value !== undefined) callbackURL.searchParams.set(name, value);
	return new Response(null, {
		status: 302,
		headers: privateHeaders(new Headers({ Location: callbackURL.href })),
	});
}

function validURL(value: string, maximumLength = maximumCallbackLength) {
	if (
		!value ||
		value.length > maximumLength ||
		value.startsWith("//") ||
		/[\\\u0000-\u0020\u007f]/.test(value)
	)
		return false;
	return true;
}

function configuredCallbacks(values: readonly string[], origins: Set<string>) {
	if (!values.length)
		throw new Error("An explicit authentication callback is required.");
	return values.map((value) => {
		const url = new URL(value);
		if (
			!validURL(value) ||
			!origins.has(url.origin) ||
			url.username ||
			url.password ||
			url.hash ||
			url.searchParams.has("token") ||
			url.searchParams.has("error")
		)
			throw new Error("Invalid authentication callback configuration.");
		return url.href;
	});
}

async function boundedJson(
	request: Request,
	maximumBytes = 8192,
): Promise<unknown> {
	if (
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			.trim()
			.toLowerCase() !== "application/json"
	)
		return undefined;
	const reader = request.body?.getReader();
	if (!reader) return undefined;
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let length = 0;
	let source = "";
	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) return JSON.parse(source + decoder.decode());
			length += value.byteLength;
			if (length > maximumBytes) {
				void reader.cancel().catch(() => {});
				return undefined;
			}
			source += decoder.decode(value, { stream: true });
		}
	} catch {
		return undefined;
	} finally {
		reader.releaseLock();
	}
}

/** Isolated project handler for the existing email-link routes. No fallback on a handled request. */
export function createOwnedRecoveryHttp(options: RecoveryHttpOptions) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid owned recovery route.");
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	const linkBase = new URL(options.publicLinkBaseURL);
	if (
		!validURL(options.publicLinkBaseURL) ||
		!origins.has(linkBase.origin) ||
		linkBase.username ||
		linkBase.password ||
		linkBase.search ||
		linkBase.hash ||
		!/^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+$/.test(linkBase.pathname)
	)
		throw new Error("Invalid recovery email link base.");
	const resetCallbacks = configuredCallbacks(
		options.resetCallbackURLs,
		origins,
	);
	const verifyCallbacks = configuredCallbacks(
		options.verificationCallbackURLs,
		origins,
	);
	const hostedRecovery =
		options.basePath === "/api/auth" &&
		linkBase.origin === origin &&
		Boolean(options.callbackPolicy);
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);
	const reset = createOwnedPasswordReset({
		...options,
		schemaName: options.project.schemaName,
	});
	const emailOTP = createOwnedEmailOTPRecovery({
		...options,
		schemaName: options.project.schemaName,
		admit: admission,
	});
	const verification = createOwnedEmailVerification({
		...options,
		schemaName: options.project.schemaName,
	});
	const brand = options.email.branding;
	const appName = brand?.name || "AllAuth";

	function selectCallback(
		value: string | undefined,
		flow: "verification" | "password-reset",
		phase: Parameters<OwnedEmailCallbackPolicy>[2],
		caller = linkBase.origin,
		allowHostedVerification = false,
	): ReturnType<OwnedEmailCallbackPolicy> {
		const approved = flow === "verification" ? verifyCallbacks : resetCallbacks;
		if (value === undefined) return { url: new URL(approved[0]) };
		let selectedFlow: Parameters<OwnedEmailCallbackPolicy>[1] = flow;
		if (
			hostedRecovery &&
			caller === origin &&
			value.length > maximumCallbackLength
		) {
			if (flow === "password-reset") selectedFlow = "hosted-password-reset";
			else if (allowHostedVerification)
				selectedFlow = "hosted-password-verification";
		}
		const extended = selectedFlow !== flow;
		if (!validURL(value, extended ? maximumHostedEmailURLLength : undefined))
			return null;
		try {
			const target = new URL(value, caller);
			if (approved.includes(target.href)) return { url: target };
			if (
				extended &&
				(target.origin !== origin ||
					target.href.length > maximumHostedEmailURLLength)
			)
				return null;
			return origins.has(target.origin)
				? (options.callbackPolicy?.(target, selectedFlow, phase) ?? null)
				: null;
		} catch {
			return null;
		}
	}

	function emailURL(path: string, callbackURL: URL | string, token?: string) {
		const link = new URL(`${linkBase.pathname}${path}`, linkBase.origin);
		link.searchParams.set("callbackURL", callbackURL.toString());
		if (token) link.searchParams.set("token", token);
		return link.href;
	}

	type Recipient = { id: string; name: string; email: string };
	const recipientQuery = `SELECT id, name, email FROM "user" WHERE email = $1
		AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true
		AND "directoryManaged" IS DISTINCT FROM true AND "isAnonymous" IS DISTINCT FROM true`;

	async function prepareReset(
		request: Request,
		identity: ProjectEmailIdentity,
		destination: URL,
	) {
		const token = Array.from(
			{ length: resetTokenLength },
			() => alphabet[randomInt(alphabet.length)],
		).join("");
		const user = await store.transaction(async (client) => {
			const result = await client.query<Recipient>(
				`WITH recipient AS (${recipientQuery}
					AND ($4::text IS NULL OR (id = $4 AND "emailVerified" IS TRUE)) FOR UPDATE),
				issued AS (
					INSERT INTO "verification" (id, identifier, value, "expiresAt")
					SELECT $2, $3, id, statement_timestamp() + interval '1 hour' FROM recipient
					RETURNING value
				)
				SELECT recipient.* FROM recipient JOIN issued ON issued.value = recipient.id`,
				[identity.email, randomUUID(), `reset-password:${token}`, identity.userId ?? null],
			);
			await store.recordEvent(client, {
				type: "user.password-reset-requested",
				outcome: "success",
				...options.auditContext?.(request),
				metadata: { path: "/request-password-reset" },
			});
			return result.rows[0];
		});
		return user
			? { user, link: emailURL(`/reset-password/${token}`, destination) }
			: null;
	}

	async function deliverVerification(
		identity: ProjectEmailIdentity,
		destination: URL | string,
	) {
		const user = await store.transaction(async (client) => {
			const result = await client.query<Recipient>(
				`${recipientQuery} AND "emailVerified" = false AND ($2::text IS NULL OR id = $2)`,
				[identity.email, identity.userId ?? null],
			);
			return result.rows[0];
		});
		if (!user) return;
		const token = await verification.issue(user);
		const link = emailURL("/verify-email", destination, token);
		await deliver("send-verification-email", {
			user,
			link:
				link.length <= maximumHostedEmailURLLength
					? link
					: emailURL("/verify-email", verifyCallbacks[0], token),
		});
	}

	function resendAfterPassword(
		user: Pick<Recipient, "id" | "email">,
		callbackURL: string | undefined,
		request: Request,
	) {
		if (!emailConfigured(options.email.environment)) return;
		const caller = request.headers.get("origin") ?? undefined;
		const selected = selectCallback(
			callbackURL ?? new URL("/", linkBase.origin).href,
			"verification",
			"issue",
			caller,
			hostedPasswordSignInRequests.has(request),
		);
		const destination = selected
			? (callbackURL === undefined ? "/" : selected.url)
			: verifyCallbacks[0];
		const onFailure = () =>
			options.onDeliveryFailure?.("send-verification-email");
		void scheduleOwnedEmailDelivery(
			(work) => options.defer(work),
			async () => () =>
				deliverVerification({ email: user.email, userId: user.id }, destination),
			onFailure,
		).then((scheduled) => {
			if (!scheduled) onFailure();
		}, onFailure);
	}

	async function deliver(
		operation: "request-password-reset" | "send-verification-email",
		message: { user: Recipient; link: string },
	) {
		const isReset = operation === "request-password-reset";
		const title = isReset ? "Reset your password" : "Verify your email";
		await sendAuthEmail(options.email.environment, {
			to: message.user.email,
			fromName: appName,
			subject: isReset
				? `Reset your ${appName} password`
				: `Verify your ${appName} email`,
			react: authenticationEmail({
				branding: brand,
				title,
				url: message.link,
				actionLabel: isReset ? "Reset password" : "Verify email",
				description: isReset
					? `Follow this link to choose a new password for ${appName}.`
					: `Hello ${message.user.name}, confirm your email address for ${appName}.`,
			}),
		});
	}

	async function admission(
		request: Request,
		operation: RecoveryOperation,
		normalizedEmail?: string,
	) {
		const decision = await options.admit(request, operation, normalizedEmail);
		if (decision instanceof Response) return decision;
		return decision.allowed
			? null
			: failure(
					429,
					"TOO_MANY_REQUESTS",
					"Too many requests.",
					new Headers({
						"Retry-After": String(Math.max(1, Math.ceil(decision.retryAfter))),
					}),
				);
	}

	async function send(
		request: Request,
		operation: "request-password-reset" | "send-verification-email",
	) {
		const caller = request.headers.get("origin") ?? undefined;
		const isReset = operation === "request-password-reset";
		const hosted = isReset && hostedRecovery && caller === origin;
		const raw = await boundedJson(
			request,
			hosted ? maximumHostedResetBodyBytes : undefined,
		);
		const body = isReset
			? (options.emailAliases?.normalizeInput(raw) ?? raw)
			: raw;
		const parsed = isReset
			? (hosted ? hostedResetRequest : resetRequest).safeParse(body)
			: verifyRequest.safeParse(body);
		if (!parsed.success)
			return failure(400, "INVALID_BODY", "Supply a valid email address.");
		const value =
			"redirectTo" in parsed.data
				? parsed.data.redirectTo
				: "callbackURL" in parsed.data
					? parsed.data.callbackURL
					: undefined;
		const destination = selectCallback(
			value,
			isReset ? "password-reset" : "verification",
			"issue",
			caller,
		);
		if (!destination) return forbidden();
		// Check the nested, encoded email URL before creating a reset token.
		if (
			hosted &&
			value &&
			value.length > maximumCallbackLength &&
			emailURL(
				`/reset-password/${"a".repeat(resetTokenLength)}`,
				destination.url,
			).length > maximumHostedEmailURLLength
		)
			return forbidden();
		const address = parsed.data.email.toLowerCase();
		const identity = isReset && options.emailAliases
			? await options.emailAliases.resolve(address)
			: { email: address };
		if (!identity) return failure(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password");
		const limited = await admission(request, operation, identity.email);
		if (limited) return limited;
		if (
			!emailConfigured(options.email.environment) ||
			(isReset && !policy.emailAndPasswordEnabled)
		)
			return failure(
				503,
				"EMAIL_DELIVERY_UNAVAILABLE",
				"Authentication email is unavailable.",
			);
		const scheduled = await scheduleOwnedEmailDelivery(
			(work) => options.defer(work),
			async () => {
				if (!isReset)
					return () => deliverVerification({ email: address }, destination.url);
				const message = await prepareReset(request, identity, destination.url);
				return message ? () => deliver(operation, message) : null;
			},
			() => options.onDeliveryFailure?.(operation),
		);
		if (!scheduled)
			return failure(
				503,
				"EMAIL_DELIVERY_UNAVAILABLE",
				"Authentication email is unavailable.",
			);
		return json(
			isReset
				? {
						status: true,
						message:
							"If this email exists in our system, check your email for the reset link",
					}
				: { status: true },
		);
	}

	async function consume(request: Request, url: URL) {
		const parsed = resetInput.safeParse(await boundedJson(request));
		if (!parsed.success)
			return failure(400, "INVALID_BODY", "Supply a new password.");
		const query = url.searchParams.getAll("token");
		if (
			query.length > 1 ||
			(parsed.data.token && query[0] && parsed.data.token !== query[0])
		)
			return failure(400, "INVALID_TOKEN", "Invalid token");
		const limited = await admission(request, "reset-password");
		if (limited) return limited;
		const auditContext = options.auditContext?.(request);
		const rejected = async (
			status: number,
			code: string,
			message: string,
			auditCode = code,
		) => {
			await store.transaction((client) =>
				store.recordEvent(client, {
					type: "user.password-reset",
					outcome: "failure",
					...auditContext,
					metadata: { path: "/reset-password", errorCode: auditCode },
				}),
			);
			return failure(status, code, message);
		};
		const result = await reset({
			token: parsed.data.token ?? query[0] ?? "",
			newPassword: parsed.data.newPassword,
			auditContext,
		});
		switch (result.status) {
			case "reset":
				return json({ status: true });
			case "invalid-token":
				return rejected(400, "INVALID_TOKEN", "Invalid token");
			case "password-policy":
				// The installed password policy rejects before the endpoint audit hook.
				return failure(400, result.code, result.message);
			case "breached-password":
				return rejected(
					400,
					"PASSWORD_COMPROMISED",
					"The password you entered has been compromised. Please choose a different password.",
				);
			case "breach-check-unavailable":
			case "unavailable":
				return rejected(
					503,
					"PASSWORD_RESET_UNAVAILABLE",
					"Password reset is unavailable.",
					// Preserve the installed audit code without exposing provider errors in HTTP.
					result.status === "breach-check-unavailable"
						? "AUTHENTICATION_FAILED"
						: undefined,
				);
		}
	}

	async function dispatch(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(`${options.basePath}/`)) return null;
		const path = url.pathname.slice(options.basePath.length);
		const resetToken = path.match(/^\/reset-password\/([^/]+)$/)?.[1];
		const sharedOtpSend =
			path === "/email-otp/send-verification-otp" && request.method === "POST";
		const otpOperation =
			path === "/email-otp/request-password-reset"
				? "email-otp/request-password-reset"
				: path === "/forget-password/email-otp"
					? "forget-password/email-otp"
					: path === "/email-otp/reset-password"
						? "email-otp/reset-password"
						: undefined;
		if (
			!resetToken &&
			!sharedOtpSend &&
			!otpOperation &&
			![
				"/request-password-reset",
				"/reset-password",
				"/send-verification-email",
				"/verify-email",
			].includes(path)
		)
			return null;
		const isCallback = Boolean(resetToken) || path === "/verify-email";
		if (request.method !== (isCallback ? "GET" : "POST"))
			return failure(
				405,
				"METHOD_NOT_ALLOWED",
				"Method not allowed.",
				new Headers({ Allow: isCallback ? "GET" : "POST" }),
			);
		const caller = request.headers.get("origin");
		if (
			url.origin !== origin ||
			request.headers.has("authorization") ||
			(caller !== null && !origins.has(caller)) ||
			(!isCallback &&
				(!caller || request.headers.get("sec-fetch-site") === "cross-site"))
		)
			return forbidden();
		if (sharedOtpSend) {
			const input = await readSharedProjectEmailOtpBody(request);
			if (
				!input ||
				typeof input !== "object" ||
				!("type" in input) ||
				input.type !== "forget-password"
			)
				return null;
			return emailOTP(request, "email-otp/send-verification-otp", input);
		}
		if (otpOperation)
			return emailOTP(
				request,
				otpOperation,
				await readProjectEmailProofBody(request),
			);

		if (
			path === "/request-password-reset" ||
			path === "/send-verification-email"
		)
			return send(
				request,
				path.slice(1) as "request-password-reset" | "send-verification-email",
			);
		if (path === "/reset-password") return consume(request, url);

		const candidates = url.searchParams.getAll("callbackURL");
		if (candidates.length > 1) return forbidden();
		const destination = selectCallback(
			candidates[0],
			resetToken ? "password-reset" : "verification",
			"consume",
			undefined,
			hostedVerificationLinkRequests.has(request) &&
				url.href.length <= maximumHostedEmailURLLength,
		);
		if (!destination) return forbidden();
		if (resetToken) {
			const limited = await admission(request, "reset-password-callback");
			if (limited) return limited;
			const user = isLegacyPasswordResetToken(resetToken)
				? await findOwnedPasswordResetUser(
						options.database,
						options.project.schemaName,
						resetToken,
					)
				: null;
			if (user) return redirect(destination.url, "token", resetToken);
			return destination.expiredContinuation
				? failure(
						401,
						"INVALID_TOKEN",
						"Invalid or expired password reset token.",
					)
				: redirect(destination.url, "error", "INVALID_TOKEN");
		}

		const limited = await admission(request, "verify-email");
		if (limited) return limited;
		if (
			(candidates[0]?.length ?? 0) > maximumCallbackLength &&
			!destination.expiredContinuation &&
			!(await options.verifyHostedVerificationContinuation?.(destination.url))
		)
			return forbidden();
		const tokens = url.searchParams.getAll("token");
		const result =
			tokens.length === 1
				? await verification.verify({
						token: tokens[0],
						request,
						callbackURL: candidates[0] ? destination.url.href : undefined,
					})
				: { status: "invalid" as const };
		if (result.status === "verified") {
			if (result.response)
				return new Response(result.response.body, {
					status: result.response.status,
					headers: privateHeaders(new Headers(result.response.headers)),
				});
			return candidates[0]
				? redirect(destination.url)
				: json({ status: true, user: null });
		}
		const code =
			result.status === "expired" ? "TOKEN_EXPIRED" : "INVALID_TOKEN";
		return candidates[0] && !destination.expiredContinuation
			? redirect(destination.url, "error", code)
			: failure(401, code, "Invalid or expired verification token.");
	}
	return Object.assign(dispatch, { resendAfterPassword });
}
