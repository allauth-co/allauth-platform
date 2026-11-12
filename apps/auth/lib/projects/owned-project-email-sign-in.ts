import type { Pool } from "pg";
import * as z from "zod";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { validAvatarPath } from "../avatars/protocol";
import type { ApplicationBranding } from "../branding/types";
import { hostedMagicLinkCallbacks } from "../domains/hosted-sdk-policy";
import { authenticationEmail } from "../email/authentication";
import type { EmailEnvironment } from "../email/send";
import { emailConfigured, sendAuthEmail } from "../email/send";
import type { OwnedEmailCallbackPolicy } from "./owned-project-email-callback";
import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { scheduleOwnedEmailDelivery } from "./owned-project-email-delivery";
import type { ProjectEmailOtpVerificationOperation } from "./owned-project-email-otp-verification";
import { readProjectEmailProofBody, readSharedProjectEmailOtpBody } from "./owned-project-email-proof-body";
import type { CompleteProjectEmailSignIn } from "./owned-project-email-sign-in-store";
import { createProjectEmailSignInStore } from "./owned-project-email-sign-in-store";
import type { Project } from "./registry";
import type { SessionCheckAdmission } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const email = z.email().max(320);
const callback = z.string().max(2048).optional();
const magicInput = z.object({
	email,
	name: z.string().max(256).optional(),
	callbackURL: callback,
	newUserCallbackURL: callback,
	errorCallbackURL: callback,
});
type MagicCallbackInput = Pick<
	z.infer<typeof magicInput>,
	"callbackURL" | "newUserCallbackURL" | "errorCallbackURL"
>;
const otpSend = z.object({
	email,
	type: z.enum([
		"sign-in",
		"email-verification",
		"forget-password",
		"change-email",
	]),
});
const otpSignIn = z.object({
	email,
	otp: z.string().max(256),
	name: z.string().max(256).optional(),
	image: z.string().max(2048).optional(),
});

export type ProjectEmailSignInOperation =
	| "sign-in/magic-link"
	| "magic-link/verify"
	| "sign-in/email-otp"
	| ProjectEmailOtpVerificationOperation;

export interface OwnedProjectEmailSignInOptions {
	database: Pool;
	emailAliases?: OwnedProjectEmailAliases;
	project: Pick<Project, "schemaName" | "slug">;
	policy: AuthPolicy;
	baseURL: string;
	basePath: string;
	/** Exact auth endpoint base used in email, including the SDK proxy path when applicable. */
	publicLinkBaseURL: string;
	trustedOrigins: readonly string[];
	callbackURLs: readonly string[];
	hostedCallbackPolicy?: OwnedEmailCallbackPolicy;
	email: { environment: EmailEnvironment; branding?: ApplicationBranding };
	/** Meter trusted ingress before any challenge mutation or delivery. */
	admit(
		request: Request,
		operation: ProjectEmailSignInOperation,
		normalizedEmail?: string,
	): Promise<SessionCheckAdmission | Response>;
	/** Schedule email delivery after the HTTP response. */
	defer(delivery: () => Promise<void>): void;
	onDeliveryFailure?(
		operation: "sign-in/magic-link" | "email-otp/send-verification-otp",
	): void;
	completeSignIn: CompleteProjectEmailSignIn;
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

function unsupported() {
	return failure(
		501,
		"ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
		"This authentication operation is unavailable in this realm.",
	);
}

function normalizeURL(value: string, origin: string) {
	if (
		!value ||
		value.length > 2048 ||
		value.startsWith("//") ||
		/[\\\u0000-\u0020\u007f]/.test(value)
	)
		return null;
	try {
		const url = new URL(value, origin);
		return url.username || url.password || url.hash ? null : url;
	} catch {
		return null;
	}
}

function redirectError(callback: URL, code: string) {
	callback.searchParams.set("error", code);
	return new Response(null, {
		status: 302,
		headers: privateHeaders(new Headers({ Location: callback.href })),
	});
}

/** Cookie-only project sign-in backed by the existing five-minute email challenge rows. */
export function createOwnedProjectEmailSignIn(
	options: OwnedProjectEmailSignInOptions,
) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid project email sign-in route.");
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((item) => projectOrigin.parse(item)),
	]);
	const linkBase = normalizeURL(options.publicLinkBaseURL, origin);
	if (
		!linkBase ||
		!origins.has(linkBase.origin) ||
		linkBase.search ||
		!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(linkBase.pathname)
	)
		throw new Error("Invalid project magic link base.");
	const linkOrigin = linkBase.origin;
	const linkPath = linkBase.pathname;
	const approved = options.callbackURLs.map((value) => {
		const url = normalizeURL(value, origin);
		if (
			!url ||
			!origins.has(url.origin) ||
			url.searchParams.has("token") ||
			url.searchParams.has("error")
		)
			throw new Error("Invalid project magic link callback.");
		return url.href;
	});
	if (!approved.length)
		throw new Error("An explicit project magic link callback is required.");
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEmailSignInStore({
		...options,
		schemaName: options.project.schemaName,
		policy,
		async completeSignIn(input) {
			const response = await options.completeSignIn(input);
			const location = response.headers.get("location");
			if (location) {
				const target = normalizeURL(location, linkOrigin);
				if (!target || !origins.has(target.origin)) return forbidden();
			}
			return response;
		},
	});
	const branding = options.email.branding;
	const appName = branding?.name || "AllAuth";

	function selectCallback(
		value: string | undefined,
		caller: string,
		fallback = approved[0],
	) {
		if (value === undefined) return new URL(fallback);
		const url = normalizeURL(value, caller);
		return url && approved.includes(url.href) ? url : null;
	}

	function selectHostedMagicCallbacks(
		input: MagicCallbackInput,
		phase: "issue" | "consume",
	) {
		if (
			!options.hostedCallbackPolicy ||
			options.basePath !== "/api/auth" ||
			!input.callbackURL ||
			!input.errorCallbackURL ||
			input.newUserCallbackURL !== undefined ||
			input.callbackURL.startsWith("//") ||
			/[\\\u0000-\u0020\u007f]/.test(input.callbackURL)
		)
			return null;
		try {
			const target = new URL(input.callbackURL, origin);
			const checked = options.hostedCallbackPolicy(target, "verification", phase);
			if (!checked) return null;
			const error = normalizeURL(
				decodeURIComponent(input.errorCallbackURL),
				origin,
			);
			if (error?.origin !== origin || error.pathname !== "/auth-error")
				return null;
			// The standard form uses a bare error URL. The hosted form carries the
			// same checked destination in both callback fields.
			const wire = error.search
				? hostedMagicLinkCallbacks(`${target.pathname}${target.search}${target.hash}`, origin)
				: { callbackURL: target.href, errorCallbackURL: error.href };
			if (error.search && input.errorCallbackURL !== wire.errorCallbackURL)
				return null;
			if (checked.expiredContinuation && error.search)
				error.searchParams.set("callbackUrl", checked.url.pathname);
			return { destination: checked.url, created: checked.url, error, wire };
		} catch {
			return null;
		}
	}

	function magicCallbacks(
		input: MagicCallbackInput,
		caller: string,
		phase: "issue" | "consume",
	) {
		const hosted = selectHostedMagicCallbacks(input, phase);
		if (hosted) return hosted;
		const destination = selectCallback(input.callbackURL, caller);
		if (!destination) return null;
		const created = selectCallback(
			input.newUserCallbackURL,
			caller,
			destination.href,
		);
		const error = selectCallback(input.errorCallbackURL, caller, destination.href);
		return created && error
			? {
					destination,
					created,
					error,
					wire: { callbackURL: destination.href, errorCallbackURL: error.href },
				}
			: null;
	}

	async function schedule(
		operation: "sign-in/magic-link" | "email-otp/send-verification-otp",
		prepare: () => Promise<(() => Promise<void>) | null>,
	) {
		if (
			emailConfigured(options.email.environment) &&
			(await scheduleOwnedEmailDelivery(
				(work) => options.defer(work),
				prepare,
				() => options.onDeliveryFailure?.(operation),
			))
		)
			return null;
		return failure(
			503,
			"EMAIL_DELIVERY_UNAVAILABLE",
			"Authentication email is unavailable.",
		);
	}

	async function admission(
		request: Request,
		operation: ProjectEmailSignInOperation,
		identity?: string,
	) {
		const decision = await options.admit(request, operation, identity);
		if (decision instanceof Response) return privateResponse(decision);
		if (decision.allowed) return null;
		return failure(
			429,
			"TOO_MANY_REQUESTS",
			"Too many requests.",
			new Headers({
				"Retry-After": String(
					Number.isFinite(decision.retryAfter)
						? Math.max(1, Math.ceil(decision.retryAfter))
						: 1,
				),
			}),
		);
	}

	function invalidAlias() {
		return failure(401, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password");
	}

	function resolveEmail(email: string) {
		const address = email.toLowerCase();
		return options.emailAliases ? options.emailAliases.resolve(address) : { email: address };
	}

	async function proofBody(request: Request) {
		const raw = await readProjectEmailProofBody(request);
		return options.emailAliases?.normalizeInput(raw) ?? raw;
	}

	async function sendMagic(request: Request, caller: string) {
		const parsed = magicInput.safeParse(await proofBody(request));
		if (!parsed.success)
			return failure(400, "INVALID_BODY", "Supply a valid email address.");
		const body = parsed.data;
		const callbacks = magicCallbacks(body, caller, "issue");
		if (!callbacks) return forbidden();
		const identity = await resolveEmail(body.email);
		if (!identity) return invalidAlias();
		const limited = await admission(request, "sign-in/magic-link", identity.email);
		if (limited) return limited;
		const scheduled = await schedule("sign-in/magic-link", async () => {
			const token = await store.issueMagic({ ...identity, name: body.name });
			if (!token) return null;
			const url = new URL(`${linkPath}/magic-link/verify`, linkOrigin);
			url.searchParams.set("token", token);
			url.searchParams.set("callbackURL", callbacks.wire.callbackURL);
			if (body.newUserCallbackURL)
				url.searchParams.set("newUserCallbackURL", callbacks.created.href);
			if (body.errorCallbackURL)
				url.searchParams.set("errorCallbackURL", callbacks.wire.errorCallbackURL);
			return () =>
				sendAuthEmail(options.email.environment, {
					to: identity.email,
					fromName: appName,
					subject: `Sign in to ${appName}`,
					react: authenticationEmail({
						branding,
						title: `Sign in to ${appName}`,
						description:
							"Use this link to sign in. It expires in five minutes.",
						url: url.href,
						actionLabel: "Sign in",
					}),
				});
		});
		return scheduled ?? json({ status: true });
	}

	async function sendOtp(request: Request) {
		const body = await readSharedProjectEmailOtpBody(request);
		const parsed = otpSend.safeParse(options.emailAliases?.normalizeInput(body) ?? body);
		if (!parsed.success)
			return failure(
				400,
				"INVALID_BODY",
				"Supply a valid email address and code purpose.",
			);
		if (parsed.data.type !== "sign-in") return unsupported();
		const identity = await resolveEmail(parsed.data.email);
		if (!identity) return invalidAlias();
		const limited = await admission(
			request,
			"email-otp/send-verification-otp",
			identity.email,
		);
		if (limited) return limited;
		const scheduled = await schedule(
			"email-otp/send-verification-otp",
			async () => {
				const code = await store.issueOtp(identity);
				if (!code) return null;
				return () =>
					sendAuthEmail(options.email.environment, {
						to: identity.email,
						fromName: appName,
						subject: `Your ${appName} verification code`,
						react: authenticationEmail({
							branding,
							title: "Your verification code",
							description:
								"Use this code to complete sign in. It expires in five minutes.",
							code,
						}),
					});
			},
		);
		return scheduled ?? json({ success: true });
	}

	async function verifyMagic(request: Request, url: URL) {
		const fields = [
			"token",
			"callbackURL",
			"newUserCallbackURL",
			"errorCallbackURL",
		];
		if (fields.some((name) => url.searchParams.getAll(name).length > 1))
			return forbidden();
		const callbackURL = url.searchParams.get("callbackURL") ?? undefined;
		const newUserCallback =
			url.searchParams.get("newUserCallbackURL") ?? undefined;
		const callbacks = magicCallbacks({
			callbackURL,
			newUserCallbackURL: newUserCallback,
			errorCallbackURL: url.searchParams.get("errorCallbackURL") ?? undefined,
		}, linkOrigin, "consume");
		if (!callbacks) return forbidden();
		const { destination, created, error } = callbacks;
		const limited = await admission(request, "magic-link/verify");
		if (limited) return limited;
		const token = url.searchParams.get("token") ?? "";
		if (!/^[A-Za-z]{32}$/.test(token))
			return redirectError(error, "INVALID_TOKEN");
		const result = await store.verifyMagic(token, request, {
			existing: callbackURL ? destination.href : undefined,
			created: callbackURL || newUserCallback ? created.href : undefined,
		});
		if (result.status === "authenticated")
			return privateResponse(result.response);
		if (result.status === "signup-disabled")
			return redirectError(error, "new_user_signup_disabled");
		return redirectError(
			error,
			result.status === "invalid" || result.status === "expired"
				? "INVALID_TOKEN"
				: "failed_to_create_session",
		);
	}

	function privateResponse(response: Response) {
		return new Response(response.body, {
			status: response.status,
			headers: privateHeaders(new Headers(response.headers)),
		});
	}

	async function verifyOtp(request: Request, caller: string) {
		const input = otpSignIn.safeParse(await proofBody(request));
		if (!input.success)
			return failure(
				400,
				"INVALID_BODY",
				"Supply a valid email address and code.",
			);
		const { email, otp, name, image } = input.data;
		if (image) {
			try {
				if (validAvatarPath(new URL(image, caller).pathname))
					return failure(
						400,
						"INVALID_PROFILE_IMAGE",
						"Choose the original profile photo uploaded for your current account.",
					);
			} catch {
				// Ordinary external profile-image values keep their existing contract.
			}
		}
		const identity = await resolveEmail(email);
		if (!identity) return invalidAlias();
		const limited = await admission(request, "sign-in/email-otp", identity.email);
		if (limited) return limited;
		const result = await store.verifyOtp(
			{ ...identity, name, image },
			otp,
			request,
		);
		if ("response" in result) return privateResponse(result.response);
		if (result.status === "expired")
			return failure(400, "OTP_EXPIRED", "OTP expired");
		if (result.status === "attempts")
			return failure(403, "TOO_MANY_ATTEMPTS", "Too many attempts");
		if (result.status === "unsupported") return unsupported();
		return failure(400, "INVALID_OTP", "Invalid OTP");
	}

	return async function dispatch(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(`${options.basePath}/`)) return null;
		const path = url.pathname.slice(options.basePath.length + 1);
		if (
			path !== "sign-in/magic-link" &&
			path !== "magic-link/verify" &&
			path !== "email-otp/send-verification-otp" &&
			path !== "sign-in/email-otp"
		)
			return null;
		const get = path === "magic-link/verify";
		if (request.method !== (get ? "GET" : "POST"))
			return failure(
				405,
				"METHOD_NOT_ALLOWED",
				"Method not allowed.",
				new Headers({ Allow: get ? "GET" : "POST" }),
			);
		const caller = request.headers.get("origin");
		if (
			url.origin !== origin ||
			request.headers.has("authorization") ||
			(caller && !origins.has(caller))
		)
			return forbidden();
		if (get) return verifyMagic(request, url);
		if (!caller || request.headers.get("sec-fetch-site") === "cross-site")
			return forbidden();
		if (path === "sign-in/magic-link") return sendMagic(request, caller);
		if (path === "email-otp/send-verification-otp") return sendOtp(request);
		return verifyOtp(request, caller);
	};
}
