import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ApplicationBranding } from "../branding/types";
import type { ControlEventInput } from "../control/types";
import { authenticationEmail } from "../email/authentication";
import type { EmailEnvironment } from "../email/send";
import { emailConfigured, sendAuthEmail } from "../email/send";
import {
	accountLinkError,
	accountLinkHeaders,
	accountLinkJson,
} from "./owned-project-account-links";
import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { scheduleOwnedEmailDelivery } from "./owned-project-email-delivery";
import type { ProjectEmailOtpProof } from "./owned-project-email-otp-proof";
import {
	createOwnedProjectEmailOtpProof,
	projectEmailOtpIdentifier,
} from "./owned-project-email-otp-proof";
import {
	readProjectEmailProofBody,
	readSharedProjectEmailOtpBody,
} from "./owned-project-email-proof-body";
import type { ProjectUser } from "./owned-project-engine-store";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { Project } from "./registry";
import type { SessionCheckAdmission } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const sendPath = "email-otp/send-verification-otp";
const checkPath = "email-otp/check-verification-otp";
const verifyPath = "email-otp/verify-email";
const emailAddress = z.email().max(320);
const sendInput = z.object({
	email: z.string().max(320),
	type: z.literal("email-verification"),
});
const verifyInput = z.object({
	email: z.string().max(320),
	otp: z.string().max(256),
});
const checkInput = verifyInput.extend({
	type: z.enum([
		"email-verification",
		"sign-in",
		"forget-password",
		"change-email",
	]),
});

export type ProjectEmailOtpVerificationOperation =
	| typeof sendPath
	| typeof checkPath
	| typeof verifyPath;

export interface OwnedProjectEmailOtpVerificationOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	emailAliases?: OwnedProjectEmailAliases;
	email: { environment: EmailEnvironment; branding?: ApplicationBranding };
	admit(
		request: Request,
		operation: ProjectEmailOtpVerificationOperation,
		email?: string,
	): Promise<SessionCheckAdmission | Response>;
	defer(delivery: () => Promise<void>): void;
	onDeliveryFailure?(): void;
	auditContext?(
		request: Request,
	): Pick<ControlEventInput, "ipAddress" | "userAgent">;
	completeVerification?(input: {
		client: PoolClient;
		user: ProjectUser;
		request: Request;
	}): Promise<Response | undefined>;
	onVerificationFailure?(input: {
		client: PoolClient;
		request: Request;
		email: string;
	}): Promise<void>;
}

function invalidOtp(
	status: Exclude<ProjectEmailOtpProof["status"], "valid"> = "invalid",
) {
	switch (status) {
		case "expired":
			return accountLinkError(400, "OTP_EXPIRED", "OTP expired");
		case "attempts":
			return accountLinkError(403, "TOO_MANY_ATTEMPTS", "Too many attempts");
		default:
			return accountLinkError(400, "INVALID_OTP", "Invalid OTP");
	}
}

function privateResponse(response: Response) {
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: accountLinkHeaders(new Headers(response.headers)),
	});
}

type Mailbox = Pick<
	ProjectUser,
	| "id"
	| "createdAt"
	| "banned"
	| "directoryDisabled"
	| "directoryManaged"
	| "isAnonymous"
>;

function activeMailbox(user: Mailbox | null): user is Mailbox {
	return Boolean(
		user &&
			!user.banned &&
			!user.directoryDisabled &&
			!user.directoryManaged &&
			!user.isAnonymous,
	);
}

/** Persist native-compatible proof before scheduling verification email or creating a session. */
export function createOwnedProjectEmailOtpVerification(
	options: OwnedProjectEmailOtpVerificationOptions,
) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid project email OTP verification route.");
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);
	const proofs = createOwnedProjectEmailOtpProof(options.project.schemaName);
	const branding = options.email.branding;
	const appName = branding?.name || "AllAuth";

	async function admission(
		request: Request,
		operation: ProjectEmailOtpVerificationOperation,
		email: string,
	) {
		const result = await options.admit(request, operation, email);
		if (result instanceof Response) return privateResponse(result);
		return result.allowed
			? null
			: accountLinkJson(
					{ code: "TOO_MANY_REQUESTS", message: "Too many requests." },
					429,
					new Headers({
						"Retry-After": String(Math.max(1, Math.ceil(result.retryAfter))),
					}),
				);
	}

	async function lockMailbox(client: PoolClient, email: string) {
		const {
			rows: [user],
		} = await client.query<Mailbox>(
			`SELECT id, "createdAt", banned, "directoryDisabled", "directoryManaged", "isAnonymous"
			 FROM "user" WHERE email = $1 FOR UPDATE`,
			[email],
		);
		return user ?? null;
	}

	async function send(request: Request, email: string) {
		const limited = await admission(request, sendPath, email);
		if (limited) return limited;
		const unavailable = () =>
			accountLinkError(
				503,
				"EMAIL_DELIVERY_UNAVAILABLE",
				"Authentication email is unavailable.",
			);
		if (!emailConfigured(options.email.environment)) return unavailable();
		const scheduled = await scheduleOwnedEmailDelivery(
			(work) => options.defer(work),
			async () => {
				const code = await store.transaction(async (client) => {
					const { rowCount } = await client.query(
						`SELECT id FROM "user" WHERE email = $1
							AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true
							AND "directoryManaged" IS DISTINCT FROM true AND "isAnonymous" IS DISTINCT FROM true
							FOR UPDATE`,
						[email],
					);
					return proofs.issueIf(
						client,
						projectEmailOtpIdentifier("email-verification", email),
						rowCount === 1,
					);
				});
				if (!code) return null;
				return () =>
					sendAuthEmail(options.email.environment, {
						to: email,
						fromName: appName,
						subject: `Your ${appName} verification code`,
						react: authenticationEmail({
							branding,
							title: "Verify your email",
							description:
								"Use this code to verify your email address. It expires in five minutes.",
							code,
						}),
					});
			},
			() => options.onDeliveryFailure?.(),
		);
		return scheduled ? accountLinkJson({ success: true }) : unavailable();
	}

	async function check(request: Request, body: z.infer<typeof checkInput>) {
		const entered = body.email.toLowerCase();
		const identity =
			(body.type === "sign-in" || body.type === "forget-password") &&
			options.emailAliases
				? await options.emailAliases.resolve(entered)
				: { email: entered };
		if (!identity) return invalidOtp();
		const limited = await admission(request, checkPath, identity.email);
		if (limited) return limited;
		const identifier = projectEmailOtpIdentifier(body.type, identity.email);
		return store.transaction(async (client) => {
			const proof = await proofs.verify(client, identifier, body.otp, {
				consume: false,
			});
			if (proof.status !== "valid") return invalidOtp(proof.status);
			const { rowCount } = await client.query(
				'SELECT id FROM "user" WHERE email = $1 AND ($2::text IS NULL OR id = $2)',
				[identity.email, identity.userId ?? null],
			);
			return rowCount
				? accountLinkJson({ success: true })
				: accountLinkError(400, "USER_NOT_FOUND", "User not found");
		});
	}

	async function verify(request: Request, email: string, code: string) {
		const limited = await admission(request, verifyPath, email);
		if (limited) return limited;
		return store.transaction(async (client) => {
			const mailbox = await lockMailbox(client, email);
			const proof = await proofs.verify(
				client,
				projectEmailOtpIdentifier("email-verification", email),
				code,
				{ consume: true },
			);
			if (proof.status === "valid" && !mailbox)
				return accountLinkError(400, "USER_NOT_FOUND", "User not found");
			if (
				proof.status !== "valid" ||
				!activeMailbox(mailbox) ||
				new Date(mailbox.createdAt).getTime() > proof.issuedAt.getTime()
			) {
				await options.onVerificationFailure?.({ client, request, email });
				return invalidOtp(proof.status === "valid" ? "invalid" : proof.status);
			}
			const user = await store.lockUser(client, mailbox.id);
			if (!user)
				throw new Error("Project verification account changed while locked.");
			const {
				rows: [updated],
			} = await client.query<{ updatedAt: Date }>(
				'UPDATE "user" SET "emailVerified" = true, "updatedAt" = statement_timestamp() WHERE id = $1 RETURNING "updatedAt"',
				[user.id],
			);
			if (!updated)
				throw new Error("Project verification account changed while locked.");
			await store.record(
				client,
				"user.updated",
				"success",
				`/${verifyPath}`,
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
				metadata: { path: `/${verifyPath}` },
			});
			const verified = {
				...user,
				emailVerified: true,
				updatedAt: updated.updatedAt,
			};
			const result = await options.completeVerification?.({
				client,
				user: verified,
				request,
			});
			return result
				? privateResponse(result)
				: accountLinkJson({
						status: true,
						token: null,
						user: projectUserResponse(verified),
					});
		});
	}

	return async function dispatch(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(`${options.basePath}/`)) return null;
		const path = url.pathname.slice(options.basePath.length + 1);
		if (path !== sendPath && path !== verifyPath && path !== checkPath)
			return null;
		if (request.method !== "POST") {
			if (path === sendPath) return null;
			return accountLinkJson(
				{ code: "METHOD_NOT_ALLOWED", message: "Method not allowed." },
				405,
				new Headers({ Allow: "POST" }),
			);
		}
		const caller = request.headers.get("origin");
		if (
			url.origin !== origin ||
			!caller ||
			!origins.has(caller) ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);

		const invalidBody = () =>
			accountLinkError(
				400,
				"INVALID_BODY",
				"Supply a valid email address and code.",
			);
		const invalidEmail = () =>
			accountLinkError(400, "INVALID_EMAIL", "Invalid email");
		// Sending is shared with sign-in and password reset. Leave other purposes' body intact.
		if (path === sendPath) {
			const raw = await readSharedProjectEmailOtpBody(request);
			if (!raw || typeof raw !== "object" || !("type" in raw)) return null;
			if (raw.type === "change-email") {
				if (!("email" in raw) || typeof raw.email !== "string")
					return invalidBody();
				if (!emailAddress.safeParse(raw.email.toLowerCase()).success)
					return invalidEmail();
				const limited = await admission(
					request,
					sendPath,
					raw.email.toLowerCase(),
				);
				return limited ?? accountLinkJson({ message: "Invalid OTP type" }, 400);
			}
			if (raw.type !== "email-verification") return null;
			const input = sendInput.safeParse(raw);
			if (!input.success) return invalidBody();
			const email = emailAddress.safeParse(input.data.email.toLowerCase());
			return email.success ? send(request, email.data) : invalidEmail();
		}
		const raw = await readProjectEmailProofBody(request);
		if (path === checkPath) {
			const input = checkInput.safeParse(
				raw &&
					typeof raw === "object" &&
					"type" in raw &&
					(raw.type === "sign-in" || raw.type === "forget-password")
					? (options.emailAliases?.normalizeInput(raw) ?? raw)
					: raw,
			);
			if (!input.success) return invalidBody();
			return emailAddress.safeParse(input.data.email.toLowerCase()).success
				? check(request, input.data)
				: invalidEmail();
		}
		const input = verifyInput.safeParse(raw);
		if (!input.success) return invalidBody();
		const email = emailAddress.safeParse(input.data.email.toLowerCase());
		return email.success
			? verify(request, email.data, input.data.otp)
			: invalidEmail();
	};
}
