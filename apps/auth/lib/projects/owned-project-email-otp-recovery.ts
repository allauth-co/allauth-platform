import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { passwordPolicyError } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import type { ApplicationBranding } from "../branding/types";
import { clerkCompatiblePasswords } from "../clerk-password";
import { authenticationEmail } from "../email/authentication";
import type { EmailEnvironment } from "../email/send";
import { emailConfigured, sendAuthEmail } from "../email/send";
import type { PasswordSafety } from "./owned-password-reset";
import { writeOwnedPasswordReset } from "./owned-password-reset";
import type {
	OwnedProjectEmailAliases,
	ProjectEmailIdentity,
} from "./owned-project-email-aliases";
import { scheduleOwnedEmailDelivery } from "./owned-project-email-delivery";
import {
	createOwnedProjectEmailOtpProof,
	projectEmailOtpIdentifier,
} from "./owned-project-email-otp-proof";
import { createProjectEngineStore } from "./owned-project-engine-store";

const issueOperation = "email-otp/request-password-reset";
const deprecatedOperation = "forget-password/email-otp";
const sendOperation = "email-otp/send-verification-otp";
const resetOperation = "email-otp/reset-password";
export type EmailOTPRecoveryIssueOperation =
	| typeof issueOperation
	| typeof deprecatedOperation
	| typeof sendOperation;
export type EmailOTPRecoveryOperation =
	| EmailOTPRecoveryIssueOperation
	| typeof resetOperation;

const email = z.email().max(320);
const issueInput = z.object({ email: z.string().max(320) });
const resetInput = issueInput.extend({
	otp: z.string().max(256),
	password: z.string(),
});
const operationInput = z.discriminatedUnion("operation", [
	z.object({
		operation: z.enum([issueOperation, deprecatedOperation]),
		body: issueInput,
	}),
	z.object({
		operation: z.literal(sendOperation),
		body: issueInput.extend({ type: z.literal("forget-password") }),
	}),
	z.object({ operation: z.literal(resetOperation), body: resetInput }),
]);

const otpErrors = {
	invalid: [400, "INVALID_OTP", "Invalid OTP"],
	expired: [400, "OTP_EXPIRED", "OTP expired"],
	attempts: [403, "TOO_MANY_ATTEMPTS", "Too many attempts"],
} as const;

interface Options {
	database: Pool;
	schemaName: string;
	policy: AuthPolicy;
	emailAliases?: OwnedProjectEmailAliases;
	email: { environment: EmailEnvironment; branding?: ApplicationBranding };
	checkPasswordSafety(password: string): Promise<PasswordSafety>;
	admit(
		request: Request,
		operation: EmailOTPRecoveryOperation,
		email?: string,
	): Promise<Response | null>;
	defer(delivery: () => Promise<void>): void;
	onDeliveryFailure?(operation: EmailOTPRecoveryIssueOperation): void;
	prepareEmailOtpReset?(
		request: Request,
	): Promise<string | Response | undefined>;
}

function json(value: unknown, status = 200) {
	return Response.json(value, {
		status,
		headers: {
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			"Referrer-Policy": "no-referrer",
		},
	});
}

function failure(status: number, code: string, message: string) {
	return json({ code, message }, status);
}

function unavailable() {
	return failure(
		503,
		"PASSWORD_RESET_UNAVAILABLE",
		"Password reset is unavailable.",
	);
}

/** The caller supplies verified browser transport, bounded input and realm admission. */
export function createOwnedEmailOTPRecovery(options: Options) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	const proof = createOwnedProjectEmailOtpProof(options.schemaName);
	const policy = authPolicySchema.parse(options.policy);
	const branding = options.email.branding;
	const appName = branding?.name || "AllAuth";

	async function resolve(
		entered: string,
		client?: PoolClient,
	): Promise<ProjectEmailIdentity | null> {
		return options.emailAliases
			? options.emailAliases.resolve(entered, client)
			: { email: entered };
	}

	async function lockRecipient(
		client: PoolClient,
		entered: string,
		identity: ProjectEmailIdentity,
	) {
		if (identity.userId) {
			const current = await resolve(entered, client);
			if (
				current?.email !== identity.email ||
				current.userId !== identity.userId
			)
				return null;
		}
		const {
			rows: [user],
		} = await client.query<{ id: string; email: string }>(
			`SELECT id, email FROM "user" WHERE email=$1
			 AND ($2::text IS NULL OR (id=$2 AND "emailVerified" IS TRUE))
			 AND banned IS DISTINCT FROM true AND "directoryManaged" IS DISTINCT FROM true
			 AND "directoryDisabled" IS DISTINCT FROM true AND "isAnonymous" IS DISTINCT FROM true
			 FOR UPDATE`,
			[identity.email, identity.userId ?? null],
		);
		return user ?? null;
	}

	async function issue(
		entered: string,
		identity: ProjectEmailIdentity | null,
		operation: EmailOTPRecoveryIssueOperation,
	) {
		const scheduled =
			emailConfigured(options.email.environment) &&
			(await scheduleOwnedEmailDelivery(
				options.defer,
				async () => {
					if (!identity) return null;
					const message = await store.transaction(async (client) => {
						const user = await lockRecipient(client, entered, identity);
						if (!user) return null;
						const code = await proof.issue(
							client,
							projectEmailOtpIdentifier("forget-password", user.email),
						);
						return { to: user.email, code };
					});
					if (!message) return null;
					return () =>
						sendAuthEmail(options.email.environment, {
							to: message.to,
							fromName: appName,
							subject: `Your ${appName} verification code`,
							react: authenticationEmail({
								branding,
								title: "Your verification code",
								description: `Use this code to complete forget password for ${appName}. It expires in five minutes.`,
								code: message.code,
							}),
						});
				},
				() => options.onDeliveryFailure?.(operation),
			));
		return scheduled
			? json({ success: true })
			: failure(
					503,
					"EMAIL_DELIVERY_UNAVAILABLE",
					"Authentication email is unavailable.",
				);
	}

	async function reset(
		request: Request,
		entered: string,
		identity: ProjectEmailIdentity | null,
		input: z.infer<typeof resetInput>,
	) {
		const { password, otp } = input;
		const rules = policy.passwordPolicy;
		const policyError = passwordPolicyError(password, rules);
		if (policyError)
			return failure(
				400,
				password.length < rules.minLength
					? "PASSWORD_TOO_SHORT"
					: password.length > rules.maxLength
						? "PASSWORD_TOO_LONG"
						: "PASSWORD_REQUIREMENTS_NOT_MET",
				policyError,
			);
		const actor = await options.prepareEmailOtpReset?.(request);
		if (actor instanceof Response) return actor;
		if (!identity) return failure(...otpErrors.invalid);
		const identifier = projectEmailOtpIdentifier(
			"forget-password",
			identity.email,
		);
		const before = await store.transaction(async (client) => {
			const user = await lockRecipient(client, entered, identity);
			if (!user) return { status: "invalid" } as const;
			return {
				...(await proof.verify(client, identifier, otp, { consume: false })),
				userId: user.id,
			};
		});
		if (before.status !== "valid") {
			const [status, code, message] = otpErrors[before.status];
			return failure(status, code, message);
		}

		// Verify possession before contacting the breach corpus. Recheck the same
		// locked challenge before writes, with no database lock held during egress or KDF.
		const safety = await options
			.checkPasswordSafety(password)
			.catch(() => "unavailable" as const);
		if (safety === "unavailable") return unavailable();
		const passwordHash =
			safety === "allowed"
				? await clerkCompatiblePasswords.hash(password)
				: null;
		const result = await store.transaction(async (client) => {
			const user = await lockRecipient(client, entered, identity);
			if (!user || user.id !== before.userId) return "invalid";
			const verified = await proof.verify(client, identifier, otp, {
				consume: passwordHash === null,
				expectedId: before.id,
			});
			if (verified.status !== "valid") return verified.status;
			if (passwordHash === null) return "breached";
			return (await writeOwnedPasswordReset(client, store, {
				userId: user.id,
				email: user.email,
				passwordHash,
				path: "/email-otp/reset-password",
				actorId: actor,
			}))
				? "reset"
				: "unavailable";
		});
		switch (result) {
			case "reset":
				return json({ success: true });
			case "breached":
				return failure(
					400,
					"PASSWORD_COMPROMISED",
					"The password you entered has been compromised. Please choose a different password.",
				);
			case "unavailable":
				return unavailable();
			default: {
				const [status, code, message] = otpErrors[result];
				return failure(status, code, message);
			}
		}
	}

	return async function handle(
		request: Request,
		operation: EmailOTPRecoveryOperation,
		input: unknown,
	) {
		// The installed alias hook covers modern and typed OTP paths only.
		const useAliases = operation !== deprecatedOperation;
		const raw = useAliases
			? (options.emailAliases?.normalizeInput(input) ?? input)
			: input;
		const parsed = operationInput.safeParse({ operation, body: raw });
		if (!parsed.success)
			return failure(
				400,
				"INVALID_BODY",
				"Supply a valid password recovery request.",
			);
		const entered = parsed.data.body.email.toLowerCase();
		const validEmail = email.safeParse(entered).success;
		if (operation === sendOperation && !validEmail)
			return failure(400, "INVALID_EMAIL", "Invalid email");
		const identity = validEmail
			? useAliases
				? await resolve(entered)
				: { email: entered }
			: null;
		const denied = await options.admit(
			request,
			operation,
			identity?.email ?? entered,
		);
		if (denied) return denied;
		if (!policy.emailAndPasswordEnabled)
			return failure(
				403,
				"FORBIDDEN",
				"Password authentication is disabled for this application.",
			);
		if (parsed.data.operation === resetOperation)
			return reset(request, entered, identity, parsed.data.body);
		return issue(entered, identity, parsed.data.operation);
	};
}
