import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import {
	defaultPasswordPolicy,
	passwordPolicyError,
} from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { ProjectSession, ProjectUser } from "./owned-project-engine-store";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

const changeInput = z.object({
	newPassword: z.string(),
	currentPassword: z.string(),
	revokeOtherSessions: z.boolean().optional(),
});
const enrollmentInput = changeInput.pick({ newPassword: true });

type PasswordSafety = "allowed" | "breached" | "unavailable";
export interface ProjectPasswordAuthority {
	user: ProjectUser;
	session: ProjectSession;
}
export interface OwnedProjectPasswordChangeOptions {
	database: Pool;
	project: Pick<Project, "schemaName">;
	policy: AuthPolicy;
	checkPasswordSafety(password: string): Promise<PasswordSafety>;
	/** Read the current realm's authoritative session, using the browser session cookie. */
	readAuthority(request: Request): Promise<ProjectPasswordAuthority | null>;
	/** Lock the current user and its live session in that order, then return fresh values. */
	lockAuthority(
		client: PoolClient,
		request: Request,
	): Promise<ProjectPasswordAuthority | null>;
	/** Revoke existing sessions with their linked grants, then issue the replacement in this transaction. */
	rotateSession(
		client: PoolClient,
		request: Request,
		authority: ProjectPasswordAuthority,
	): Promise<{ token: string; headers: Headers }>;
}

type CredentialAccount = {
	id: string;
	accountId: string;
	password: string | null;
};
type PasswordUserFields = {
	banReason: string | null;
	banExpires: Date | null;
};

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

function failure(status: number, code: string, message: string) {
	return json({ code, message }, status);
}

function unauthorized() {
	return failure(401, "UNAUTHORIZED", "Unauthorized");
}

function unavailable() {
	return failure(
		503,
		"PASSWORD_CHANGE_UNAVAILABLE",
		"Password changes are temporarily unavailable.",
	);
}

function invalidPassword() {
	return failure(400, "INVALID_PASSWORD", "Invalid password");
}

function accountNotFound() {
	return failure(
		400,
		"CREDENTIAL_ACCOUNT_NOT_FOUND",
		"Credential account not found",
	);
}

function alreadyEnrolled() {
	return failure(
		400,
		"PASSWORD_ALREADY_SET",
		"User already has a password set",
	);
}

/** Compatible authenticated credential changes, including the legacy server-only enrollment operation. */
export function createOwnedProjectPasswordChange(
	options: OwnedProjectPasswordChangeOptions,
) {
	const schema = checkedProjectSchema(options.project.schemaName);
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEngineStore(options.database, schema);

	function admit(authority: ProjectPasswordAuthority | null): Response | null {
		if (!authority || authority.user.id !== authority.session.userId)
			return unauthorized();
		const { user, session } = authority;
		if (session.impersonatedBy)
			return failure(
				403,
				"FORBIDDEN",
				"Authentication changes and account deletion are unavailable during impersonation.",
			);
		if (user.banned || user.directoryDisabled || user.isAnonymous)
			return unauthorized();
		if (user.directoryManaged)
			return failure(
				403,
				"FORBIDDEN",
				"This account must sign in through its enterprise identity provider.",
			);
		if (
			policy.mfaMode === "required" &&
			(!user.twoFactorEnabled || !user.emailVerified)
		)
			return failure(
				403,
				"FORBIDDEN",
				"This application requires an already verified account enrolled in MFA.",
			);
		return null;
	}

	async function credential(userId: string, client?: PoolClient) {
		const { rows } = await (
			client ?? options.database
		).query<CredentialAccount>(
			`SELECT id, "accountId", password FROM "${schema}"."account"
			 WHERE "userId" = $1 AND "providerId" = 'credential'
			 ORDER BY id LIMIT 2${client ? " FOR UPDATE" : ""}`,
			[userId],
		);
		if (rows.length > 1 || (rows[0] && rows[0].accountId !== userId))
			return false;
		return rows[0] ?? null;
	}

	async function replace(
		request: Request,
		input: {
			newPassword: string;
			currentPassword?: string;
			revokeOtherSessions?: boolean;
		},
	) {
		const { newPassword, currentPassword, revokeOtherSessions } = input;
		const enroll = currentPassword === undefined;
		const rules = policy.passwordPolicy;
		const policyError = passwordPolicyError(newPassword, rules);
		if (policyError)
			return failure(
				400,
				newPassword.length < rules.minLength
					? "PASSWORD_TOO_SHORT"
					: newPassword.length > rules.maxLength
						? "PASSWORD_TOO_LONG"
						: "PASSWORD_REQUIREMENTS_NOT_MET",
				policyError,
			);
		if (!policy.emailAndPasswordEnabled)
			return failure(
				403,
				"FORBIDDEN",
				"Password authentication is disabled for this application.",
			);

		const authority = await options.readAuthority(request);
		const denied = admit(authority);
		if (denied || !authority) return denied ?? unauthorized();
		if (
			currentPassword !== undefined &&
			currentPassword.length > defaultPasswordPolicy.maxLength
		)
			return failure(400, "PASSWORD_TOO_LONG", "Password too long");
		const snapshot = await credential(authority.user.id);
		if (snapshot === false) return unavailable();
		if (currentPassword !== undefined) {
			if (!snapshot?.password) return accountNotFound();
			if (
				!(await clerkCompatiblePasswords.verify({
					hash: snapshot.password,
					password: currentPassword,
				}))
			)
				return invalidPassword();
		} else if (snapshot?.password) {
			return alreadyEnrolled();
		}

		// Keep the breach check and KDF outside the transaction, then compare the
		// credential snapshot again while the current user and session are locked.
		const safety = await options
			.checkPasswordSafety(newPassword)
			.catch(() => "unavailable" as const);
		if (safety === "breached")
			return failure(
				400,
				"PASSWORD_COMPROMISED",
				"The password you entered has been compromised. Please choose a different password.",
			);
		if (safety !== "allowed") return unavailable();
		const hashed = await clerkCompatiblePasswords.hash(newPassword);

		return store.transaction(async (client) => {
			const current = await options.lockAuthority(client, request);
			if (
				!current ||
				current.user.id !== authority.user.id ||
				current.session.id !== authority.session.id
			)
				return unauthorized();
			const denied = admit(current);
			if (denied) return denied;
			const userId = current.user.id;
			const account = await credential(userId, client);
			if (account === false) return unavailable();
			if (currentPassword === undefined && account?.password)
				return alreadyEnrolled();
			if (currentPassword !== undefined && !account?.password)
				return accountNotFound();
			if (
				currentPassword !== undefined &&
				(account?.id !== snapshot?.id ||
					account?.password !== snapshot?.password)
			)
				return invalidPassword();

			const path = enroll ? "/set-password" : "/change-password";
			if (account) {
				await client.query(
					'UPDATE "account" SET password = $1, "updatedAt" = statement_timestamp() WHERE id = $2',
					[hashed, account.id],
				);
			} else {
				const accountId = randomUUID();
				await client.query(
					`INSERT INTO "account"(id, "accountId", "providerId", "userId", password, "updatedAt")
					 VALUES ($1, $2, 'credential', $2, $3, statement_timestamp())`,
					[accountId, userId, hashed],
				);
				await store.record(
					client,
					"account.linked",
					"success",
					path,
					userId,
					accountId,
				);
			}
			const rotation = revokeOtherSessions
				? await options.rotateSession(client, request, current)
				: undefined;
			await store.record(
				client,
				enroll ? "user.password-set" : "user.password-changed",
				"success",
				path,
				userId,
			);
			if (enroll) return json({ status: true });
			const { rows } = await client.query<PasswordUserFields>(
				'SELECT "banReason", "banExpires" FROM "user" WHERE id = $1',
				[userId],
			);
			return json(
				{
					token: rotation?.token ?? null,
					user: {
						...projectUserResponse(current.user),
						...rows[0],
						directoryManaged: current.user.directoryManaged,
						directoryDisabled: current.user.directoryDisabled,
					},
				},
				200,
				rotation?.headers,
			);
		});
	}

	return {
		async change(request: Request, input: unknown) {
			const parsed = changeInput.safeParse(input);
			return parsed.success
				? replace(request, parsed.data)
				: failure(400, "INVALID_BODY", "Supply a valid password request.");
		},
		// This is the existing server-only setPassword contract. Keep HTTP dispatch on change.
		async enroll(request: Request, input: unknown) {
			const parsed = enrollmentInput.safeParse(input);
			return parsed.success
				? replace(request, parsed.data)
				: failure(400, "INVALID_BODY", "Supply a valid password request.");
		},
	};
}
