import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { passwordPolicyError } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { ControlEventInput } from "../control/types";
import { projectEmailOtpIdentifier } from "./owned-project-email-otp-proof";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { checkedProjectSchema } from "./validation";

export type PasswordSafety = "allowed" | "breached" | "unavailable";
type PasswordResetResult =
	| { status: "reset" }
	| {
			status:
				| "invalid-token"
				| "breached-password"
				| "breach-check-unavailable"
				| "unavailable";
	  }
	| {
			status: "password-policy";
			code:
				| "PASSWORD_TOO_SHORT"
				| "PASSWORD_TOO_LONG"
				| "PASSWORD_REQUIREMENTS_NOT_MET";
			message: string;
	  };

interface PasswordResetOptions {
	database: Pool;
	schemaName: string;
	policy: AuthPolicy;
	/** Supply the realm's approved breached-password policy. The primitive has no HTTP entry point. */
	checkPasswordSafety(password: string): Promise<PasswordSafety>;
}

export function isLegacyPasswordResetToken(token: string) {
	return /^[A-Za-z0-9]{24}$/.test(token);
}

/** Look up the latest live row without consuming it or exposing it to the caller. */
export async function findOwnedPasswordResetUser(
	database: Pool,
	schemaName: string,
	token: string,
) {
	const schema = checkedProjectSchema(schemaName);
	if (!isLegacyPasswordResetToken(token)) return null;
	const verification = await database.query<{ value: string }>(
		`SELECT value FROM (
			SELECT value, "expiresAt" FROM "${schema}"."verification" WHERE identifier = $1
			ORDER BY "createdAt" DESC, id DESC LIMIT 1
		) v WHERE "expiresAt" > statement_timestamp()`,
		[`reset-password:${token}`],
	);
	return verification.rows[0]?.value ?? null;
}

/** Replace a locked account's password and revoke its existing access in the proof transaction. */
export async function writeOwnedPasswordReset(
	client: PoolClient,
	store: Pick<ReturnType<typeof createProjectEngineStore>, "recordEvent">,
	input: {
		userId: string;
		email: string;
		passwordHash: string;
	} & (
		| {
				path: "/reset-password";
				linkIdentifier: string;
				auditContext?: Pick<ControlEventInput, "ipAddress" | "userAgent">;
		  }
		| { path: "/email-otp/reset-password" }
	),
) {
	const { userId, email, passwordHash, path } = input;
	const accounts = await client.query<{ id: string; accountId: string }>(
		`SELECT id, "accountId" FROM "account" WHERE "userId" = $1 AND "providerId" = 'credential'
		ORDER BY id LIMIT 2 FOR UPDATE`,
		[userId],
	);
	const account = accounts.rows[0];
	if (accounts.rows.length > 1 || (account && account.accountId !== userId))
		return false;

	if (account) {
		await client.query(
			'UPDATE "account" SET password = $1, "updatedAt" = statement_timestamp() WHERE id = $2',
			[passwordHash, account.id],
		);
	} else {
		const accountId = randomUUID();
		await client.query(
			`INSERT INTO "account" (id, "userId", "accountId", "providerId", password, "updatedAt")
			VALUES ($1, $2, $2, 'credential', $3, statement_timestamp())`,
			[accountId, userId, passwordHash],
		);
		await store.recordEvent(client, {
			type: "account.linked",
			outcome: "success",
			userId,
			targetId: accountId,
			metadata: { path, provider: "credential" },
		});
	}
	await client.query(
		`DELETE FROM "verification" WHERE identifier IN ($2, $3) OR (value = $1 AND (
			starts_with(identifier, 'reset-password:') OR starts_with(identifier, 'trust-device-')
			OR starts_with(identifier, '2fa-')
		))`,
		[
			userId,
			projectEmailOtpIdentifier("forget-password", email),
			input.path === "/reset-password" ? input.linkIdentifier : null,
		],
	);
	await client.query('DELETE FROM "oauthAccessToken" WHERE "userId" = $1', [
		userId,
	]);
	await client.query('DELETE FROM "oauthRefreshToken" WHERE "userId" = $1', [
		userId,
	]);
	if (path === "/email-otp/reset-password") {
		const verified = await client.query(
			`UPDATE "user" SET "emailVerified"=true, "updatedAt"=statement_timestamp()
			WHERE id=$1 AND "emailVerified" IS DISTINCT FROM true`,
			[userId],
		);
		if (verified.rowCount)
			await store.recordEvent(client, {
				type: "user.updated",
				outcome: "success",
				actorId: userId,
				userId,
				targetId: userId,
				metadata: { path },
			});
	}
	const sessions = await client.query<{ id: string }>(
		'DELETE FROM "session" WHERE "userId" = $1 RETURNING id',
		[userId],
	);
	for (const session of sessions.rows)
		await store.recordEvent(client, {
			type: "session.deleted",
			outcome: "success",
			userId,
			targetId: session.id,
			metadata: { path },
		});
	await client.query(
		`INSERT INTO "allauthAudit"(id, "actorId", action, "targetId", "createdAt")
		VALUES ($1, $2, 'password-reset', $2, statement_timestamp())`,
		[randomUUID(), userId],
	);
	await store.recordEvent(client, {
		type: "password-reset",
		outcome: "success",
		actorId: userId,
		targetId: userId,
	});
	if (path === "/reset-password")
		await store.recordEvent(client, {
			type: "user.password-reset",
			outcome: "success",
			...input.auditContext,
			metadata: { path },
		});
	return true;
}

/** A transaction-only candidate for consuming legacy password reset links. */
export function createOwnedPasswordReset(options: PasswordResetOptions) {
	const schema = checkedProjectSchema(options.schemaName);
	const policy = authPolicySchema.parse(options.policy);
	const store = createProjectEngineStore(options.database, schema);

	return async function consumePasswordReset(input: {
		token: string;
		newPassword: string;
		auditContext?: Pick<ControlEventInput, "ipAddress" | "userAgent">;
	}): Promise<PasswordResetResult> {
		if (!policy.emailAndPasswordEnabled) return { status: "unavailable" };
		const passwordPolicy = policy.passwordPolicy;
		const error = passwordPolicyError(input.newPassword, passwordPolicy);
		if (error) {
			const length = input.newPassword.length;
			const code =
				length < passwordPolicy.minLength
					? "PASSWORD_TOO_SHORT"
					: length > passwordPolicy.maxLength
						? "PASSWORD_TOO_LONG"
						: "PASSWORD_REQUIREMENTS_NOT_MET";
			return { status: "password-policy", code, message: error };
		}
		if (!isLegacyPasswordResetToken(input.token))
			return { status: "invalid-token" };

		const identifier = `reset-password:${input.token}`;
		// Only a current token can trigger the breach check and password KDF.
		const userId = await findOwnedPasswordResetUser(
			options.database,
			schema,
			input.token,
		);
		if (!userId) return { status: "invalid-token" };

		const safe = await options
			.checkPasswordSafety(input.newPassword)
			.catch(() => "unavailable" as const);
		if (safe === "breached") return { status: "breached-password" };
		if (safe !== "allowed") return { status: "breach-check-unavailable" };
		const hashed = await clerkCompatiblePasswords.hash(input.newPassword);

		return store.transaction(async (client) => {
			// Serialize all reset links for this account before locking individual verification rows.
			const {
				rows: [user],
			} = await client.query<{ email: string }>(
				`SELECT email FROM "user" WHERE id = $1 AND banned IS DISTINCT FROM true
					AND "directoryManaged" IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true
					AND "isAnonymous" IS DISTINCT FROM true FOR UPDATE`,
				[userId],
			);
			if (!user) return { status: "invalid-token" };
			const latest = await client.query<{ valid: boolean; value: string }>(
				`SELECT value, "expiresAt" > statement_timestamp() AS valid FROM "verification"
				WHERE identifier = $1 ORDER BY "createdAt" DESC, id DESC LIMIT 1 FOR UPDATE`,
				[identifier],
			);
			if (!latest.rows[0]?.valid || latest.rows[0].value !== userId)
				return { status: "invalid-token" };
			const written = await writeOwnedPasswordReset(client, store, {
				userId,
				email: user.email,
				passwordHash: hashed,
				path: "/reset-password",
				linkIdentifier: identifier,
				auditContext: input.auditContext,
			});
			return { status: written ? "reset" : "unavailable" };
		});
	};
}
