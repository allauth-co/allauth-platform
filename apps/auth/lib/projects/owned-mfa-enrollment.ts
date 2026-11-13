import {
	randomBytes,
	randomInt,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { defaultPasswordPolicy } from "../auth-policy/password";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { ControlEventInput } from "../control/types";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord, sealLegacyMfaRecord } from "./legacy-mfa-record";
import {
	ownedMfaTotpUri,
	verifyOwnedMfaTotp,
} from "./owned-mfa-enrollment-totp";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";
import { checkedProjectSchema, projectSlug } from "./validation";

type MfaUser = { id: string; email: string; twoFactorEnabled: boolean | null };
type MfaSession = { id: string };
type Authority<User, Session> = { user: User; session: Session };
type Factor = {
	id: string;
	secret: string;
	backupCodes: string;
	verified: boolean | null;
};
type MutationPath = "/two-factor/verify-totp" | "/two-factor/disable";
type PasswordInput = { password?: string };

const mutationEvents = {
	"/two-factor/enable": "mfa.enrollment-started",
	"/two-factor/disable": "mfa.disabled",
	"/two-factor/generate-backup-codes": "mfa.recovery-codes-rotated",
} as const;

interface Options<User extends MfaUser, Session extends MfaSession, Rotation> {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	keys: LegacyMfaKeys;
	issuer: string;
	secureCookies: boolean;
	mfaRequired: boolean;
	/** Project-resolved browser event provenance. */
	auditContext(
		request: Request,
	): Pick<ControlEventInput, "ipAddress" | "userAgent">;
	/** Resolve and lock a current, authorized database session. Lock its user before the session. */
	lockAuthority(
		client: PoolClient,
		request: Request,
		options: { fresh: boolean },
	): Promise<Authority<User, Session> | null>;
	/** Insert the replacement session on this client and return its public response data and cookies. */
	rotateSession(
		client: PoolClient,
		request: Request,
		authority: Authority<User, Session>,
		path: MutationPath,
	): Promise<{ sessionId: string; value: Rotation }>;
}

const failures = {
	unauthorized: [401, "UNAUTHORIZED", "Unauthorized"],
	invalidPassword: [400, "INVALID_PASSWORD", "Invalid password"],
	longPassword: [400, "PASSWORD_TOO_LONG", "Password too long"],
	duplicateFactor: [
		409,
		"TWO_FACTOR_RECORD_CONFLICT",
		"Two-factor records could not be resolved.",
	],
	alreadyEnrolled: [400, "TOTP_ALREADY_ENABLED", "TOTP is already enabled"],
	otpUnsupported: [400, "OTP_NOT_CONFIGURED", "OTP is not available"],
	noTotp: [400, "TOTP_NOT_ENABLED", "TOTP not enabled"],
	noBackup: [400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled"],
	mfaNotEnabled: [400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"],
	invalidTotp: [401, "INVALID_CODE", "Invalid code"],
	invalidBackup: [401, "INVALID_BACKUP_CODE", "Invalid backup code"],
	required: [
		403,
		"FORBIDDEN",
		"MFA cannot be disabled while this application requires it.",
	],
} as const;

function reject(key: keyof typeof failures) {
	const [httpStatus, code, message] = failures[key];
	return { status: "rejected" as const, httpStatus, code, message };
}

function newBackupCodes() {
	const alphabet =
		"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const codes = new Set<string>();
	while (codes.size < 10) {
		const code = Array.from(
			{ length: 10 },
			() => alphabet[randomInt(alphabet.length)],
		).join("");
		codes.add(`${code.slice(0, 5)}-${code.slice(5)}`);
	}
	return [...codes];
}

const encoder = new TextEncoder();

function removeBackupCode(
	encrypted: string,
	code: string,
	keys: LegacyMfaKeys,
) {
	const codes: unknown = JSON.parse(openLegacyMfaRecord(encrypted, keys));
	if (
		!Array.isArray(codes) ||
		!codes.every((value: unknown): value is string => typeof value === "string")
	)
		throw new Error("Could not read the existing recovery codes.");
	const supplied = encoder.encode(code);
	const remaining = codes.filter((value) => {
		const expected = encoder.encode(value);
		return (
			expected.length !== supplied.length ||
			!timingSafeEqual(expected, supplied)
		);
	});
	return remaining.length < codes.length
		? sealLegacyMfaRecord(JSON.stringify(remaining), keys)
		: null;
}

/** Authenticated MFA operations over the project's legacy enrolment and revocation records. */
export function createOwnedMfaEnrollment<
	User extends MfaUser,
	Session extends MfaSession,
	Rotation,
>(options: Options<User, Session, Rotation>) {
	const schema = checkedProjectSchema(options.project.schemaName);
	const slug = projectSlug.parse(options.project.slug);
	const store = createProjectEngineStore(options.database, schema);
	const { keys, issuer } = options;
	const { secureCookies } = options;
	const prefix = `${secureCookies ? "__Secure-" : ""}allauth_project_${slug}.`;
	const expired = (name: string) =>
		`${prefix}${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secureCookies ? "; Secure" : ""}`;

	function recordMfaEvent(
		client: PoolClient,
		request: Request,
		userId: string | undefined,
		type: string,
		path: string,
		errorCode?: string,
	) {
		return store.recordEvent(client, {
			...options.auditContext(request),
			type,
			outcome: errorCode ? "failure" : "success",
			actorId: userId,
			userId,
			metadata: { path, ...(errorCode ? { errorCode } : {}) },
		});
	}

	function auditedMutation<T extends { status: string; code?: string }>(
		request: Request,
		path: keyof typeof mutationEvents,
		work: (client: PoolClient, auth: Authority<User, Session>) => Promise<T>,
	) {
		return store.transaction(async (client) => {
			const auth = await options.lockAuthority(client, request, {
				fresh: false,
			});
			const result = auth ? await work(client, auth) : reject("unauthorized");
			await recordMfaEvent(
				client,
				request,
				auth?.user.id,
				mutationEvents[path],
				path,
				result.status === "rejected" ? result.code : undefined,
			);
			return result;
		});
	}

	async function recordMalformedMutation(
		request: Request,
		path: keyof typeof mutationEvents,
	) {
		if (path === "/two-factor/disable" && options.mfaRequired) return;
		await store.transaction(async (client) => {
			const auth = await options.lockAuthority(client, request, {
				fresh: false,
			});
			await recordMfaEvent(
				client,
				request,
				auth?.user.id,
				mutationEvents[path],
				path,
				"VALIDATION_ERROR",
			);
		});
	}

	async function lockFactor(client: PoolClient, userId: string) {
		return (
			await client.query<Factor>(
				`SELECT id, secret, "backupCodes", verified FROM "${schema}"."twoFactor"
			WHERE "userId" = $1 ORDER BY id LIMIT 2 FOR UPDATE`,
				[userId],
			)
		).rows;
	}

	async function authorizePassword(
		client: PoolClient,
		userId: string,
		password: string | undefined,
	) {
		const credentials = (
			await client.query<{ password: string | null }>(
				`SELECT password FROM "${schema}"."account" WHERE "userId" = $1 AND "providerId" = 'credential'
			ORDER BY id LIMIT 2 FOR UPDATE`,
				[userId],
			)
		).rows;
		if (credentials.length > 1) return reject("invalidPassword");
		const hash = credentials[0]?.password;
		if (hash && password && password.length > defaultPasswordPolicy.maxLength)
			return reject("longPassword");
		if (
			hash &&
			(!password ||
				!(await clerkCompatiblePasswords.verify({ hash, password })))
		)
			return reject("invalidPassword");
		return null;
	}

	async function enable(
		request: Request,
		input: PasswordInput & { issuer?: string; method?: "totp" | "otp" },
	) {
		return auditedMutation(
			request,
			"/two-factor/enable",
			async (client, auth) => {
				const { id, email } = auth.user;
				const denied = await authorizePassword(client, id, input.password);
				if (denied) return denied;
				if (input.method === "otp") return reject("otpUnsupported");
				const factors = await lockFactor(client, id);
				if (factors.length > 1) return reject("duplicateFactor");
				const existing = factors[0];
				if (existing && existing.verified !== false)
					return reject("alreadyEnrolled");
				const secret = randomBytes(24).toString("base64url");
				const codes = newBackupCodes();
				const encrypted = sealLegacyMfaRecord(secret, keys);
				const encryptedCodes = sealLegacyMfaRecord(JSON.stringify(codes), keys);
				if (existing) {
					await client.query(
						`UPDATE "${schema}"."twoFactor" SET secret = $1, "backupCodes" = $2, verified = FALSE WHERE id = $3`,
						[encrypted, encryptedCodes, existing.id],
					);
				} else {
					await client.query(
						`INSERT INTO "${schema}"."twoFactor" (id, secret, "backupCodes", "userId", verified) VALUES ($1, $2, $3, $4, FALSE)`,
						[randomUUID(), encrypted, encryptedCodes, id],
					);
				}
				return {
					status: "setup" as const,
					method: "totp" as const,
					totpURI: ownedMfaTotpUri(secret, input.issuer || issuer, email),
					backupCodes: codes,
				};
			},
		);
	}

	async function rotate(
		client: PoolClient,
		request: Request,
		auth: Authority<User, Session>,
		enabled: boolean,
		path: MutationPath,
	) {
		const userId = auth.user.id;
		const changed = Boolean(auth.user.twoFactorEnabled) !== enabled;
		await client.query(
			`UPDATE "${schema}"."user" SET "twoFactorEnabled" = $1, "updatedAt" = statement_timestamp() WHERE id = $2`,
			[enabled, userId],
		);
		await store.record(client, "user.updated", "success", path, userId, userId);
		const replacement = await options.rotateSession(
			client,
			request,
			auth,
			path,
		);
		const stored = await client.query(
			`SELECT 1 FROM "${schema}"."session" WHERE id = $1 AND id <> $2 AND "userId" = $3
			AND "expiresAt" > statement_timestamp() AND "impersonatedBy" IS NULL`,
			[replacement.sessionId, auth.session.id, userId],
		);
		if (stored.rowCount !== 1)
			throw new Error("Could not rotate the project MFA session.");
		const revoked = await client.query<{ id: string }>(
			`DELETE FROM "${schema}"."session" WHERE "userId" = $1 AND id <> $2 AND ($3::boolean OR id = $4) RETURNING id`,
			[userId, replacement.sessionId, changed, auth.session.id],
		);
		// The native MFA endpoint audits the active rotation. Its account-wide cleanup deletes sibling sessions directly.
		if (revoked.rows.some(({ id }) => id === auth.session.id))
			await store.record(
				client,
				"session.deleted",
				"success",
				path,
				userId,
				auth.session.id,
			);
		if (changed) {
			await client.query(
				`DELETE FROM "${schema}"."oauthAccessToken" WHERE "userId" = $1`,
				[userId],
			);
			await client.query(
				`DELETE FROM "${schema}"."oauthRefreshToken" WHERE "userId" = $1`,
				[userId],
			);
			// The attempt rows store counts, so derive their identifiers from the owner's deleted challenges.
			await client.query(
				`WITH revoked AS (DELETE FROM "${schema}"."verification"
				 WHERE value = $1 AND (starts_with(identifier, 'trust-device-')
				 OR (starts_with(identifier, '2fa-') AND NOT starts_with(identifier, '2fa-attempts-')))
				 RETURNING identifier)
				 DELETE FROM "${schema}"."verification" WHERE identifier IN (
				 SELECT '2fa-attempts-' || identifier FROM revoked WHERE starts_with(identifier, '2fa-'))`,
				[userId],
			);
			const action = enabled ? "two-factor.enrolled" : "two-factor.disabled";
			await client.query(
				`INSERT INTO "${schema}"."allauthAudit" (id, "actorId", action, "targetId", "createdAt")
				VALUES ($1, $2, $3, $2, statement_timestamp())`,
				[randomUUID(), userId, action],
			);
			await store.record(client, action, "success", path, userId, userId);
		}
		return {
			status: "rotated" as const,
			value: replacement.value,
			setCookies: [expired("two_factor"), expired("trust_device")],
		};
	}

	async function verify(
		request: Request,
		input: { method: "totp" | "backup"; code: string },
	) {
		return store.transaction(async (client) => {
			const auth = await options.lockAuthority(client, request, {
				fresh: false,
			});
			if (!auth) return reject("unauthorized");
			const factors = await lockFactor(client, auth.user.id);
			if (factors.length > 1) return reject("duplicateFactor");
			const factor = factors[0];
			if (!factor)
				return reject(input.method === "totp" ? "noTotp" : "noBackup");
			if (input.method === "backup") {
				const remaining = removeBackupCode(
					factor.backupCodes,
					input.code,
					keys,
				);
				if (!remaining) return reject("invalidBackup");
				await client.query(
					`UPDATE "${schema}"."twoFactor" SET "backupCodes" = $1 WHERE id = $2`,
					[remaining, factor.id],
				);
				return { status: "verified" as const, authority: auth };
			}
			if (
				!verifyOwnedMfaTotp(
					openLegacyMfaRecord(factor.secret, keys),
					input.code,
				)
			)
				return reject("invalidTotp");
			if (factor.verified !== true) {
				await client.query(
					`UPDATE "${schema}"."twoFactor" SET verified = TRUE WHERE id = $1`,
					[factor.id],
				);
				if (!auth.user.twoFactorEnabled) {
					const path = "/two-factor/verify-totp";
					const result = await rotate(client, request, auth, true, path);
					await recordMfaEvent(
						client,
						request,
						auth.user.id,
						"mfa.verified",
						path,
					);
					return result;
				}
			}
			return { status: "verified" as const, authority: auth };
		});
	}

	async function disable(request: Request, input: PasswordInput) {
		if (options.mfaRequired) return reject("required");
		return auditedMutation(
			request,
			"/two-factor/disable",
			async (client, auth) => {
				const denied = await authorizePassword(
					client,
					auth.user.id,
					input.password,
				);
				if (denied) return denied;
				await client.query(
					`DELETE FROM "${schema}"."twoFactor" WHERE "userId" = $1`,
					[auth.user.id],
				);
				return rotate(client, request, auth, false, "/two-factor/disable");
			},
		);
	}

	async function readTotp(request: Request, input: PasswordInput) {
		return store.transaction(async (client) => {
			const auth = await options.lockAuthority(client, request, {
				fresh: false,
			});
			if (!auth) return reject("unauthorized");
			const factors = await lockFactor(client, auth.user.id);
			if (factors.length > 1) return reject("duplicateFactor");
			const factor = factors[0];
			if (!factor) return reject("noTotp");
			const denied = await authorizePassword(
				client,
				auth.user.id,
				input.password,
			);
			if (denied) return denied;
			const secret = openLegacyMfaRecord(factor.secret, keys);
			return {
				status: "uri" as const,
				totpURI: ownedMfaTotpUri(secret, issuer, auth.user.email),
			};
		});
	}

	async function rotateBackupCodes(request: Request, input: PasswordInput) {
		return auditedMutation(
			request,
			"/two-factor/generate-backup-codes",
			async (client, auth) => {
				if (!auth.user.twoFactorEnabled) return reject("mfaNotEnabled");
				const denied = await authorizePassword(
					client,
					auth.user.id,
					input.password,
				);
				if (denied) return denied;
				const factors = await lockFactor(client, auth.user.id);
				if (factors.length > 1) return reject("duplicateFactor");
				const factor = factors[0];
				if (!factor) return reject("mfaNotEnabled");
				const codes = newBackupCodes();
				await client.query(
					`UPDATE "${schema}"."twoFactor" SET "backupCodes" = $1 WHERE id = $2`,
					[sealLegacyMfaRecord(JSON.stringify(codes), keys), factor.id],
				);
				return { status: "codes" as const, backupCodes: codes };
			},
		);
	}

	return {
		enable,
		verify,
		disable,
		readTotp,
		rotateBackupCodes,
		recordMalformedMutation,
	};
}
