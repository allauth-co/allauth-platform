import {
	createHmac,
	randomBytes,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord } from "./legacy-mfa-record";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { verifyOwnedMfaTotp } from "./owned-mfa-enrollment-totp";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { consumeProjectRecoveryCode } from "./recovery-code-store";
import type { Project } from "./registry";
import { checkedProjectSchema, projectSlug } from "./validation";

const challengeAge = 10 * 60;
const trustAge = 7 * 24 * 60 * 60;
const challengeBudget = 5;
const accountBudget = 10;
const lockoutSeconds = 15 * 60;
const challengePattern = /^2fa-[A-Za-z0-9_-]{20}$/;
const trustValuePattern =
	/^([A-Za-z0-9_-]{43})!(trust-device-[A-Za-z0-9_-]{32})$/;
const expiredDuringAttempt = Symbol("expired MFA challenge");

type MfaMethod = "totp" | "backup";
type Verification = {
	id: string;
	identifier: string;
	value: string;
	live: boolean;
};
type Factor = {
	id: string;
	secret: string;
	verified: boolean | null;
	locked: boolean;
};
type CompletionInput = {
	method: MfaMethod;
	code: string;
	trustDevice?: boolean;
	disableSession?: boolean;
};

const failures = {
	invalidChallenge: [
		401,
		"INVALID_TWO_FACTOR_COOKIE",
		"Invalid two factor cookie",
	],
	invalidTotp: [401, "INVALID_CODE", "Invalid code"],
	invalidBackup: [401, "INVALID_BACKUP_CODE", "Invalid backup code"],
	noTotp: [400, "TOTP_NOT_ENABLED", "TOTP not enabled"],
	noBackup: [400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled"],
	spent: [
		400,
		"TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
		"Too many attempts. Please request a new code.",
	],
	locked: [
		429,
		"ACCOUNT_TEMPORARILY_LOCKED",
		"Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
	],
	conflict: [
		409,
		"CONFLICT",
		"Failed to verify backup code. Please try again.",
	],
} as const;

function rejected(key: keyof typeof failures, setCookies: string[] = []) {
	const [httpStatus, code, message] = failures[key];
	return { status: "rejected" as const, httpStatus, code, message, setCookies };
}

/** Pending project MFA that shares the legacy record, cookie and attempt formats. */
export function createOwnedProjectMfa(options: {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	signingSecret: string;
	secureCookies: boolean;
	keys?: LegacyMfaKeys;
}) {
	const schema = checkedProjectSchema(options.project.schemaName);
	const slug = projectSlug.parse(options.project.slug);
	const { signingSecret, secureCookies } = options;
	if (signingSecret.length < 32)
		throw new Error("Invalid project MFA signing key.");
	const store = createProjectEngineStore(options.database, schema);
	const keys = options.keys ?? { secret: signingSecret };
	const prefix = `${secureCookies ? "__Secure-" : ""}allauth_project_${slug}.`;
	const sessionCookie = `${prefix}session_token`;
	const challengeCookie = `${prefix}two_factor`;
	const trustCookie = `${prefix}trust_device`;
	const rememberCookie = `${prefix}dont_remember`;
	const attributes = `Path=/; HttpOnly; SameSite=Lax${secureCookies ? "; Secure" : ""}`;
	const expire = (name: string) => `${name}=; Max-Age=0; ${attributes}`;

	function signedCookie(name: string, value: string, maxAge: number) {
		const signature = createHmac("sha256", signingSecret)
			.update(value)
			.digest("base64");
		return `${name}=${encodeURIComponent(`${value}.${signature}`)}; Max-Age=${maxAge}; ${attributes}`;
	}

	async function activeOwner(client: PoolClient, id: string) {
		const owner = await client.query<{ id: string }>(
			`SELECT id FROM "${schema}"."user"
			WHERE id = $1 AND "twoFactorEnabled" = TRUE
				AND banned IS DISTINCT FROM TRUE AND "directoryDisabled" IS DISTINCT FROM TRUE
			FOR UPDATE`,
			[id],
		);
		return owner.rows[0]?.id;
	}

	async function factor(client: PoolClient, userId: string) {
		const result = await client.query<Factor>(
			`SELECT id, secret, verified, COALESCE("lockedUntil" > clock_timestamp(), FALSE) AS locked
			FROM "${schema}"."twoFactor" WHERE "userId" = $1 ORDER BY id LIMIT 2 FOR UPDATE`,
			[userId],
		);
		const row = result.rows[0];
		return result.rows.length === 1 && row?.verified !== false ? row : null;
	}

	async function hasEnrolledFactor(client: PoolClient, userId: string) {
		return Boolean(
			(await activeOwner(client, userId)) && (await factor(client, userId)),
		);
	}

	/** Call from the primary-credential transaction after authenticating the owner. */
	async function issue(client: PoolClient, userId: string) {
		if (!(await hasEnrolledFactor(client, userId))) return null;
		const identifier = `2fa-${randomBytes(15).toString("base64url")}`;
		await client.query(
			`INSERT INTO "${schema}"."verification" (id, identifier, value, "expiresAt")
			VALUES ($1, $2, $3, statement_timestamp() + $6::int * interval '1 second'),
			       ($4, $5, '0', statement_timestamp() + $6::int * interval '1 second')`,
			[
				randomUUID(),
				identifier,
				userId,
				randomUUID(),
				`2fa-attempts-${identifier}`,
				challengeAge,
			],
		);
		const twoFactorMethods: MfaMethod[] = ["totp"];
		return {
			setCookie: signedCookie(challengeCookie, identifier, challengeAge),
			twoFactorMethods,
		};
	}

	function trustedDeviceToken(userId: string, identifier: string) {
		return createHmac("sha256", signingSecret)
			.update(`${userId}!${identifier}`)
			.digest("base64url");
	}

	async function issueTrustedDevice(client: PoolClient, userId: string) {
		const identifier = `trust-device-${randomBytes(24).toString("base64url")}`;
		const token = trustedDeviceToken(userId, identifier);
		await client.query(
			`INSERT INTO "${schema}"."verification" (id, identifier, value, "expiresAt")
			VALUES ($1, $2, $3, statement_timestamp() + $4::int * interval '1 second')`,
			[randomUUID(), identifier, userId, trustAge],
		);
		return signedCookie(trustCookie, `${token}!${identifier}`, trustAge);
	}

	/** Rotate a legacy trusted device inside the same transaction as primary sign-in. */
	async function rotateTrustedDevice(
		client: PoolClient,
		userId: string,
		headers: Headers,
	) {
		const present = (headers.get("cookie") ?? "")
			.split(";")
			.some(
				(part) =>
					part.includes("=") &&
					part.slice(0, part.indexOf("=")).trim() === trustCookie,
			);
		if (!present) return { trusted: false, setCookie: null };
		const invalid = { trusted: false, setCookie: expire(trustCookie) };
		const value = readLegacySessionCookie(headers, trustCookie, signingSecret);
		const match = value && trustValuePattern.exec(value);
		if (!match) return invalid;
		const token = match[1]!;
		const identifier = match[2]!;
		const encoder = new TextEncoder();
		if (
			!timingSafeEqual(
				encoder.encode(token),
				encoder.encode(trustedDeviceToken(userId, identifier)),
			)
		)
			return invalid;
		if (!(await activeOwner(client, userId))) return invalid;
		const records = await client.query<{ id: string; value: string }>(
			`SELECT id, value FROM "${schema}"."verification" WHERE identifier = $1
			ORDER BY id LIMIT 2 FOR UPDATE`,
			[identifier],
		);
		if (records.rows.length !== 1 || records.rows[0]?.value !== userId)
			return invalid;
		const deleted = await client.query(
			`DELETE FROM "${schema}"."verification" WHERE id = $1 AND "expiresAt" > statement_timestamp()`,
			[records.rows[0].id],
		);
		if (deleted.rowCount !== 1) return invalid;
		return {
			trusted: true,
			setCookie: await issueTrustedDevice(client, userId),
		};
	}

	/** Verify the factor and run the completion callback in the same transaction. */
	async function complete<T>(
		headers: Headers,
		input: CompletionInput,
		completeVerified: (
			client: PoolClient,
			verified: { userId: string; dontRememberMe: boolean },
		) => Promise<T>,
	) {
		const identifier = readLegacySessionCookie(
			headers,
			challengeCookie,
			signingSecret,
		);
		if (!identifier || !challengePattern.test(identifier))
			return rejected("invalidChallenge");
		const existingSession = readLegacySessionCookie(
			headers,
			sessionCookie,
			signingSecret,
		);
		const attemptsIdentifier = `2fa-attempts-${identifier}`;
		const expiredCookie = [expire(challengeCookie)];
		try {
			return await store.transaction(async (client) => {
				// Authenticated re-verification belongs to the active session, not a pending sign-in.
				if (existingSession) {
					const current = await client.query(
						`SELECT 1 FROM "${schema}"."session" WHERE token = $1 AND "expiresAt" > statement_timestamp()`,
						[existingSession],
					);
					if (current.rows.length !== 0) return rejected("invalidChallenge");
				}
				const pending = await client.query<{ value: string }>(
					`SELECT value FROM "${schema}"."verification" WHERE identifier = $1
						AND "expiresAt" > clock_timestamp() LIMIT 2`,
					[identifier],
				);
				if (pending.rows.length !== 1)
					return rejected("invalidChallenge", expiredCookie);
				// Lock the user first, matching password reset and directory admission changes.
				const userId = await activeOwner(client, pending.rows[0]!.value);
				if (!userId) return rejected("invalidChallenge", expiredCookie);
				const enrolled = await factor(client, userId);
				if (!enrolled)
					return rejected(input.method === "totp" ? "noTotp" : "noBackup");
				const records = await client.query<Verification>(
					`SELECT id, identifier, value, "expiresAt" > clock_timestamp() AS live
					FROM "${schema}"."verification" WHERE identifier = ANY($1::text[])
					ORDER BY identifier, id LIMIT 3 FOR UPDATE`,
					[[identifier, attemptsIdentifier]],
				);
				const challenge = records.rows.find(
					(row) => row.identifier === identifier,
				);
				const counter = records.rows.find(
					(row) => row.identifier === attemptsIdentifier,
				);
				if (
					records.rows.length !== 2 ||
					!challenge?.live ||
					challenge.value !== userId ||
					!counter?.live
				)
					return rejected("invalidChallenge", expiredCookie);
				if (enrolled.locked) return rejected("locked");
				const ids = [challenge.id, counter.id];
				const count = /^[0-9]+$/.test(counter.value)
					? Number(counter.value)
					: Infinity;
				if (count >= challengeBudget) {
					await client.query(
						`DELETE FROM "${schema}"."verification" WHERE id = ANY($1::text[])`,
						[ids],
					);
					return rejected("spent", expiredCookie);
				}

				const result =
					input.method === "totp"
						? verifyOwnedMfaTotp(
								openLegacyMfaRecord(enrolled.secret, keys),
								input.code,
								Date.now(),
							)
							? "consumed"
							: "invalid"
						: await consumeProjectRecoveryCode(client, {
								schemaName: schema,
								userId,
								code: input.code,
								keys,
							});
				if (result === "conflict") return rejected("conflict");
				if (result === "invalid") {
					await client.query(
						`UPDATE "${schema}"."verification" SET value = $1, "updatedAt" = statement_timestamp() WHERE id = $2`,
						[String(count + 1), counter.id],
					);
					await client.query(
						`UPDATE "${schema}"."twoFactor"
						SET "failedVerificationCount" = CASE WHEN "lockedUntil" <= statement_timestamp()
							THEN 1 ELSE COALESCE("failedVerificationCount", 0) + 1 END,
						"lockedUntil" = CASE WHEN "lockedUntil" <= statement_timestamp() THEN NULL
							WHEN COALESCE("failedVerificationCount", 0) + 1 >= $2
							THEN statement_timestamp() + $3::int * interval '1 second' ELSE NULL END
						WHERE id = $1`,
						[enrolled.id, accountBudget, lockoutSeconds],
					);
					return rejected(
						input.method === "totp" ? "invalidTotp" : "invalidBackup",
					);
				}

				const verifyOnly = input.method === "backup" && input.disableSession;
				// A legacy verification without sign-in spends the attempt record but leaves the challenge cookie alone.
				const completedIds = verifyOnly ? [counter.id] : ids;
				const deleted = await client.query(
					`DELETE FROM "${schema}"."verification"
					WHERE id = ANY($1::text[]) AND "expiresAt" > statement_timestamp()`,
					[completedIds],
				);
				if (deleted.rowCount !== completedIds.length)
					throw expiredDuringAttempt;
				await client.query(
					`UPDATE "${schema}"."twoFactor" SET "failedVerificationCount" = 0, "lockedUntil" = NULL,
						verified = CASE WHEN $2 THEN TRUE ELSE verified END WHERE id = $1`,
					[enrolled.id, input.method === "totp"],
				);
				const dontRememberMe = Boolean(
					readLegacySessionCookie(headers, rememberCookie, signingSecret),
				);
				const session = await completeVerified(client, {
					userId,
					dontRememberMe,
				});
				if (verifyOnly)
					return { status: "verified" as const, session, setCookies: [] };
				const setCookies = input.trustDevice
					? [
							...expiredCookie,
							await issueTrustedDevice(client, userId),
							expire(rememberCookie),
						]
					: expiredCookie;
				return { status: "verified" as const, session, setCookies };
			});
		} catch (error) {
			if (error === expiredDuringAttempt)
				return rejected("invalidChallenge", expiredCookie);
			throw error;
		}
	}

	return { issue, complete, rotateTrustedDevice, hasEnrolledFactor };
}
