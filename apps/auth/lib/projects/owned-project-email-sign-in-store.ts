import {
	createHash,
	randomInt,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { AuthPolicy } from "../auth-policy/policy";
import type { ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";

const nativeIdAlphabet =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const magicAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const magicRecord = z
	.object({
		type: z.literal("magic-link"),
		email: z.email().max(320),
		name: z.string().max(256).optional(),
	})
	.strict();

export type EmailSignInPath = "/magic-link/verify" | "/sign-in/email-otp";
export type CompleteProjectEmailSignIn = (input: {
	/** Use this transaction for session or MFA writes. Do not perform external side effects. */
	client: PoolClient;
	user: ProjectUser;
	request: Request;
	path: EmailSignInPath;
	callbackURL?: string;
}) => Promise<Response>;

interface EmailProof {
	email: string;
	name?: string;
	image?: string;
}

interface VerificationRow {
	id: string;
	value: string;
	active: boolean;
}

type AuthResult =
	| { status: "authenticated" | "rejected"; response: Response }
	| {
			status:
				| "invalid"
				| "expired"
				| "attempts"
				| "blocked"
				| "signup-disabled"
				| "unsupported";
	  };

function hash(value: string) {
	return createHash("sha256").update(value).digest("base64url");
}

function randomText(alphabet: string) {
	return Array.from(
		{ length: 32 },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
}

function parseMagicRecord(value: string) {
	try {
		const result = magicRecord.safeParse(JSON.parse(value));
		return result.success ? result.data : null;
	} catch {
		return null;
	}
}

function otpIdentifier(email: string) {
	return `sign-in-otp-${email}`;
}

function sameHash(left: string, right: string) {
	const encoder = new TextEncoder();
	const a = encoder.encode(left);
	const b = encoder.encode(right);
	return a.length === b.length && timingSafeEqual(a, b);
}

export function createProjectEmailSignInStore(options: {
	database: Pool;
	schemaName: string;
	policy: AuthPolicy;
	completeSignIn: CompleteProjectEmailSignIn;
}) {
	const store = createProjectEngineStore(options.database, options.schemaName);

	async function lockOtp(client: PoolClient, identifier: string) {
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`allauth-email-otp:${options.schemaName}:${identifier}`],
		);
	}

	async function currentVerification(client: PoolClient, identifier: string) {
		return (
			(
				await client.query<VerificationRow>(
					`SELECT id, value, "expiresAt" > statement_timestamp() AS active FROM "verification"
			WHERE identifier = $1 ORDER BY "createdAt" DESC, id DESC LIMIT 1 FOR UPDATE`,
					[identifier],
				)
			).rows[0] ?? null
		);
	}

	async function clearVerification(client: PoolClient, identifier: string) {
		await client.query('DELETE FROM "verification" WHERE identifier = $1', [
			identifier,
		]);
	}

	const recipient = `SELECT COALESCE((
		SELECT NOT (banned IS TRUE OR "directoryManaged" IS TRUE OR "directoryDisabled" IS TRUE
			OR "isAnonymous" IS TRUE) FROM "user" WHERE email = $1
	), $2::boolean) AS eligible`;
	const insertProof = `INSERT INTO "verification" (id, identifier, value, "expiresAt")
		SELECT $3, $4, $5, statement_timestamp() + interval '5 minutes' FROM recipient WHERE eligible`;

	async function issueMagic(proof: EmailProof) {
		const token = randomText(magicAlphabet);
		return store.transaction(async (client) => {
			const result = await client.query(
				`WITH recipient AS (${recipient}) ${insertProof}`,
				[
					proof.email,
					options.policy.signUpEnabled,
					randomUUID(),
					`magic-link:${hash(token)}`,
					JSON.stringify({
						type: "magic-link",
						email: proof.email,
						name: proof.name,
					}),
				],
			);
			return result.rowCount ? token : null;
		});
	}

	async function issueOtp(email: string) {
		const identifier = otpIdentifier(email);
		const otp = String(randomInt(1_000_000)).padStart(6, "0");
		return store.transaction(async (client) => {
			await lockOtp(client, identifier);
			const result = await client.query(
				`WITH recipient AS (${recipient}), replaced AS (
					DELETE FROM "verification" WHERE identifier = $4 AND (SELECT eligible FROM recipient)
				)
				${insertProof}`,
				[
					email,
					options.policy.signUpEnabled,
					randomUUID(),
					identifier,
					`${hash(otp)}:0`,
				],
			);
			return result.rowCount ? otp : null;
		});
	}

	async function lockUserByEmail(client: PoolClient, email: string) {
		const result = await client.query<{ id: string }>(
			'SELECT id FROM "user" WHERE email = $1 FOR UPDATE',
			[email],
		);
		const id = result.rows[0]?.id;
		return id ? store.lockUser(client, id) : null;
	}

	async function promoteUnproven(
		client: PoolClient,
		user: ProjectUser,
		path: EmailSignInPath,
	) {
		// An unproven profile's old sign-in methods must never follow the mailbox owner.
		// An enrolled factor is ambiguous for an unverified identity; defer that case.
		const protectedAccess = await client.query<{ protected: boolean }>(
			`SELECT (EXISTS (SELECT 1 FROM "twoFactor" WHERE "userId" = $1)
				OR EXISTS (SELECT 1 FROM "passkey" WHERE "userId" = $1)) AS protected`,
			[user.id],
		);
		if (user.twoFactorEnabled || protectedAccess.rows[0]?.protected !== false)
			return null;
		await client.query('DELETE FROM "oauthAccessToken" WHERE "userId" = $1', [
			user.id,
		]);
		await client.query('DELETE FROM "oauthRefreshToken" WHERE "userId" = $1', [
			user.id,
		]);
		await client.query(
			`DELETE FROM "verification" WHERE value = $1 AND (
				starts_with(identifier, 'trust-device-') OR starts_with(identifier, '2fa-')
				OR starts_with(identifier, 'reset-password:')
			)`,
			[user.id],
		);
		const accounts = await client.query<{ id: string }>(
			'DELETE FROM "account" WHERE "userId" = $1 RETURNING id',
			[user.id],
		);
		for (const account of accounts.rows)
			await store.record(
				client,
				"account.deleted",
				"success",
				path,
				user.id,
				account.id,
			);
		const sessions = await client.query<{ id: string }>(
			'DELETE FROM "session" WHERE "userId" = $1 RETURNING id',
			[user.id],
		);
		for (const session of sessions.rows)
			await store.record(
				client,
				"session.deleted",
				"success",
				path,
				user.id,
				session.id,
			);
		await client.query(
			'UPDATE "user" SET "emailVerified" = true, "updatedAt" = statement_timestamp() WHERE id = $1',
			[user.id],
		);
		await store.record(
			client,
			"user.updated",
			"success",
			path,
			user.id,
			user.id,
		);
		return store.lockUser(client, user.id);
	}

	async function authenticate(
		client: PoolClient,
		proof: EmailProof,
		request: Request,
		path: EmailSignInPath,
		callbacks?: { existing?: string; created?: string },
	): Promise<AuthResult> {
		let user = await lockUserByEmail(client, proof.email);
		let created = false;
		if (!user) {
			if (!options.policy.signUpEnabled) return { status: "signup-disabled" };
			const newId = randomText(nativeIdAlphabet);
			const inserted = await client.query<{ id: string }>(
				`INSERT INTO "user" (id,name,email,image,"emailVerified",role,banned,"twoFactorEnabled",
					"isAnonymous","directoryManaged","directoryDisabled")
				VALUES ($1,$2,$3,$4,true,'user',false,false,false,false,false)
				ON CONFLICT (email) DO NOTHING RETURNING id`,
				[newId, proof.name ?? "", proof.email, proof.image ?? null],
			);
			created = inserted.rows.length === 1;
			user = created
				? await store.lockUser(client, newId)
				: await lockUserByEmail(client, proof.email);
		}
		if (
			!user ||
			user.banned ||
			user.directoryManaged ||
			user.directoryDisabled ||
			user.isAnonymous
		)
			return { status: "blocked" };
		if (created)
			await store.record(
				client,
				"user.created",
				"success",
				path,
				user.id,
				user.id,
			);
		if (!user.emailVerified) {
			user = await promoteUnproven(client, user, path);
			if (!user) return { status: "unsupported" };
		}
		const callbackURL = created ? callbacks?.created : callbacks?.existing;
		const response = await options.completeSignIn({
			client,
			user,
			request,
			path,
			callbackURL,
		});
		if (response.status >= 400) throw response;
		if (path === "/magic-link/verify" && callbackURL && response.ok) {
			const headers = new Headers(response.headers);
			headers.set("Location", callbackURL);
			headers.delete("Content-Type");
			return {
				status: "authenticated",
				response: new Response(null, { status: 302, headers }),
			};
		}
		return { status: "authenticated", response };
	}

	async function runAuth(
		work: (client: PoolClient) => Promise<AuthResult>,
	): Promise<AuthResult> {
		try {
			return await store.transaction(work);
		} catch (error) {
			if (error instanceof Response)
				return { status: "rejected", response: error };
			throw error;
		}
	}

	function verifyMagic(
		token: string,
		request: Request,
		callbacks: { existing?: string; created?: string },
	) {
		return runAuth(async (client) => {
			const identifier = `magic-link:${hash(token)}`;
			const row = await currentVerification(client, identifier);
			const record = row ? parseMagicRecord(row.value) : null;
			if (!row || !record) return { status: "invalid" };
			await clearVerification(client, identifier);
			if (!row.active) return { status: "expired" };
			return authenticate(
				client,
				{ ...record, email: record.email.toLowerCase() },
				request,
				"/magic-link/verify",
				callbacks,
			);
		});
	}

	function verifyOtp(proof: EmailProof, code: string, request: Request) {
		return runAuth(async (client) => {
			const identifier = otpIdentifier(proof.email);
			await lockOtp(client, identifier);
			const row = await currentVerification(client, identifier);
			if (!row) return { status: "invalid" };
			if (!row.active) {
				await clearVerification(client, identifier);
				return { status: "expired" };
			}
			const matched = /^([A-Za-z0-9_-]{43}):([0-3])$/.exec(row.value);
			if (!matched) return { status: "invalid" };
			const [, expected, count] = matched;
			const used = Number(count);
			if (used >= 3) {
				await clearVerification(client, identifier);
				return { status: "attempts" };
			}
			if (!sameHash(expected, hash(code))) {
				await client.query(
					'UPDATE "verification" SET value = $1, "updatedAt" = statement_timestamp() WHERE id = $2',
					[`${expected}:${used + 1}`, row.id],
				);
				return { status: "invalid" };
			}
			await clearVerification(client, identifier);
			return authenticate(client, proof, request, "/sign-in/email-otp");
		});
	}

	return { issueMagic, issueOtp, verifyMagic, verifyOtp };
}
