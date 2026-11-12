import { jwtVerify, SignJWT } from "jose";
import { JWTExpired } from "jose/errors";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { createProjectEngineStore } from "./owned-project-engine-store";

const lifetimeSeconds = 3600;
const legacyClaims = {
	email: z.email().max(320),
	iat: z.number().int().nonnegative(),
	exp: z.number().int().nonnegative(),
};
const claims = z.union([
	z.object(legacyClaims).strict(),
	z
		.object({
			...legacyClaims,
			sub: z.string().min(1).max(160),
			purpose: z.literal("allauth-email-verification"),
		})
		.strict(),
]);

export interface VerifiedEmailAccount {
	id: string;
	email: string;
	twoFactorEnabled: boolean | null;
}

export type CompleteOwnedEmailVerification = (input: {
	/** Use this transaction for credential writes. Do not perform external side effects. */
	client: PoolClient;
	user: VerifiedEmailAccount;
	request: Request;
	callbackURL?: string;
}) => Promise<Response | undefined>;

type VerificationResult =
	| { status: "verified"; response?: Response }
	| { status: "invalid" | "expired" };

export function createOwnedEmailVerification(options: {
	database: Pool;
	schemaName: string;
	signingSecret: string;
	completeVerification?: CompleteOwnedEmailVerification;
}) {
	if (options.signingSecret.length < 32)
		throw new Error("Invalid email-verification configuration.");
	const store = createProjectEngineStore(options.database, options.schemaName);
	const secret = new TextEncoder().encode(options.signingSecret);

	/** The native verifier accepts this HS256 format during an image rollback. */
	function issue(user: Pick<VerifiedEmailAccount, "id" | "email">) {
		const now = Math.floor(Date.now() / 1000);
		return new SignJWT({
			email: user.email.toLowerCase(),
			purpose: "allauth-email-verification",
		})
			.setSubject(user.id)
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt(now)
			.setExpirationTime(now + lifetimeSeconds)
			.sign(secret);
	}

	async function verify(input: {
		token: string;
		request: Request;
		callbackURL?: string;
	}): Promise<VerificationResult> {
		if (input.token.length > 2048) return { status: "invalid" };
		let verified: z.infer<typeof claims>;
		try {
			const { payload } = await jwtVerify(input.token, secret, {
				algorithms: ["HS256"],
				maxTokenAge: lifetimeSeconds,
				requiredClaims: ["iat", "exp"],
			});
			const parsed = claims.safeParse(payload);
			if (
				!parsed.success ||
				parsed.data.exp <= parsed.data.iat ||
				parsed.data.exp - parsed.data.iat > lifetimeSeconds
			)
				return { status: "invalid" };
			verified = parsed.data;
		} catch (error) {
			return { status: error instanceof JWTExpired ? "expired" : "invalid" };
		}
		const subject = "sub" in verified ? verified.sub : null;
		return store.transaction(async (client) => {
			const result = await client.query<
				VerifiedEmailAccount & { emailVerified: boolean }
			>(
				`SELECT id, email, "emailVerified", "twoFactorEnabled" FROM "user"
				WHERE email = $1 AND ($2::text IS NULL OR id = $2)
					AND floor(extract(epoch FROM "createdAt")) <= $3
					AND banned IS DISTINCT FROM true AND "directoryDisabled" IS DISTINCT FROM true
					AND "directoryManaged" IS DISTINCT FROM true AND "isAnonymous" IS DISTINCT FROM true
				FOR UPDATE`,
				[verified.email.toLowerCase(), subject, verified.iat],
			);
			const user = result.rows[0];
			if (!user) return { status: "invalid" };
			if (user.emailVerified) return { status: "verified" };
			await client.query(
				'UPDATE "user" SET "emailVerified" = true, "updatedAt" = statement_timestamp() WHERE id = $1',
				[user.id],
			);
			await store.record(
				client,
				"user.updated",
				"success",
				"/verify-email",
				user.id,
				user.id,
			);
			await store.record(
				client,
				"user.email-verified",
				"success",
				"/verify-email",
				user.id,
				user.id,
			);
			const response = await options.completeVerification?.({
				client,
				user: {
					id: user.id,
					email: user.email,
					twoFactorEnabled: user.twoFactorEnabled,
				},
				request: input.request,
				callbackURL: input.callbackURL,
			});
			return { status: "verified", ...(response ? { response } : {}) };
		});
	}

	return { issue, verify };
}
