import {
	createHash,
	randomInt,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import type { PoolClient } from "pg";
import { checkedProjectSchema } from "./validation";

export type ProjectEmailOtpPurpose =
	| "email-verification"
	| "sign-in"
	| "forget-password"
	| "change-email";

export function projectEmailOtpIdentifier(
	purpose: ProjectEmailOtpPurpose,
	email: string,
) {
	return `${purpose}-otp-${email}`;
}

export type ProjectEmailOtpProof =
	| { status: "valid"; id: string; issuedAt: Date }
	| { status: "invalid" | "expired" | "attempts" };

function digest(code: string) {
	return createHash("sha256").update(code).digest("base64url");
}

/** Use the installed realm's native SHA-256 proof rows and three-attempt budget. */
export function createOwnedProjectEmailOtpProof(schemaName: string) {
	const schema = checkedProjectSchema(schemaName);

	async function lock(client: PoolClient, identifier: string) {
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`allauth-email-otp:${schema}:${identifier}`],
		);
	}

	async function replace(
		client: PoolClient,
		identifier: string,
		eligible: boolean,
	) {
		const code = String(randomInt(1_000_000)).padStart(6, "0");
		await lock(client, identifier);
		await client.query(
			`WITH replaced AS (
				DELETE FROM "verification" WHERE identifier = $2 AND $4::boolean
			)
			INSERT INTO "verification" (id, identifier, value, "expiresAt")
			SELECT $1, $2, $3, statement_timestamp() + interval '5 minutes' WHERE $4::boolean`,
			[randomUUID(), identifier, `${digest(code)}:0`, eligible],
		);
		return code;
	}

	function issue(client: PoolClient, identifier: string) {
		return replace(client, identifier, true);
	}

	async function issueIf(
		client: PoolClient,
		identifier: string,
		eligible: boolean,
	) {
		const code = await replace(client, identifier, eligible);
		return eligible ? code : null;
	}

	async function clear(client: PoolClient, identifier: string) {
		await client.query('DELETE FROM "verification" WHERE identifier = $1', [
			identifier,
		]);
	}

	async function verify(
		client: PoolClient,
		identifier: string,
		code: string,
		{ consume, expectedId }: { consume: boolean; expectedId?: string },
	): Promise<ProjectEmailOtpProof> {
		await lock(client, identifier);
		const {
			rows: [row],
		} = await client.query<{
			id: string;
			value: string;
			issuedAt: Date;
			active: boolean;
		}>(
			`SELECT id, value, "createdAt" AS "issuedAt", "expiresAt" > statement_timestamp() AS active
			FROM "verification" WHERE identifier = $1 ORDER BY "createdAt" DESC, id DESC LIMIT 1 FOR UPDATE`,
			[identifier],
		);
		if (!row || (expectedId !== undefined && row.id !== expectedId))
			return { status: "invalid" };
		if (!row.active) {
			await clear(client, identifier);
			return { status: "expired" };
		}
		const proof = /^([A-Za-z0-9_-]{43}):(\d{1,2})$/.exec(row.value);
		if (!proof) return { status: "invalid" };
		const [, expected, attempts] = proof;
		const used = Number(attempts);
		if (used >= 3) {
			await clear(client, identifier);
			return { status: "attempts" };
		}
		const encoder = new TextEncoder();
		if (
			!timingSafeEqual(encoder.encode(expected), encoder.encode(digest(code)))
		) {
			await client.query(
				'UPDATE "verification" SET value = $1, "updatedAt" = statement_timestamp() WHERE id = $2',
				[`${expected}:${used + 1}`, row.id],
			);
			return { status: "invalid" };
		}
		if (consume) await clear(client, identifier);
		return { status: "valid", id: row.id, issuedAt: row.issuedAt };
	}

	return { lock, issue, issueIf, verify };
}
