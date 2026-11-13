import { timingSafeEqual } from "node:crypto";
import type { PoolClient } from "pg";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord, sealLegacyMfaRecord } from "./legacy-mfa-record";
import { checkedProjectSchema } from "./validation";

interface EnrolmentRow {
	id: string;
	backupCodes: string;
}

/**
 * Consume a code for the subject of an already validated project MFA challenge.
 * The caller uses the same transaction for the challenge and any new session.
 * This storage operation never creates or authenticates a session on its own.
 */
export async function consumeProjectRecoveryCode(
	database: PoolClient,
	input: {
		schemaName: string;
		userId: string;
		code: string;
		keys: LegacyMfaKeys;
	},
): Promise<"consumed" | "invalid" | "conflict"> {
	const schema =
		input.schemaName === "public"
			? "public"
			: checkedProjectSchema(input.schemaName);
	if (!input.code || input.code.length > 128) return "invalid";
	// Serialize with account deprovisioning and hold the lock through session issuance.
	const owner = await database.query(
		`SELECT id FROM "${schema}"."user" WHERE id = $1 AND "twoFactorEnabled" = TRUE
			AND COALESCE(banned, FALSE) = FALSE AND COALESCE("directoryDisabled", FALSE) = FALSE
		FOR UPDATE`,
		[input.userId],
	);
	if (owner.rowCount !== 1) return "invalid";

	const result = await database.query<EnrolmentRow>(
		`SELECT f.id, f."backupCodes" FROM "${schema}"."twoFactor" AS f
		JOIN "${schema}"."user" AS u ON u.id = f."userId"
		WHERE f."userId" = $1 AND f.verified IS DISTINCT FROM FALSE
			AND u."twoFactorEnabled" = TRUE AND COALESCE(u.banned, FALSE) = FALSE
			AND COALESCE(u."directoryDisabled", FALSE) = FALSE
			AND (f."lockedUntil" IS NULL OR f."lockedUntil" <= statement_timestamp())
		LIMIT 2`,
		[input.userId],
	);
	if (result.rows.length !== 1) return "invalid";
	const record = result.rows[0]!;
	const plaintext = openLegacyMfaRecord(record.backupCodes, input.keys);
	let codes: unknown;
	try {
		codes = JSON.parse(plaintext);
	} catch {
		throw new Error("Could not read the existing recovery codes.");
	}
	if (
		!Array.isArray(codes) ||
		!codes.every((code: unknown): code is string => typeof code === "string")
	) {
		throw new Error("Could not read the existing recovery codes.");
	}
	const encoder = new TextEncoder();
	const presented = encoder.encode(input.code);
	const remaining = codes.filter((code) => {
		const expected = encoder.encode(code);
		return (
			expected.length !== presented.length ||
			!timingSafeEqual(expected, presented)
		);
	});
	if (remaining.length === codes.length) return "invalid";

	const updated = await database.query(
		`UPDATE "${schema}"."twoFactor" AS f SET "backupCodes" = $1
		FROM "${schema}"."user" AS u
		WHERE f.id = $2 AND f."userId" = $3 AND f."backupCodes" = $4
			AND u.id = f."userId" AND f.verified IS DISTINCT FROM FALSE
			AND u."twoFactorEnabled" = TRUE AND COALESCE(u.banned, FALSE) = FALSE
			AND COALESCE(u."directoryDisabled", FALSE) = FALSE
			AND (f."lockedUntil" IS NULL OR f."lockedUntil" <= statement_timestamp())`,
		[
			sealLegacyMfaRecord(JSON.stringify(remaining), input.keys),
			record.id,
			input.userId,
			record.backupCodes,
		],
	);
	return updated.rowCount === 1 ? "consumed" : "conflict";
}
