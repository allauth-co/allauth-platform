import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { checkedProjectSchema } from "./validation";

export interface StoredProjectPasskey {
	id: string;
	name: string | null;
	userId: string;
	credentialID: string;
	/** The legacy column stores standard Base64-encoded COSE public-key bytes. */
	publicKey: string;
	counter: number;
	deviceType: string;
	backedUp: boolean;
	transports: string | null;
	createdAt: Date | null;
	aaguid: string | null;
}

export interface RegisteredProjectPasskey {
	id: string;
	publicKey: Uint8Array;
	counter: number;
	deviceType: "singleDevice" | "multiDevice";
	backedUp: boolean;
	transports?: readonly string[];
	name?: string;
	aaguid?: string;
}

type CheckedCredential = Pick<
	StoredProjectPasskey,
	"id" | "userId" | "credentialID" | "publicKey" | "counter"
>;

const columns =
	'id, name, "userId", "credentialID", "publicKey", counter, "deviceType", "backedUp", transports, "createdAt", aaguid';

function supportedCounter(value: number): boolean {
	return Number.isInteger(value) && value >= 0 && value <= 2_147_483_647;
}

/** PostgreSQL passkey storage for a realm selected by trusted project routing. */
export function projectPasskeyStore(
	database: Pick<Pool, "query" | "connect">,
	schemaName: string,
) {
	const schema = checkedProjectSchema(schemaName);
	const table = `"${schema}"."passkey"`;
	return {
		/** Return no credential when legacy data has more than one matching owner or row. */
		async findCredential(
			credentialId: string,
		): Promise<StoredProjectPasskey | null> {
			const { rows } = await database.query<StoredProjectPasskey>(
				`SELECT ${columns} FROM ${table} WHERE "credentialID" = $1 LIMIT 2`,
				[credentialId],
			);
			return rows.length === 1 ? rows[0]! : null;
		},

		async listForUser(userId: string): Promise<StoredProjectPasskey[]> {
			const { rows } = await database.query<StoredProjectPasskey>(
				`SELECT ${columns} FROM ${table} WHERE "userId" = $1`,
				[userId],
			);
			return rows;
		},

		/** Persist an already verified registration for the authenticated owner. */
		async registerForUser(
			userId: string,
			credential: RegisteredProjectPasskey,
			transaction?: PoolClient,
		): Promise<StoredProjectPasskey | null> {
			if (!supportedCounter(credential.counter))
				throw new Error("Passkey counter is outside the stored range.");
			const key = btoa(
				Array.from(credential.publicKey, (byte) =>
					String.fromCharCode(byte),
				).join(""),
			);
			const client = transaction ?? (await database.connect());
			try {
				if (!transaction)
					await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
				// The legacy schema indexes the credential ID without a uniqueness
				// constraint. AllAuth writers serialize duplicate checks per realm.
				await client.query(
					"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
					[JSON.stringify(["allauth-passkey", schema, credential.id])],
				);
				const { rows } = await client.query<StoredProjectPasskey>(
					`INSERT INTO ${table} (${columns})
					SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, statement_timestamp(), $10
					WHERE NOT EXISTS (SELECT 1 FROM ${table} WHERE "credentialID" = $4)
					RETURNING ${columns}`,
					[
						randomUUID(),
						credential.name?.trim() || null,
						userId,
						credential.id,
						key,
						credential.counter,
						credential.deviceType,
						credential.backedUp,
						credential.transports?.join(",") ?? "",
						credential.aaguid ?? null,
					],
				);
				if (!transaction) await client.query("COMMIT");
				return rows[0] ?? null;
			} catch (error) {
				if (!transaction) await client.query("ROLLBACK");
				throw error;
			} finally {
				if (!transaction) client.release();
			}
		},

		/** Apply a verified assertion only while the credential still matches what was verified. */
		async recordAssertion(
			credential: CheckedCredential,
			nextCounter: number,
			transaction?: PoolClient,
		): Promise<boolean> {
			const priorCounter = credential.counter;
			if (!supportedCounter(priorCounter) || !supportedCounter(nextCounter))
				return false;
			if (
				(priorCounter !== 0 || nextCounter !== 0) &&
				nextCounter <= priorCounter
			)
				return false;
			// Counterless authenticators legitimately remain at zero. Single-use
			// challenge consumption is still required before recording an assertion.
			const result = await (transaction ?? database).query(
				`UPDATE ${table} SET counter = $6
				WHERE id = $1 AND "userId" = $2 AND "credentialID" = $3 AND "publicKey" = $4 AND counter = $5`,
				[
					credential.id,
					credential.userId,
					credential.credentialID,
					credential.publicKey,
					priorCounter,
					nextCounter,
				],
			);
			return result.rowCount === 1;
		},

		async renameForUser(
			userId: string,
			id: string,
			name: string,
			transaction?: PoolClient,
		): Promise<StoredProjectPasskey | null> {
			const trimmed = name.trim();
			if (!trimmed) throw new Error("A passkey name is required.");
			const { rows } = await (
				transaction ?? database
			).query<StoredProjectPasskey>(
				`UPDATE ${table} SET name = $3 WHERE id = $1 AND "userId" = $2 RETURNING ${columns}`,
				[id, userId, trimmed],
			);
			return rows[0] ?? null;
		},

		async removeForUser(
			userId: string,
			id: string,
			transaction?: PoolClient,
		): Promise<boolean> {
			const result = await (transaction ?? database).query(
				`DELETE FROM ${table} WHERE id = $1 AND "userId" = $2`,
				[id, userId],
			);
			return result.rowCount === 1;
		},
	};
}
