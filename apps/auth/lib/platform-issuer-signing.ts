import { randomUUID } from "node:crypto";
// cspell:ignore xact
import type { JWK, JWTHeaderParameters, JWTPayload } from "jose";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import type { Pool, PoolClient } from "pg";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, setting } from "./configuration";
import {
	openLegacyMfaRecord,
	sealLegacyMfaRecord,
} from "./projects/legacy-mfa-record";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";

const primaryAlgorithm = "RS256";
const keyLifetimeSeconds = 30 * 86400;

interface PlatformSigningPin {
	signingKeyId?: string;
	signingAlgorithm?: string;
}

interface PlatformSigningRow {
	id: string;
	alg: string | null;
	privateKey: string;
}

interface PlatformSigningKey {
	alg: string;
	kid: string;
	/** The protocol endpoint supplies the audience, lifetime and other claims. */
	sign(
		payload: JWTPayload,
		header?: Pick<JWTHeaderParameters, "typ" | "cty">,
	): Promise<string>;
}

async function findKey(database: Pick<Pool, "query">, pin: PlatformSigningPin) {
	const { rows } = await database.query<PlatformSigningRow>(
		`SELECT id, alg, "privateKey" FROM public."jwks"
		 WHERE ($2::text IS NULL OR id=$2) AND ($3::text IS NULL OR COALESCE(alg,$1)=$3)
		 AND ("expiresAt" IS NULL OR "expiresAt">$4::timestamptz)
		 ORDER BY (COALESCE(alg,$1)=$1) DESC, "createdAt" DESC LIMIT 1`,
		[
			primaryAlgorithm,
			pin.signingKeyId ?? null,
			pin.signingAlgorithm ?? null,
			new Date(),
		],
	);
	return rows[0];
}

/** Resolve root keys for protocol claims while keeping private key material inside the signer. */
export function createPlatformIssuerSigner(options: {
	database: Pool;
	env: AuthEnvironment;
}) {
	const { database, env } = options;
	const issuer = authOrigin(env);
	const fallback = setting(env, "ALLAUTH_AUTH_SECRET");
	if (fallback.length < 32)
		throw new Error("The platform issuer auth secret is unavailable.");
	const { encryptionKeys } = readLegacyProjectKeyring(
		fallback,
		setting(env, "BETTER_AUTH_SECRETS"),
	);

	async function provisionKey(client: PoolClient, pin: PlatformSigningPin) {
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended('allauth:platform-issuer:jwks',0))",
		);
		const concurrent = await findKey(client, pin);
		if (concurrent) return concurrent;
		const pair = await generateKeyPair(primaryAlgorithm, { extractable: true });
		const [publicKey, privateKey] = await Promise.all([
			exportJWK(pair.publicKey),
			exportJWK(pair.privateKey),
		]);
		const created = {
			id: randomUUID(),
			alg: primaryAlgorithm,
			privateKey: JSON.stringify(
				sealLegacyMfaRecord(JSON.stringify(privateKey), encryptionKeys),
			),
		};
		await client.query(
			`INSERT INTO public."jwks" (id, alg, "publicKey", "privateKey", "createdAt", "expiresAt")
			 VALUES ($1,$2,$3,$4,statement_timestamp(),statement_timestamp() + $5::integer * interval '1 second')`,
			[
				created.id,
				created.alg,
				JSON.stringify(publicKey),
				created.privateKey,
				keyLifetimeSeconds,
			],
		);
		return created;
	}

	async function resolveRow(pin: PlatformSigningPin, transaction?: PoolClient) {
		const row = await findKey(transaction ?? database, pin);
		if (row) return row;
		if (
			pin.signingKeyId !== undefined ||
			(pin.signingAlgorithm !== undefined &&
				pin.signingAlgorithm !== primaryAlgorithm)
		)
			throw new Error(
				"The requested platform issuer signing key is unavailable.",
			);
		if (transaction) return provisionKey(transaction, pin);

		const client = await database.connect();
		try {
			await client.query("BEGIN");
			const created = await provisionKey(client, pin);
			await client.query("COMMIT");
			return created;
		} catch {
			await client.query("ROLLBACK").catch(() => {});
			throw new Error("Could not create the platform issuer signing key.");
		} finally {
			client.release();
		}
	}

	/** An existing transaction owns the minted key until it commits. */
	async function resolveSigningKey(
		pin: PlatformSigningPin = {},
		transaction?: PoolClient,
	): Promise<PlatformSigningKey> {
		const row = await resolveRow(pin, transaction);
		const alg = row.alg ?? primaryAlgorithm;
		const kid = row.id;
		let key: CryptoKey;
		try {
			const envelope: unknown = JSON.parse(row.privateKey);
			if (typeof envelope !== "string")
				throw new Error("Invalid key envelope.");
			const jwk = JSON.parse(
				openLegacyMfaRecord(envelope, encryptionKeys),
			) as JWK;
			const imported = await importJWK(jwk, alg);
			if (imported instanceof Uint8Array || imported.type !== "private")
				throw new Error("Expected an asymmetric private key.");
			key = imported;
		} catch {
			throw new Error(
				"Could not read the existing platform issuer signing key.",
			);
		}
		return {
			alg,
			kid,
			sign(payload, header) {
				return new SignJWT(payload)
					.setProtectedHeader({ ...header, alg, kid })
					.setIssuer(issuer)
					.sign(key);
			},
		};
	}

	return { resolveSigningKey };
}
