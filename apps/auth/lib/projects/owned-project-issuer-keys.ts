import { randomUUID } from "node:crypto";
import type { JSONWebKeySet, JWK } from "jose";
import { exportJWK, generateKeyPair, importJWK } from "jose";
import type { Pool, PoolClient } from "pg";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { openLegacyMfaRecord, sealLegacyMfaRecord } from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";

const keyLifetimeSeconds = 30 * 86400;
const algorithm = "RS256";
const signingAlgorithms = new Set([
	algorithm,
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
	"ES256",
	"ES384",
	"ES512",
	"EdDSA",
	"Ed25519",
	"ML-DSA-44",
	"ML-DSA-65",
	"ML-DSA-87",
]);
const gracePeriodSeconds = 7 * 86400;

interface IssuerKeyOptions {
	database: Pool;
	schemaName: string;
	keys: LegacyMfaKeys;
}

interface PublicKeyRow {
	id: string;
	alg: string | null;
	crv: string | null;
	publicKey: string;
}

/** Select only public fields even if a stored JWK has other attributes. */
function publicKey(row: PublicKeyRow): JWK {
	const value = JSON.parse(row.publicKey) as JWK;
	const base = { kid: row.id, alg: value.alg ?? row.alg ?? algorithm };
	if (value.kty === "RSA" && value.n && value.e)
		return { ...base, kty: value.kty, n: value.n, e: value.e };
	const crv = value.crv ?? row.crv;
	if (value.kty === "EC" && crv && value.x && value.y)
		return { ...base, kty: value.kty, crv, x: value.x, y: value.y };
	if (value.kty === "OKP" && crv && value.x)
		return { ...base, kty: value.kty, crv, x: value.x };
	if (value.kty === "AKP" && typeof value.pub === "string")
		return { ...base, kty: value.kty, pub: value.pub };
	throw new Error("Invalid stored issuer public key.");
}

export interface IssuerSigningPin {
	alg?: string;
	kid?: string;
}

export function createOwnedProjectIssuerKeys(options: IssuerKeyOptions) {
	const store = createProjectEngineStore(options.database, options.schemaName);
	async function latestKey(client: PoolClient, pin: IssuerSigningPin) {
		const { rows } = await client.query<{
			id: string;
			alg: string | null;
			privateKey: string;
		}>(
			`SELECT id, alg, "privateKey" FROM "jwks"
			 WHERE ("expiresAt" IS NULL OR "expiresAt" > statement_timestamp())
			 AND ($2::text IS NULL OR COALESCE(alg, $1) = $2)
			 AND ($3::text IS NULL OR id = $3)
			 ORDER BY (COALESCE(alg, $1) = $1) DESC, "createdAt" DESC, id DESC LIMIT 1`,
			[algorithm, pin.alg ?? null, pin.kid ?? null],
		);
		return rows[0];
	}

	async function currentKey(client: PoolClient, pin: IssuerSigningPin = {}) {
		const existing = await latestKey(client, pin);
		if (existing) return existing;
		if (pin.kid || (pin.alg && pin.alg !== algorithm))
			throw new Error("The configured issuer signing key is unavailable.");
		await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
			`allauth-issuer-key:${options.schemaName}`,
		]);
		const concurrent = await latestKey(client, pin);
		if (concurrent) return concurrent;
		const pair = await generateKeyPair(algorithm, { extractable: true });
		const [privateKey, publicKey] = await Promise.all([
			exportJWK(pair.privateKey),
			exportJWK(pair.publicKey),
		]);
		const inserted = {
			id: randomUUID(),
			alg: algorithm,
			privateKey: JSON.stringify(
				sealLegacyMfaRecord(JSON.stringify(privateKey), options.keys),
			),
		};
		await client.query(
			`INSERT INTO "jwks" (id, alg, "privateKey", "publicKey", "createdAt", "expiresAt")
				 VALUES ($1, $2, $3, $4, statement_timestamp(),
				   statement_timestamp() + $5::integer * interval '1 second')`,
			[
				inserted.id,
				inserted.alg,
				inserted.privateKey,
				JSON.stringify(publicKey),
				keyLifetimeSeconds,
			],
		);
		return inserted;
	}

	async function signingKey(client?: PoolClient, pin?: IssuerSigningPin) {
		const row = client
			? await currentKey(client, pin)
			: await store.transaction((connection) => currentKey(connection, pin));
		const alg = row.alg ?? algorithm;
		if (!signingAlgorithms.has(alg))
			throw new Error("Invalid existing issuer signing algorithm.");
		const sealed: unknown = JSON.parse(row.privateKey);
		if (typeof sealed !== "string")
			throw new Error("Invalid existing issuer key envelope.");
		const jwk = JSON.parse(openLegacyMfaRecord(sealed, options.keys)) as JWK;
		const key = await importJWK(jwk, alg);
		return { id: row.id, alg, key };
	}

	async function listPublicRows(client: PoolClient) {
		const result = await client.query<PublicKeyRow & { publish: boolean }>(
			`SELECT id, alg, crv, "publicKey", ("expiresAt" IS NULL OR
			  "expiresAt" > statement_timestamp() - $1::integer * interval '1 second') AS publish FROM "jwks"`,
			[gracePeriodSeconds],
		);
		return result.rows;
	}

	function publish(
		rows: Awaited<ReturnType<typeof listPublicRows>>,
	): JSONWebKeySet {
		return { keys: rows.filter((row) => row.publish).map(publicKey) };
	}

	async function existingPublicKeys(
		client: PoolClient,
	): Promise<JSONWebKeySet> {
		return publish(await listPublicRows(client));
	}

	async function publicKeys(): Promise<JSONWebKeySet> {
		let rows = await store.transaction(listPublicRows);
		if (!rows.length) {
			await store.transaction((client) => currentKey(client));
			rows = await store.transaction(listPublicRows);
		}
		return publish(rows);
	}

	return { signingKey, publicKeys, existingPublicKeys };
}
