import type { JSONWebKeySet } from "jose";
import type { Pool } from "pg";
import * as z from "zod";

const gracePeriodSeconds = 7 * 86400;
const requiredString = z.string().min(1);
const metadata = {
	alg: requiredString,
	kid: requiredString,
	crv: z.string().optional(),
	use: z.string().optional(),
	key_ops: z.array(z.string()).optional(),
	ext: z.boolean().optional(),
	x5c: z.array(z.string()).optional(),
	x5t: z.string().optional(),
	"x5t#S256": z.string().optional(),
	x5u: z.string().optional(),
};

const publicJwk = z.discriminatedUnion("kty", [
	z.object({
		...metadata,
		kty: z.literal("RSA"),
		n: requiredString,
		e: requiredString,
	}),
	z.object({
		...metadata,
		kty: z.literal("EC"),
		crv: requiredString,
		x: requiredString,
		y: requiredString,
	}),
	z.object({
		...metadata,
		kty: z.literal("OKP"),
		crv: requiredString,
		x: requiredString,
	}),
	z.object({ ...metadata, kty: z.literal("AKP"), pub: requiredString }),
]);

interface PlatformPublicKeyRow {
	id: string;
	alg: string | null;
	crv: string | null;
	publicKey: string | null;
}

interface PlatformIssuerJwks {
	/** Native bootstraps a key only when the store has no rows. */
	keyStoreEmpty: boolean;
	document: JSONWebKeySet;
}

/** Read the shared issuer's persisted public keys without creating or rotating keys. */
export async function readPlatformIssuerJwks(
	database: Pick<Pool, "query">,
): Promise<PlatformIssuerJwks> {
	const { rows } = await database.query<PlatformPublicKeyRow>(
		`SELECT id, alg, crv, CASE WHEN "expiresAt" IS NULL OR
		 "expiresAt" > statement_timestamp() - $1::integer * interval '1 second'
		 THEN "publicKey" END AS "publicKey" FROM public."jwks"`,
		[gracePeriodSeconds],
	);
	const keys: JSONWebKeySet["keys"] = [];
	for (const row of rows) {
		if (row.publicKey === null) continue;
		try {
			const stored: unknown = JSON.parse(row.publicKey);
			if (!stored || typeof stored !== "object" || Array.isArray(stored))
				throw new Error("Expected a public JWK object.");
			keys.push(
				publicJwk.parse({
					alg: row.alg ?? "RS256",
					...(row.crv === null ? {} : { crv: row.crv }),
					...stored,
					kid: row.id,
				}),
			);
		} catch {
			throw new Error("Invalid stored platform issuer public key.");
		}
	}
	return { keyStoreEmpty: rows.length === 0, document: { keys } };
}
