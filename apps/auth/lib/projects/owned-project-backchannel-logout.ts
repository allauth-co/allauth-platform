import { randomBytes, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import type { Pool, PoolClient } from "pg";
import {
	type LegacyMfaKeys,
	openLegacyMfaRecord,
	sealLegacyMfaRecord,
} from "./legacy-mfa-record";
import { createProjectEngineStore } from "./owned-project-engine-store";
import {
	fetchPublicProjectHttps,
	publicProjectHttpsURL,
} from "./owned-project-https";

const event = "http://schemas.openid.net/event/backchannel-logout";
const tokenLifetimeSeconds = 120;
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
type LogoutTransport = (
	url: URL,
	body: URLSearchParams,
	signal: AbortSignal,
) => Promise<number>;

const postToRelyingParty: LogoutTransport = async (url, body, signal) => {
	const response = await fetchPublicProjectHttps(
		new Request(url, {
			method: "POST",
			body,
			signal,
			headers: { Accept: "application/json" },
		}),
		{ timeoutMs: 5000, headersOnly: true },
	);
	return response.status;
};

export interface ProjectBackchannelTarget {
	clientId: string;
	sessionId: string;
	userId: string;
	url: string;
}

interface BackchannelOptions {
	database: Pool;
	schemaName: string;
	issuer: string;
	keys: LegacyMfaKeys;
	/** Pass an in-process transport in an isolated integration test. */
	post?: LogoutTransport;
	defer?(delivery: () => Promise<void>): void;
	observe?(result: { clientId: string; outcome: "delivered" | "failed" }): void;
}

export function createOwnedProjectBackchannelLogout(
	options: BackchannelOptions,
) {
	const store = createProjectEngineStore(options.database, options.schemaName);

	async function latestKey(client: PoolClient) {
		const { rows } = await client.query<{
			id: string;
			alg: string | null;
			privateKey: string;
		}>(
			`SELECT id, alg, "privateKey" FROM "jwks"
			 WHERE "expiresAt" IS NULL OR "expiresAt" > statement_timestamp()
			 ORDER BY (COALESCE(alg, $1) = $1) DESC, "createdAt" DESC, id DESC LIMIT 1`,
			[algorithm],
		);
		return rows[0];
	}

	async function signingKey() {
		const row = await store.transaction(async (client) => {
			const existing = await latestKey(client);
			if (existing) return existing;
			await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
				`allauth-issuer-key:${options.schemaName}`,
			]);
			const concurrent = await latestKey(client);
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
		});
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

	const post = options.post ?? postToRelyingParty;
	async function deliver(targets: readonly ProjectBackchannelTarget[]) {
		let signing: ReturnType<typeof signingKey> | undefined;
		await Promise.allSettled(
			targets.map(async (target) => {
				let outcome: "delivered" | "failed" = "failed";
				try {
					const url = publicProjectHttpsURL(target.url, true);
					const { id, alg, key } = await (signing ??= signingKey());
					const iat = Math.floor(Date.now() / 1000);
					const token = await new SignJWT({
						sid: target.sessionId,
						events: { [event]: {} },
					})
						.setProtectedHeader({ alg, kid: id, typ: "logout+jwt" })
						.setIssuer(options.issuer)
						.setAudience(target.clientId)
						.setSubject(target.userId)
						.setJti(randomBytes(16).toString("hex"))
						.setIssuedAt(iat)
						.setExpirationTime(iat + tokenLifetimeSeconds)
						.sign(key);
					const status = await post(
						url,
						new URLSearchParams({ logout_token: token }),
						AbortSignal.timeout(5000),
					);
					if (status === 200 || status === 204) outcome = "delivered";
				} finally {
					options.observe?.({ clientId: target.clientId, outcome });
				}
			}),
		);
	}

	return async (targets: readonly ProjectBackchannelTarget[]) => {
		if (!targets.length) return;
		if (!options.defer) {
			await deliver(targets);
			return;
		}
		let pending: Promise<void> | undefined;
		const run = () => (pending ??= deliver(targets));
		try {
			options.defer(run);
		} catch {
			await run();
		}
	};
}
