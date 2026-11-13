import {
	calculateJwkThumbprint,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import type { PoolClient } from "pg";
import { issuerDpopAlgorithms } from "../issuer-algorithms";
import { issuerDigest, ProjectOAuthError } from "./owned-project-issuer-http";

const privateJwkFields = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const proofLifetime = 300;

function invalidProof(message: string) {
	return new ProjectOAuthError("invalid_dpop_proof", message);
}

function proofURL(value: string) {
	const url = new URL(value);
	if (url.hash || url.username || url.password)
		throw invalidProof("Invalid DPoP target URL.");
	return url.origin + url.pathname;
}

export async function requireIssuerDpop(
	database: PoolClient,
	request: Request,
	endpoint: string,
	options: { required: boolean; expectedJkt?: string; accessToken?: string },
) {
	const proof = request.headers.get("dpop");
	if (!proof) {
		if (options.required || options.expectedJkt)
			throw invalidProof("DPoP proof header is required.");
		return undefined;
	}
	if (proof.length > 8192) throw invalidProof("Invalid DPoP proof.");
	const method = request.method.toUpperCase();
	let jkt: string;
	let replayKey: string;
	let expiresAt: Date;
	try {
		const header = decodeProtectedHeader(proof);
		const jwk = header.jwk;
		if (
			header.typ !== "dpop+jwt" ||
			!header.alg ||
			!issuerDpopAlgorithms.includes(header.alg) ||
			!jwk ||
			!["RSA", "EC", "OKP"].includes(jwk.kty ?? "") ||
			privateJwkFields.some((field) => field in jwk)
		)
			throw invalidProof("Invalid DPoP signing key or algorithm.");
		const { payload } = await jwtVerify(
			proof,
			await importJWK(jwk, header.alg),
			{
				algorithms: issuerDpopAlgorithms,
				typ: "dpop+jwt",
				requiredClaims: ["iat", "jti", "htm", "htu"],
			},
		);
		const now = Math.floor(Date.now() / 1000);
		if (
			typeof payload.iat !== "number" ||
			payload.iat > now + 5 ||
			payload.iat < now - proofLifetime ||
			typeof payload.htm !== "string" ||
			payload.htm.toUpperCase() !== method ||
			typeof payload.htu !== "string" ||
			proofURL(payload.htu) !== endpoint ||
			typeof payload.jti !== "string" ||
			!payload.jti ||
			payload.jti.length > 512
		)
			throw invalidProof("DPoP proof does not match this request.");
		jkt = await calculateJwkThumbprint(jwk, "sha256");
		if (options.expectedJkt && jkt !== options.expectedJkt)
			throw invalidProof("DPoP proof key does not match the bound token.");
		if (
			options.accessToken !== undefined &&
			payload.ath !== issuerDigest(options.accessToken)
		)
			throw invalidProof("DPoP proof does not match the access token.");
		replayKey = issuerDigest([jkt, method, endpoint, payload.jti].join("\n"));
		expiresAt = new Date((payload.iat + proofLifetime) * 1000);
	} catch (error) {
		if (error instanceof ProjectOAuthError) throw error;
		throw invalidProof("Invalid DPoP proof.");
	}
	const identifier = `dpop-proof:${replayKey}`;
	const inserted = await database.query(
		`INSERT INTO "verification" (id, identifier, value, "expiresAt")
		 VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING`,
		[issuerDigest(`reserve:${identifier}`), identifier, replayKey, expiresAt],
	);
	if (!inserted.rowCount)
		throw invalidProof("DPoP proof has already been used.");
	return { jkt };
}
