// cspell:ignore CBOR
import {
	createHash,
	generateKeyPairSync,
	randomBytes,
	sign,
} from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const hash = (value: string | Uint8Array) =>
	createHash("sha256").update(value).digest();

export function virtualCredential(origin: string) {
	const rpId = new URL(origin).hostname;
	const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const point = pair.publicKey.export({ format: "jwk" });
	const key = isoCBOR.encode(
		new Map<number, number | Uint8Array>([
			[1, 2],
			[3, -7],
			[-1, 1],
			[-2, Buffer.from(point.x!, "base64url")],
			[-3, Buffer.from(point.y!, "base64url")],
		]),
	);
	const id = randomBytes(32);
	const encodedId = id.toString("base64url");
	const credential = {
		id: encodedId,
		rawId: encodedId,
		type: "public-key" as const,
		clientExtensionResults: {},
	};
	return {
		id: encodedId,
		registration(challenge: string) {
			const client = Buffer.from(
				JSON.stringify({ type: "webauthn.create", challenge, origin }),
			);
			const idSize = Buffer.alloc(2);
			idSize.writeUInt16BE(id.length);
			const authData = Buffer.concat([
				hash(rpId),
				Buffer.from([0x45]),
				Buffer.alloc(4),
				Buffer.alloc(16),
				idSize,
				id,
				key,
			]);
			const attestation = isoCBOR.encode(
				new Map<string, string | Uint8Array | Map<string, never>>([
					["fmt", "none"],
					["attStmt", new Map<string, never>()],
					["authData", authData],
				]),
			);
			return {
				...credential,
				response: {
					clientDataJSON: client.toString("base64url"),
					attestationObject: Buffer.from(attestation).toString("base64url"),
					transports: ["internal" as const],
				},
			};
		},
		assertion(
			challenge: string,
			count: number,
			clientOrigin = origin,
			relyingParty = rpId,
		) {
			const client = Buffer.from(
				JSON.stringify({
					type: "webauthn.get",
					challenge,
					origin: clientOrigin,
				}),
			);
			const counter = Buffer.alloc(4);
			counter.writeUInt32BE(count);
			const authData = Buffer.concat([
				hash(relyingParty),
				Buffer.from([0x05]),
				counter,
			]);
			const signature = sign(
				"sha256",
				Buffer.concat([authData, hash(client)]),
				pair.privateKey,
			);
			return {
				...credential,
				response: {
					clientDataJSON: client.toString("base64url"),
					authenticatorData: authData.toString("base64url"),
					signature: signature.toString("base64url"),
				},
			};
		},
	};
}
