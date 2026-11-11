import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { passkey } from ".";

const webOrigin = "https://nativeapp.example", rpId = "nativeapp.example";
const androidOrigin = `android:apk-key-hash:${Buffer.alloc(32, 0x11).toString("base64url")}`;
const digest = (value: string | Uint8Array) => createHash("sha256").update(value).digest();
const credentialId = () => randomBytes(32);
function key() {
	const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const jwk = pair.publicKey.export({ format: "jwk" });
	const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
	return { ...pair, cose, id: credentialId() };
}
function attestation(credential: ReturnType<typeof key>, challenge: string, origin = androidOrigin, verified = true) {
	const data = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin })); const length = Buffer.alloc(2); length.writeUInt16BE(credential.id.length);
	const auth = Buffer.concat([digest(rpId), Buffer.from([verified ? 0x45 : 0x41]), Buffer.alloc(4), Buffer.alloc(16), length, credential.id, credential.cose]);
	const signature = sign("sha256", Buffer.concat([auth, digest(data)]), credential.privateKey);
	const object = isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, number | Uint8Array>>([["fmt", "packed"], ["authData", auth], ["attStmt", new Map<string, number | Uint8Array>([["alg", -7], ["sig", signature]])]]));
	return { id: credential.id.toString("base64url"), rawId: credential.id.toString("base64url"), type: "public-key" as const, response: { clientDataJSON: data.toString("base64url"), attestationObject: Buffer.from(object).toString("base64url"), transports: ["internal"] }, clientExtensionResults: {} };
}
function assertion(credential: ReturnType<typeof key>, challenge: string, options: { origin?: string; verified?: boolean; rp?: string; counter?: number; corruptSignature?: boolean } = {}) {
	const data = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: options.origin ?? androidOrigin })); const counter = Buffer.alloc(4); counter.writeUInt32BE(options.counter ?? 1);
	const auth = Buffer.concat([digest(options.rp ?? rpId), Buffer.from([options.verified === false ? 0x01 : 0x05]), counter]);
	const signature = sign("sha256", Buffer.concat([auth, digest(data)]), credential.privateKey); if (options.corruptSignature) signature[signature.length - 1] = signature[signature.length - 1]! ^ 0x01;
	return { id: credential.id.toString("base64url"), rawId: credential.id.toString("base64url"), type: "public-key" as const, response: { clientDataJSON: data.toString("base64url"), authenticatorData: auth.toString("base64url"), signature: signature.toString("base64url") }, clientExtensionResults: {} };
}
async function instance() {
	const state = await getTestInstance({ baseURL: webOrigin, logger: { disabled: true }, trustedOrigins: [webOrigin], plugins: [passkey({ rpID: rpId, origin: [webOrigin, androidOrigin], requireUserVerification: true, authenticatorSelection: { residentKey: "required", requireResidentKey: true } })] });
	const login = await state.auth.api.signInEmail({ body: { email: state.testUser.email, password: state.testUser.password }, asResponse: true });
	expect(login.status).toBe(200);
	const headers = new Headers({ origin: webOrigin, cookie: login.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ") });
	const call = async (path: string, body?: unknown, cookies = headers.get("cookie") || "") => {
		const response = await state.auth.handler(new Request(`${webOrigin}/api/auth/passkey/${path}`, { method: body === undefined ? "GET" : "POST", headers: { origin: webOrigin, cookie: cookies, ...(body === undefined ? {} : { "content-type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
		const changed = response.headers.getSetCookie().map(value => value.split(";", 1)[0]).join("; ");
		return { response, cookie: [cookies, changed].filter(Boolean).join("; ") };
	};
	return { state, call };
}
async function registered(origin = androidOrigin) {
	const current = await instance(), credential = key(); const options = await current.call("generate-register-options"); const publicKey = await options.response.json();
	expect(options.response.status, JSON.stringify(publicKey)).toBe(200);
	expect(publicKey.authenticatorSelection).toMatchObject({ userVerification: "required", residentKey: "required" });
	const result = await current.call("verify-registration", { response: attestation(credential, publicKey.challenge, origin) }, options.cookie); expect(result.response.status).toBe(200);
	return { ...current, credential };
}

/** @see https://developer.android.com/identity/passkeys/create-passkeys#verify-and-save-public-key */
describe("native passkey cryptographic boundaries", () => {
	it("accepts the exact associated iOS/web RP origin with genuine signed UV", async () => {
		const current = await registered(webOrigin); const options = await current.call("generate-authenticate-options", undefined, ""); const publicKey = await options.response.json();
		expect((await current.call("verify-authentication", { response: assertion(current.credential, publicKey.challenge, { origin: webOrigin }) }, options.cookie)).response.status).toBe(200);
	});
	it("verifies real self-attestation and signed Android assertions with UV, then consumes the challenge once", async () => {
		const current = await registered(); const options = await current.call("generate-authenticate-options", undefined, ""); const publicKey = await options.response.json(); expect(publicKey.userVerification).toBe("required");
		const body = { response: assertion(current.credential, publicKey.challenge) }; const accepted = await current.call("verify-authentication", body, options.cookie); expect(accepted.response.status).toBe(200); expect((await accepted.response.json()).session).toBeDefined();
		expect((await current.call("verify-authentication", body, options.cookie)).response.status).not.toBe(200);
	});
	it.each(["https://evil.example", `android:apk-key-hash:${Buffer.alloc(32, 0x22).toString("base64url")}`])("rejects otherwise genuinely signed assertions from unapproved origin %s", async origin => {
		const current = await registered(); const options = await current.call("generate-authenticate-options", undefined, ""); const publicKey = await options.response.json();
		expect((await current.call("verify-authentication", { response: assertion(current.credential, publicKey.challenge, { origin }) }, options.cookie)).response.status).not.toBe(200);
	});
	it.each([{ verified: false }, { rp: "another.example" }, { corruptSignature: true }])("rejects signed authentication without UV, wrong RP or invalid signature %j", async change => {
		const current = await registered(); const options = await current.call("generate-authenticate-options", undefined, ""); const publicKey = await options.response.json();
		expect((await current.call("verify-authentication", { response: assertion(current.credential, publicKey.challenge, change) }, options.cookie)).response.status).not.toBe(200);
	});
	it("rejects a signed assertion for a different challenge and a credential from another isolated tenant", async () => {
		const first = await registered(), other = await instance(); const options = await first.call("generate-authenticate-options", undefined, ""); const publicKey = await options.response.json();
		expect((await first.call("verify-authentication", { response: assertion(first.credential, "wrong-challenge") }, options.cookie)).response.status).not.toBe(200);
		const foreign = await other.call("generate-authenticate-options", undefined, ""); const foreignKey = await foreign.response.json(); expect((await other.call("verify-authentication", { response: assertion(first.credential, foreignKey.challenge) }, foreign.cookie)).response.status).not.toBe(200);
		expect(publicKey.challenge).not.toBe(foreignKey.challenge);
	});
	it.each([{ verified: false }, { origin: "https://evil.example" }, { origin: `android:apk-key-hash:${Buffer.alloc(32, 0x33).toString("base64url")}` }])("rejects real signed registration without required UV or approved origin %j", async change => {
		const current = await instance(), credential = key(); const options = await current.call("generate-register-options"); const publicKey = await options.response.json();
		expect(options.response.status).toBe(200); expect(publicKey.challenge).toBeTypeOf("string");
		expect((await current.call("verify-registration", { response: attestation(credential, publicKey.challenge, change.origin ?? androidOrigin, change.verified !== false) }, options.cookie)).response.status).not.toBe(200);
		expect(await (await current.state.auth.$context).adapter.findMany({ model: "passkey" })).toHaveLength(0);
	});
});
