import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { passkey } from "@better-auth/passkey";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { getTestInstance } from "better-auth/test";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { postgresDatabase } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { projectPasskeyStore } from "./passkey-store";
import type { StoredProjectPasskey } from "./passkey-store";
import { projectPasskeyVerification } from "./passkey-verification";
import type { ProjectPasskeyChallenge } from "./passkey-verification";
import { checkedProjectSchema } from "./validation";

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
const origin = "https://passkey-storage.fixture.example";
const rpId = new URL(origin).hostname;
const projectSlug = "passkey-fixture";
const primary = checkedProjectSchema(`allauth_project_${randomUUID().replaceAll("-", "")}`);
const other = checkedProjectSchema(`allauth_project_${randomUUID().replaceAll("-", "")}`);
const ownerEmail = "owner@passkey-storage.fixture.example";
const foreignEmail = "other@passkey-storage.fixture.example";
const publicKey = new Uint8Array([0xfb, 0xff, 0x04, 0x00, 0x99]);
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest();

function virtualCredential() {
	const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const point = pair.publicKey.export({ format: "jwk" });
	const key = isoCBOR.encode(new Map<number, number | Uint8Array>([
		[1, 2], [3, -7], [-1, 1],
		[-2, Buffer.from(point.x!, "base64url")],
		[-3, Buffer.from(point.y!, "base64url")],
	]));
	const id = randomBytes(32);
	const encodedId = id.toString("base64url");
	const credential = {
		id: encodedId, rawId: encodedId, type: "public-key" as const,
		clientExtensionResults: {},
	};
	return {
		id: encodedId,
		registration(challenge: string) {
			const client = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin }));
			const idSize = Buffer.alloc(2);
			idSize.writeUInt16BE(id.length);
			const authData = Buffer.concat([
				hash(rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idSize, id, key,
			]);
			const attestation = isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, never>>([
				["fmt", "none"], ["attStmt", new Map<string, never>()], ["authData", authData],
			]));
			return {
				...credential,
				response: {
					clientDataJSON: client.toString("base64url"),
					attestationObject: Buffer.from(attestation).toString("base64url"),
					transports: ["internal" as const],
				},
			};
		},
		assertion(challenge: string, count: number, clientOrigin = origin, relyingParty = rpId) {
			const client = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: clientOrigin }));
			const counter = Buffer.alloc(4);
			counter.writeUInt32BE(count);
			const authData = Buffer.concat([hash(relyingParty), Buffer.from([0x05]), counter]);
			const signature = sign("sha256", Buffer.concat([authData, hash(client)]), pair.privateKey);
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

function legacyFixture(database: ReturnType<typeof postgresDatabase>) {
	return getTestInstance({
		database,
		baseURL: origin,
		advanced: { cookiePrefix: `allauth_project_${projectSlug}` },
		logger: { disabled: true },
		plugins: [passkey({ rpID: rpId, origin, requireUserVerification: true })],
	}, { disableTestUser: true });
}

/** @see https://www.w3.org/TR/webauthn-3/#sctn-sign-counter */
describe.skipIf(!existsSync(fixturePath))("project passkey PostgreSQL interoperability", () => {
	let pool: Pool | undefined;
	let nativePool: Pool | undefined;
	let nativeDatabase: ReturnType<typeof postgresDatabase> | undefined;
	let legacy: Awaited<ReturnType<typeof legacyFixture>>;
	let store: ReturnType<typeof projectPasskeyStore>;
	let otherStore: ReturnType<typeof projectPasskeyStore>;
	let ownerId: string;
	let foreignId: string;
	let headers: Headers;

	async function legacyCall(path: string, cookie: string, body?: object) {
		return legacy.auth.handler(new Request(`${origin}/api/auth/passkey/${path}`, {
			method: body ? "POST" : "GET",
			headers: { cookie, origin, ...(body ? { "content-type": "application/json" } : {}) },
			body: body ? JSON.stringify(body) : undefined,
		}));
	}

	async function challenge(kind: "register" | "authenticate", sessionCookie = "") {
		const response = await legacyCall(`generate-${kind}-options`, sessionCookie);
		expect(response.status).toBe(200);
		const options = await response.json() as { challenge: string };
		const cookie = response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
		const context = await legacy.auth.$context;
		const token = readLegacySessionCookie(
			new Headers({ cookie }),
			context.createAuthCookie("better-auth-passkey").name,
			context.secret,
		);
		expect(token).not.toBeNull();
		return { challenge: options.challenge, token: token!, cookie };
	}

	function verificationService() {
		return projectPasskeyVerification(store, {
			rpId, origins: [origin], requireUserVerification: true,
			consumeChallenge: async (token) => {
				const context = await legacy.auth.$context;
				const stored = await context.internalAdapter.consumeVerificationValue(token);
				return stored ? JSON.parse(stored.value) as ProjectPasskeyChallenge : null;
			},
		});
	}

	it("interoperates on in-flight HTTP ceremonies and issues a legacy-readable session", async () => {
		const { secret } = await legacy.auth.$context;
		const owner = createOwnedProjectEngine({
			database: pool!, project: { slug: projectSlug, schemaName: primary },
			baseURL: origin, basePath: "/api/auth", trustedOrigins: [], signingSecret: secret,
			policy: defaultAuthPolicy, trustedIP: () => "192.0.2.19",
			passkeys: { id: rpId, name: "Passkey fixture", origins: [origin], requireUserVerification: true },
		});
		const existing = headers.get("cookie")!;
		const cookieFrom = (response: Response) => response.headers.getSetCookie()
			.filter((value) => !value.includes("Max-Age=0")).map((value) => value.split(";", 1)[0]).join("; ");
		function call(path: string, cookie = "", body?: unknown) {
			return owner.dispatch(new Request(`${origin}/api/auth/${path}`, {
				method: body ? "POST" : "GET",
				headers: { origin, cookie, ...(body ? { "content-type": "application/json" } : {}) },
				body: body ? JSON.stringify(body) : undefined,
			}));
		}

		const issuedByLegacy = await challenge("register", existing);
		const credential = virtualCredential();
		const enrolled = await call("passkey/verify-registration", `${existing}; ${issuedByLegacy.cookie}`, {
			response: credential.registration(issuedByLegacy.challenge), name: "Existing credential",
		});
		expect(enrolled.status).toBe(200);
		const enrolledBody = await enrolled.json() as StoredProjectPasskey;
		expect(enrolledBody.credentialID).toBe(credential.id);
		const issuedByOwned = await call("passkey/generate-register-options", existing);
		expect(issuedByOwned.status).toBe(200);
		const otherCredential = virtualCredential();
		const ownedChallenge = await issuedByOwned.json() as { challenge: string };
		const legacyRegistered = await legacyCall("verify-registration", `${existing}; ${cookieFrom(issuedByOwned)}`, {
			response: otherCredential.registration(ownedChallenge.challenge),
		});
		expect(legacyRegistered.status).toBe(200);
		const rollbackRegistration = await legacyRegistered.json() as StoredProjectPasskey;

		const pending = await challenge("authenticate");
		const assertion = { response: credential.assertion(pending.challenge, 1) };
		const signedIn = await call("passkey/verify-authentication", pending.cookie, assertion);
		expect(signedIn.status).toBe(200);
		const session = await signedIn.json() as { session: { id: string; userId: string }; user: { id: string } };
		expect(session).toMatchObject({ user: { id: ownerId }, session: { userId: ownerId } });
		expect(session.session).not.toHaveProperty("token");
		expect(await legacy.auth.api.getSession({ headers: new Headers({ cookie: cookieFrom(signedIn) }) }))
			.toMatchObject({ user: { id: ownerId }, session: { id: session.session.id } });
		const replay = await call("passkey/verify-authentication", pending.cookie, assertion);
		expect(replay.status).toBe(400);
		const rollbackOptions = await call("passkey/generate-authenticate-options");
		const rollbackChallenge = await rollbackOptions.json() as { challenge: string };
		const rolledBack = await legacyCall("verify-authentication", cookieFrom(rollbackOptions), {
			response: credential.assertion(rollbackChallenge.challenge, 2),
		});
		expect(rolledBack.status).toBe(200);
		expect((await store.findCredential(credential.id))?.counter).toBe(2);

		const renamed = await call("passkey/update-passkey", existing, { id: enrolledBody.id, name: "Updated" });
		expect(await renamed.json()).toMatchObject({ passkey: { id: enrolledBody.id, name: "Updated" } });
		expect(await (await call("passkey/list-user-passkeys", existing)).json()).toEqual(expect.arrayContaining([
			expect.objectContaining({ id: enrolledBody.id, name: "Updated" }),
		]));
		expect(await (await call("passkey/delete-passkey", existing, { id: enrolledBody.id })).json()).toEqual({ status: true });
		expect(await store.removeForUser(ownerId, rollbackRegistration.id)).toBe(true);
	});

	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
			readFileSync(fixturePath, "utf8"),
		);
		const url = new URL(fixture.DATABASE_URL);
		if (
			fixture.container !== "allauth-production-test-20261007" ||
			url.hostname !== "127.0.0.1" ||
			url.port !== "55445"
		) throw new Error("Passkey interoperability requires the isolated PostgreSQL fixture.");
		pool = new Pool({ connectionString: fixture.DATABASE_URL, max: 4 });
		const migrations = ["001-initial-auth.sql", "002-control-plane.sql", "005-free-plugins.sql"].map((name) =>
			readFileSync(new URL(`../../migrations/${name}`, import.meta.url), "utf8"));

		for (const schema of [primary, other]) {
			await pool.query(`CREATE SCHEMA "${schema}"`);
			const setup = await pool.connect();
			try {
				await setup.query("BEGIN");
				await setup.query(`SET LOCAL search_path TO "${schema}"`);
				for (const migration of migrations) await setup.query(migration);
				await setup.query("COMMIT");
			} catch (error) {
				await setup.query("ROLLBACK");
				throw error;
			} finally {
				setup.release();
			}
		}
		nativePool = new Pool({
			connectionString: fixture.DATABASE_URL,
			max: 2,
			options: `-c search_path=${primary}`,
		});
		nativeDatabase = postgresDatabase(nativePool);
		legacy = await legacyFixture(nativeDatabase);
		const password = "synthetic-passkey-fixture-password";
		const owner = await legacy.auth.api.signUpEmail({ body: { name: "Owner", email: ownerEmail, password } });
		const foreign = await legacy.auth.api.signUpEmail({ body: { name: "Other", email: foreignEmail, password } });
		ownerId = owner.user.id;
		foreignId = foreign.user.id;
		await pool.query(`UPDATE "${primary}"."user" SET "emailVerified" = TRUE WHERE id = ANY($1::text[])`, [[ownerId, foreignId]]);
		const signedIn = await legacy.auth.api.signInEmail({
			body: { email: ownerEmail, password },
			asResponse: true,
		});
		expect(signedIn.status).toBe(200);
		headers = new Headers({
			origin,
			cookie: signedIn.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; "),
		});
		store = projectPasskeyStore(pool, primary);
		otherStore = projectPasskeyStore(pool, other);
	}, 30_000);

	afterAll(async () => {
		try {
			if (nativeDatabase) await nativeDatabase.db.destroy();
			else await nativePool?.end();
			if (pool) {
				for (const schema of [primary, other]) {
					await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				}
			}
		} finally {
			await pool?.end();
		}
	});

	it("reads the exact native row format and preserves owner-scoped rename and delete", async () => {
		const adapter = (await legacy.auth.$context).adapter;
		const created = await adapter.create<Omit<StoredProjectPasskey, "id">, StoredProjectPasskey>({
			model: "passkey",
			data: {
				userId: ownerId, name: "Legacy registration", credentialID: "legacy-credential",
				publicKey: "+/8EAJk=", counter: 3, deviceType: "singleDevice", backedUp: false,
				transports: "internal,usb", createdAt: new Date(), aaguid: null,
			},
		});
		expect(await store.findCredential(created.credentialID)).toEqual(created);
		expect(await otherStore.findCredential(created.credentialID)).toBeNull();
		expect(await store.listForUser(foreignId)).toEqual([]);
		expect(await store.renameForUser(foreignId, created.id, "Wrong owner")).toBeNull();
		expect(await store.removeForUser(foreignId, created.id)).toBe(false);
		expect(await store.renameForUser(ownerId, created.id, " New name ")).toMatchObject({
			name: "New name", publicKey: created.publicKey,
		});
		const nativeList = await legacy.auth.api.listPasskeys({ headers });
		expect(nativeList).toContainEqual(expect.objectContaining({
			id: created.id, name: "New name", transports: "internal,usb", counter: 3,
		}));
		expect(await store.removeForUser(ownerId, created.id)).toBe(true);
		expect(await legacy.auth.api.listPasskeys({ headers })).toEqual([]);
	});

	it("writes rollback-readable rows and serializes duplicate registration within the realm", async () => {
		const credential = {
			id: "shared-registration", publicKey, counter: 0, deviceType: "multiDevice" as const,
			backedUp: true, transports: ["internal", "hybrid"], name: "Synced key",
		};
		const outcomes = await Promise.all([
			store.registerForUser(ownerId, credential),
			store.registerForUser(foreignId, credential),
		]);
		const winners = outcomes.filter((value) => value !== null);
		expect(winners).toHaveLength(1);
		const winner = winners[0]!;
		expect(winner).toMatchObject({
			credentialID: credential.id, publicKey: "+/8EAJk=", counter: 0, deviceType: "multiDevice",
			transports: "internal,hybrid", backedUp: true,
		});
		const adapter = (await legacy.auth.$context).adapter;
		expect(await adapter.findOne({
			model: "passkey",
			where: [{ field: "id", value: winner.id }],
		})).toEqual(winner);
		expect(await otherStore.findCredential(credential.id)).toBeNull();
	});

	it("records only current counters and permits counterless authenticators to stay at zero", async () => {
		const registered = await store.registerForUser(ownerId, {
			id: "counter-credential", publicKey, counter: 0, deviceType: "multiDevice", backedUp: true,
		});
		expect(registered).not.toBeNull();
		expect(await store.recordAssertion(registered!, 0)).toBe(true);
		const counters = await Promise.all([
			store.recordAssertion(registered!, 1),
			store.recordAssertion(registered!, 2),
		]);
		expect(counters.filter(Boolean)).toHaveLength(1);
		const current = await store.findCredential(registered!.credentialID);
		expect(current?.counter).toBe(counters[0] ? 1 : 2);
		expect(await store.recordAssertion(registered!, 3)).toBe(false);
		expect(await store.recordAssertion(current!, 0)).toBe(false);
		expect(await store.recordAssertion({ ...current!, publicKey: "wrong-key" }, 3)).toBe(false);
		expect(await store.recordAssertion(current!, 3)).toBe(true);
		const native = await legacy.auth.api.listPasskeys({ headers });
		expect(native).toContainEqual(expect.objectContaining({ id: current!.id, counter: 3 }));
	});

	it("rejects ambiguous legacy credential IDs without rewriting the stored owners", async () => {
		const adapter = (await legacy.auth.$context).adapter;
		for (const userId of [ownerId, foreignId]) {
			await adapter.create({
				model: "passkey",
				data: {
					userId, credentialID: "duplicate-legacy-id", publicKey: "+/8EAJk=",
					counter: 0, deviceType: "multiDevice", backedUp: true,
				},
			});
		}
		expect(await store.findCredential("duplicate-legacy-id")).toBeNull();
		for (const userId of [ownerId, foreignId]) {
			expect(await store.listForUser(userId)).toContainEqual(expect.objectContaining({
				userId, credentialID: "duplicate-legacy-id",
			}));
		}
	});

	it("verifies a real credential and rolls its counter forward across both engines", async () => {
		const credential = virtualCredential();
		const register = await challenge("register", headers.get("cookie")!);
		const verification = verificationService();
		expect(await verification.register({
			token: register.token, response: credential.registration(register.challenge),
			freshUserId: async () => ownerId, name: "Virtual credential",
		})).toMatchObject({ ok: true, value: { credentialID: credential.id, counter: 0, userId: ownerId } });
		const nativeChallenge = await challenge("authenticate");
		const result = await legacyCall("verify-authentication", nativeChallenge.cookie, {
			response: credential.assertion(nativeChallenge.challenge, 1),
		});
		expect(result.status).toBe(200);
		expect((await store.findCredential(credential.id))?.counter).toBe(1);
		const next = await challenge("authenticate");
		const input = { token: next.token, response: credential.assertion(next.challenge, 2) };
		expect(await verification.authenticate(input)).toEqual({ ok: true, value: { userId: ownerId } });
		expect(await verification.authenticate(input)).toEqual({ ok: false, reason: "challenge" });
		expect(await legacy.auth.api.listPasskeys({ headers })).toContainEqual(expect.objectContaining({
			credentialID: credential.id, counter: 2,
		}));
	});

	it("reads an actual legacy registration and rejects the wrong owner, origin and relying party", async () => {
		const credential = virtualCredential();
		const register = await challenge("register", headers.get("cookie")!);
		const verification = verificationService();
		expect(await verification.register({
			token: register.token, response: credential.registration(register.challenge),
			freshUserId: async () => foreignId,
		})).toEqual({ ok: false, reason: "owner" });
		expect(await store.findCredential(credential.id)).toBeNull();
		const legacyRegister = await challenge("register", headers.get("cookie")!);
		const result = await legacyCall("verify-registration", `${headers.get("cookie")}; ${legacyRegister.cookie}`, {
			response: credential.registration(legacyRegister.challenge),
		});
		expect(result.status).toBe(200);
		const badOrigin = await challenge("authenticate");
		expect(await verification.authenticate({
			token: badOrigin.token,
			response: credential.assertion(badOrigin.challenge, 1, "https://untrusted.fixture.example"),
		})).toEqual({ ok: false, reason: "verification" });
		const badRp = await challenge("authenticate");
		expect(await verification.authenticate({
			token: badRp.token,
			response: credential.assertion(badRp.challenge, 1, origin, "untrusted.fixture.example"),
		})).toEqual({ ok: false, reason: "verification" });
		const valid = await challenge("authenticate");
		expect(await verification.authenticate({
			token: valid.token, response: credential.assertion(valid.challenge, 1),
		})).toEqual({ ok: true, value: { userId: ownerId } });
	});
});
