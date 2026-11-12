import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { passkey } from "@better-auth/passkey";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { symmetricEncrypt } from "better-auth/crypto";
import { admin, anonymous } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { postgresDatabase } from "../auth";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import { newWebhookSigningSecret, webhookSignature } from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhooks";
import { deliverPendingWebhooks } from "../control/webhooks";
import { featureBoundaries } from "../features/server";
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
const fixtureSecret = "synthetic-passkey-storage-fixture-signing-secret";
const fixturePassword = "synthetic-passkey-fixture-password";
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

function legacyFixture(database: ReturnType<typeof postgresDatabase>, audit = false) {
	return getTestInstance({
		database,
		baseURL: origin,
		secret: fixtureSecret,
		advanced: { cookiePrefix: `allauth_project_${projectSlug}`, ipAddress: { ipAddressHeaders: ["x-real-ip"] } },
		...(audit ? { rateLimit: { enabled: true, storage: "database", max: 100, window: 60 } } : {}),
		logger: { disabled: true },
		plugins: [
			passkey({ rpID: rpId, origin, requireUserVerification: true }),
			...(audit ? [admin(), allauthControl({ database: database.db, secret: fixtureSecret, baseURL: origin, ipHeader: "x-real-ip", requireTrustedIP: true }), featureBoundaries(), anonymous()] : []),
		],
	}, { disableTestUser: true });
}

function ownedHttpFixture(database: Pool, policy = defaultAuthPolicy) {
	return createOwnedProjectEngine({
		database,
		project: { slug: projectSlug, schemaName: primary },
		baseURL: origin,
		basePath: "/api/auth",
		trustedOrigins: [],
		signingSecret: fixtureSecret,
		policy,
		trustedIP: (request) => request.headers.get("x-real-ip"),
		passkeys: {
			id: rpId,
			name: "Passkey fixture",
			origins: [origin],
			requireUserVerification: true,
		},
	});
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
		const migrations = ["001-initial-auth.sql", "002-control-plane.sql", "004-webhooks.sql", "005-free-plugins.sql", "006-analytics.sql"].map((name) =>
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
		const password = fixturePassword;
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

	it("matches signed native passkey registration, rename and deletion events", async () => {
			if (!pool || !nativeDatabase)
				throw new Error("Missing PostgreSQL fixture.");
			const database = nativeDatabase.db;
			const audited = await legacyFixture(nativeDatabase, true);
			const browser = {
				ipAddress: "192.0.2.65",
				userAgent: "Synthetic passkey audit browser",
			};
			const candidate = ownedHttpFixture(pool);
			const endpoint = "https://passkey-webhook.fixture.example/receive";
			const endpointId = randomUUID();
			const signingKey = newWebhookSigningSecret();
			await pool.query(
				`INSERT INTO "${primary}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["passkey.*"]',$3)`,
				[
					endpointId,
					endpoint,
					await symmetricEncrypt({ key: fixtureSecret, data: signingKey }),
				],
			);
			const cookie = headers.get("cookie")!;
			async function agedSession(kind: "stale" | "expired") {
				const login = await legacy.auth.api.signInEmail({
					body: { email: ownerEmail, password: fixturePassword },
					asResponse: true,
				});
				expect(login.status).toBe(200);
				const cookie = login.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
				const session = await legacy.auth.api.getSession({ headers: new Headers({ cookie }) });
				if (!session || !pool) throw new Error("Missing fixture session.");
				await pool.query(kind === "stale"
					? `UPDATE "${primary}"."session" SET "createdAt"=now()-interval '25 hours' WHERE id=$1`
					: `UPDATE "${primary}"."session" SET "expiresAt"=now()-interval '1 hour' WHERE id=$1`,
					[session.session.id],
				);
				return cookie;
			}
			const staleCookie = await agedSession("stale");
			const foreignLogin = await legacy.auth.api.signInEmail({
				body: { email: foreignEmail, password: fixturePassword },
				asResponse: true,
			});
			expect(foreignLogin.status).toBe(200);
			const foreignCookie = foreignLogin.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
			const absent = "synthetic-missing-passkey";
			const label = "Synthetic passkey label";
			async function exercise(
				dispatch: (request: Request) => Promise<Response>,
				candidateWriter = false,
			) {
				function send(operation: string, body?: object, session = cookie) {
					return dispatch(
						new Request(`${origin}/api/auth/passkey/${operation}`, {
							method: body ? "POST" : "GET",
							headers: {
								origin,
								cookie: session,
								"x-real-ip": browser.ipAddress,
								"user-agent": browser.userAgent,
								...(body ? { "content-type": "application/json" } : {}),
							},
							body: body ? JSON.stringify(body) : undefined,
						}),
					);
				}
				const options = await send("generate-register-options");
				expect(options.status).toBe(200);
				const { challenge } = (await options.json()) as { challenge: string };
				const proof = virtualCredential();
				const response = proof.registration(challenge);
				const request = { response, name: label };
				expect((await send("verify-registration", request)).status).toBe(400);
				const challengeCookie = options.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; ");
				async function expectValidation(operation: string, body: object, message: string, session = cookie) {
					const rejected = await send(operation, body, session);
					expect(rejected.status).toBe(400);
					expect(await rejected.json()).toEqual({ code: "VALIDATION_ERROR", message });
				}
				await expectValidation(
					"verify-registration", { ...request, createSession: "true" },
					"[body.createSession] Invalid input: expected boolean, received string",
					`${staleCookie}; ${challengeCookie}`,
				);
				const invalidProofOptions = await send("generate-register-options");
				expect(invalidProofOptions.status).toBe(200);
				const invalidProofCookie = invalidProofOptions.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
				const invalidProof = await send("verify-registration", { response: {} }, `${cookie}; ${invalidProofCookie}`);
				expect(invalidProof.status).toBe(candidateWriter ? 400 : 500);
				expect(await invalidProof.json()).toMatchObject({ code: "FAILED_TO_VERIFY_REGISTRATION" });
				const stale = { code: "SESSION_NOT_FRESH", message: "Session is not fresh" };
				const unauthenticated = { code: "UNAUTHORIZED", message: "Unauthorized" };
				const expiredCookie = await agedSession("expired");
				for (const [session, status, expected] of [
					[staleCookie, 403, stale],
					[expiredCookie, 401, unauthenticated],
					["", 401, unauthenticated],
				] as const) {
					const refused = await send("generate-register-options", undefined, session);
					expect(refused.status).toBe(status);
					expect(await refused.json()).toEqual(expected);
					expect(refused.headers.getSetCookie().some((value) => value.includes("better-auth-passkey="))).toBe(false);
					const verification = await send("verify-registration", request, [session, challengeCookie].filter(Boolean).join("; "));
					expect(verification.status).toBe(status);
					expect(await verification.json()).toEqual(expected);
				}
				const registered = await send(
					"verify-registration",
					request,
					`${cookie}; ${challengeCookie}`,
				);
				expect(registered.status).toBe(200);
				const { id } = (await registered.json()) as StoredProjectPasskey;
				await expectValidation("update-passkey", { id, name: 7 }, "[body.name] Invalid input: expected string, received number");
				await expectValidation("delete-passkey", { id: 7 }, "[body.id] Invalid input: expected string, received number", "");
				const missingId = await send("delete-passkey", { id: "" });
				expect(missingId.status).toBe(400);
				expect(await missingId.json()).toMatchObject({ message: "Missing required parameter: id" });
				if (candidateWriter) {
					if (!pool) throw new Error("Missing PostgreSQL fixture.");
					await pool.query(
						`ALTER TABLE "${primary}"."allauthEvent" ADD CONSTRAINT test_passkey_event_failure CHECK (type<>'passkey.updated') NOT VALID`,
					);
					try {
						await expect(
							send("update-passkey", { id, name: "Rolled back passkey name" }),
						).rejects.toThrow(/test_passkey_event_failure/);
					} finally {
						await pool.query(
							`ALTER TABLE "${primary}"."allauthEvent" DROP CONSTRAINT test_passkey_event_failure`,
						);
					}
					expect(
						(await store.listForUser(ownerId)).find((row) => row.id === id)
							?.name,
					).toBe(label);
				}
				expect(
					(await send("update-passkey", { id: absent, name: label })).status,
				).toBe(404);
				const extendedLabel = label.repeat(20);
				const renamed = await send("update-passkey", { id, name: extendedLabel });
				expect(renamed.status).toBe(200);
				expect(await renamed.json()).toMatchObject({ passkey: { id, name: extendedLabel } });
				for (const operation of ["update-passkey", "delete-passkey"]) {
					const rejected = await send(operation, { id, name: label }, foreignCookie);
					expect(rejected.status).toBe(candidateWriter ? 404 : 401);
					if (candidateWriter) expect(await rejected.json()).toEqual({ code: "PASSKEY_NOT_FOUND", message: "Passkey not found" });
				}
				expect((await send("delete-passkey", { id }, "")).status).toBe(401);
				expect((await send("delete-passkey", { id, name: 7, organizationId: "unrelated-fixture-field" })).status).toBe(200);
				expect((await send("delete-passkey", { id: absent })).status).toBe(404);
				const delivered: Array<{
					body: string;
					headers: Record<string, string>;
				}> = [];
				expect(
					await deliverPendingWebhooks({
						database,
						secret: fixtureSecret,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						maxDeliveries: 20,
						transport: async ({ destination, body, headers }) => {
							if (destination.url.href === endpoint)
								delivered.push({ body, headers });
							return 204;
						},
					}),
				).toMatchObject({
					claimed: delivered.length,
					delivered: delivered.length,
				});
				const events = [];
				for (const { body, headers } of delivered) {
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							signingKey,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					const envelope = JSON.parse(body) as ControlWebhookEnvelope;
					expect(envelope.data.event).toMatchObject({
						id: envelope.id,
						type: envelope.type,
						createdAt: envelope.timestamp,
					});
					expect(envelope.data.user).toBeUndefined();
					expect(envelope.data.event.organizationId).toBeUndefined();
					for (const privateValue of [
						proof.id,
						label,
						response.response.attestationObject,
						cookie,
						foreignCookie,
						signingKey,
					])
						expect(body).not.toContain(privateValue);
					const {
						id: _id,
						createdAt: _time,
						targetId,
						...event
					} = envelope.data.event;
					events.push({
						...event,
						...(targetId
							? { targetId: targetId === id ? "credential-row" : targetId }
							: {}),
					});
				}
				return events.sort((a, b) =>
					JSON.stringify(a).localeCompare(JSON.stringify(b)),
				);
			}
			try {
				const expected = await exercise((request) =>
					audited.auth.handler(request),
				);
				expect(
					expected.map(({ type, outcome }) => `${type}:${outcome}`).sort(),
				).toEqual([
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:failure",
					"passkey.deleted:success",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:failure",
					"passkey.registered:success",
					"passkey.updated:failure",
					"passkey.updated:failure",
					"passkey.updated:failure",
					"passkey.updated:success",
				]);
				for (const [type, operation] of [["passkey.deleted", "delete-passkey"], ["passkey.updated", "update-passkey"]])
					expect(expected).toContainEqual({
						...browser, type, outcome: "failure", actorId: foreignId, userId: foreignId, targetId: "credential-row",
						metadata: { path: `/passkey/${operation}`, errorCode: "PASSKEY_NOT_FOUND" },
					});
				expect(expected).toContainEqual({
					...browser,
					type: "passkey.registered", outcome: "failure", actorId: ownerId, userId: ownerId,
					metadata: { path: "/passkey/verify-registration", errorCode: "SESSION_NOT_FRESH" },
				});
				expect(
					await exercise((request) => candidate.dispatch(request), true),
				).toEqual(expected);
				const admissionIP = "192.0.2.66";
				await pool.query(
					`INSERT INTO "${primary}"."rateLimit" (id,key,count,"lastRequest") VALUES ($1,$2,99,$3)`,
					[randomUUID(), `${admissionIP}|/passkey/delete-passkey`, Date.now()],
				);
				const repeat = () =>
					new Request(`${origin}/api/auth/passkey/delete-passkey`, {
						method: "POST",
						headers: {
							origin,
							"x-real-ip": admissionIP,
							"content-type": "application/json",
						},
						body: JSON.stringify({ id: absent }),
					});
				expect((await audited.auth.handler(repeat())).status).toBe(401);
				const limit = await candidate.dispatch(repeat());
				expect(limit.status).toBe(429);
				expect(Number(limit.headers.get("X-Retry-After"))).toBeGreaterThan(0);
				const {
					rows: [queued],
				} = await pool.query<{ total: number }>(
					`SELECT count(*)::integer AS total FROM "${primary}"."allauthWebhookDelivery" WHERE "endpointId"=$1 AND status='pending'`,
					[endpointId],
				);
				expect(queued?.total).toBe(1);
			} finally {
				await pool.query(
					`DELETE FROM "${primary}"."allauthWebhookEndpoint" WHERE id=$1`,
					[endpointId],
				);
			}
		});

	it("keeps passkeys with the same existing unverified and guest identities", async () => {
		if (!pool || !nativeDatabase)
			throw new Error("Missing PostgreSQL fixture.");
		const { auth } = await legacyFixture(nativeDatabase, true);
		const candidate = ownedHttpFixture(pool, {
			...defaultAuthPolicy,
			requireEmailVerification: false,
		});
		const requiresVerification = ownedHttpFixture(pool);
		const makeRequest = (path: string, cookie: string, body?: object) =>
			new Request(`${origin}/api/auth/${path}`, {
				method: body ? "POST" : "GET",
				headers: {
					origin,
					cookie,
					"x-real-ip": "192.0.2.86",
					...(body ? { "content-type": "application/json" } : {}),
				},
				body: body ? JSON.stringify(body) : undefined,
			});
		const sessionCookie = (response: Response) =>
			response.headers
				.getSetCookie()
				.filter((value) => !value.includes("Max-Age=0"))
				.map((value) => value.split(";", 1)[0])
				.join("; ");
		const signedUp = await auth.handler(
			makeRequest("sign-up/email", "", {
				name: "Existing unverified fixture",
				email: "unverified@passkey-storage.fixture.example",
				password: fixturePassword,
			}),
		);
		const guest = await auth.handler(
			makeRequest("sign-in/anonymous", "", {}),
		);
		for (const [session, guestAccount] of [
			[signedUp, false],
			[guest, true],
		] as const) {
			expect(session.status).toBe(200);
			const { user } = (await session.json()) as {
				user: { id: string; emailVerified: boolean };
			};
			expect(user.emailVerified).toBe(false);
			if (guestAccount)
				await pool.query(
					`UPDATE "${primary}"."user" SET role='guest' WHERE id=$1`,
					[user.id],
				);
			const cookie = sessionCookie(session);
			const proof = virtualCredential();
			const nativeOptions = await auth.handler(
				makeRequest("passkey/generate-register-options", cookie),
			);
			expect(nativeOptions.status).toBe(200);
			const { challenge } = (await nativeOptions.json()) as {
				challenge: string;
			};
			const saved = await auth.handler(
				makeRequest(
					"passkey/verify-registration",
					`${cookie}; ${sessionCookie(nativeOptions)}`,
					{
						response: proof.registration(challenge),
						name: "Legacy unverified key",
					},
				),
			);
			expect(saved.status).toBe(200);
			const key = (await saved.json()) as StoredProjectPasskey;
			expect(key.userId).toBe(user.id);
			const legacyAuth = await auth.handler(
				makeRequest("passkey/generate-authenticate-options", ""),
			);
			expect(legacyAuth.status).toBe(200);
			const authentication = (await legacyAuth.json()) as {
				challenge: string;
			};
			const legacySession = await auth.handler(
				makeRequest(
					"passkey/verify-authentication",
					sessionCookie(legacyAuth),
					{
						response: proof.assertion(authentication.challenge, 1),
					},
				),
			);
			expect(legacySession.status).toBe(200);
			expect(await legacySession.json()).toMatchObject({
				user: {
					id: user.id,
					emailVerified: false,
					...(guestAccount ? { isAnonymous: true } : {}),
				},
			});
			const strictOptions = await requiresVerification.dispatch(
				makeRequest("passkey/generate-authenticate-options", ""),
			);
			expect(strictOptions.status).toBe(200);
			const strictChallenge = (await strictOptions.json()) as {
				challenge: string;
			};
			const refused = await requiresVerification.dispatch(
				makeRequest(
					"passkey/verify-authentication",
					sessionCookie(strictOptions),
					{
						response: proof.assertion(strictChallenge.challenge, 2),
					},
				),
			);
			expect(refused.status).toBe(401);
			expect((await store.findCredential(proof.id))?.counter).toBe(1);
			if (guestAccount) {
				await pool.query(
					`UPDATE "${primary}"."user" SET "twoFactorEnabled"=TRUE WHERE id=$1`,
					[user.id],
				);
				try {
					const options = await candidate.dispatch(
						makeRequest("passkey/generate-authenticate-options", ""),
					);
					expect(options.status).toBe(200);
					const { challenge } = (await options.json()) as {
						challenge: string;
					};
					const blocked = await candidate.dispatch(
						makeRequest(
							"passkey/verify-authentication",
							sessionCookie(options),
							{ response: proof.assertion(challenge, 2) },
						),
					);
					expect(blocked.status).toBe(401);
					expect((await store.findCredential(proof.id))?.counter).toBe(1);
				} finally {
					await pool.query(
						`UPDATE "${primary}"."user" SET "twoFactorEnabled"=FALSE WHERE id=$1`,
						[user.id],
					);
				}
			}
			const ownAuth = await candidate.dispatch(
				makeRequest("passkey/generate-authenticate-options", ""),
			);
			expect(ownAuth.status).toBe(200);
			const ownChallenge = (await ownAuth.json()) as { challenge: string };
			const authenticated = await candidate.dispatch(
				makeRequest("passkey/verify-authentication", sessionCookie(ownAuth), {
					response: proof.assertion(ownChallenge.challenge, 2),
				}),
			);
			expect(
				authenticated.status,
				guestAccount ? "Existing guest" : "Existing unverified account",
			).toBe(200);
			expect(await authenticated.json()).toMatchObject({
				user: {
					id: user.id,
					emailVerified: false,
					...(guestAccount ? { isAnonymous: true, role: "guest" } : {}),
				},
			});
			const renamed = await candidate.dispatch(
				makeRequest("passkey/update-passkey", cookie, {
					id: key.id,
					name: "Same owner key",
				}),
			);
			expect(renamed.status).toBe(200);
			const removed = await candidate.dispatch(
				makeRequest("passkey/delete-passkey", cookie, { id: key.id }),
			);
			expect(removed.status).toBe(200);
			const candidateOptions = await candidate.dispatch(
				makeRequest("passkey/generate-register-options", cookie),
			);
			expect(candidateOptions.status).toBe(200);
			const nextChallenge = (await candidateOptions.json()) as {
				challenge: string;
			};
			const nextProof = virtualCredential();
			const candidateRegistration = await candidate.dispatch(
				makeRequest(
					"passkey/verify-registration",
					`${cookie}; ${sessionCookie(candidateOptions)}`,
					{
						response: nextProof.registration(nextChallenge.challenge),
						createSession: true,
					},
				),
			);
			expect(candidateRegistration.status).toBe(200);
			const nextKey =
				(await candidateRegistration.json()) as StoredProjectPasskey;
			expect(nextKey.userId).toBe(user.id);
			const nextCookie = sessionCookie(candidateRegistration);
			expect(
				await auth.api.getSession({
					headers: new Headers({ cookie: nextCookie }),
				}),
			).toMatchObject({
				user: {
					id: user.id,
					emailVerified: false,
					...(guestAccount ? { isAnonymous: true, role: "guest" } : {}),
				},
			});
			const rollback = await auth.handler(
				makeRequest("passkey/delete-passkey", nextCookie, { id: nextKey.id }),
			);
			expect(rollback.status).toBe(200);
			expect(await store.listForUser(user.id)).toEqual([]);
			const events = await pool.query(
				`SELECT type,outcome,"actorId","userId" FROM "${primary}"."allauthEvent" WHERE type LIKE 'passkey.%' AND "userId"=$1 ORDER BY type`,
				[user.id],
			);
			expect(events.rows).toEqual(
				[
					"passkey.deleted",
					"passkey.deleted",
					"passkey.registered",
					"passkey.registered",
					"passkey.updated",
				].map((type) => ({
					type,
					outcome: "success",
					actorId: user.id,
					userId: user.id,
				})),
			);
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
		if (!pool) throw new Error("Missing PostgreSQL fixture.");
		const candidate = ownedHttpFixture(pool);
		const foreign = await legacy.auth.api.signInEmail({
			body: { email: foreignEmail, password: fixturePassword },
			asResponse: true,
		});
		expect(foreign.status).toBe(200);
		const foreignCookie = foreign.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
		for (const operation of ["update-passkey", "delete-passkey"])
			for (const id of [created.id, "synthetic-missing-passkey"]) {
				const rejected = await candidate.dispatch(new Request(`${origin}/api/auth/passkey/${operation}`, {
					method: "POST",
					headers: { origin, cookie: foreignCookie, "content-type": "application/json", "x-real-ip": "192.0.2.82" },
					body: JSON.stringify({ id, ...(operation === "update-passkey" ? { name: "Wrong owner" } : {}) }),
				}));
				expect(rejected.status).toBe(404);
				expect(await rejected.json()).toEqual({ code: "PASSKEY_NOT_FOUND", message: "Passkey not found" });
			}
		expect(await store.findCredential(created.credentialID)).toEqual(created);
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
