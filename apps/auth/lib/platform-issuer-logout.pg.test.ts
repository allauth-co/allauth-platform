import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "./auth";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { createPlatformIssuerLogout } from "./platform-issuer-logout";
import { createPlatformIssuerSigner } from "./platform-issuer-signing";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { postgresDatabase } from "./postgres-database";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixture = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const issuer = "https://platform-logout.fixture.example";
const path = "/oauth2/end-session";
const confirm = `${path}/confirm`;
const endpoint = `${issuer}/api/auth`;
const cookieName = "__Secure-better-auth.session_token";
const secret = "synthetic-platform-logout-session-secret";
const env = {
	AUTH_RUNTIME: "node",
	ALLAUTH_AUTH_URL: issuer,
	ALLAUTH_AUTH_SECRET: secret,
	SCIM_CREDENTIAL_HASH_SECRET: "synthetic-platform-logout-directory-secret",
};
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";

function sessionCookie(token: string) {
	const signature = createHmac("sha256", secret).update(token).digest("base64");
	return `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`;
}

function logoutRequest(route: string, cookie: string, body?: URLSearchParams) {
	return new Request(`${endpoint}${route}`, {
		method: body ? "POST" : "GET",
		headers: {
			accept: "text/html",
			origin: issuer,
			cookie,
			"x-real-ip": "192.0.2.10",
		},
		body,
	});
}

describe.skipIf(!existsSync(fixture))(
	"platform issuer logout in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let scopedDatabase: Pool;
		let store: ReturnType<typeof createPlatformIssuerStore>;
		let native: ReturnType<typeof createAuth>;
		let signer: ReturnType<typeof createPlatformIssuerSigner>;

		beforeAll(async () => {
			const configuration = JSON.parse(readFileSync(fixture, "utf8"));
			const url = new URL(configuration.DATABASE_URL);
			if (
				configuration.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			for (const name of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"004-webhooks.sql",
				"005-free-plugins.sql",
			])
				await database.query(
					readFileSync(
						new URL(`../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			await database.query(`CREATE SCHEMA fixture_project;
			CREATE TABLE fixture_project."session" (LIKE public."session" INCLUDING ALL);`);
			scopedDatabase = new Pool({
				connectionString: url.href,
				options: "-c search_path=fixture_project,public",
				max: 3,
			});
			store = createPlatformIssuerStore(scopedDatabase);
			native = createAuth(postgresDatabase(database), env);
			signer = createPlatformIssuerSigner({ database: scopedDatabase, env });
		});

		afterAll(async () => {
			await Promise.all([database?.end(), scopedDatabase?.end()]);
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		async function seed() {
			const id = randomUUID();
			const user = `${id}-user`;
			const session = `${id}-session`;
			const sibling = `${id}-sibling`;
			const token = `${id}-token`;
			const enabled = `${id}-enabled`;
			const disabled = `${id}-disabled`;
			const destination = `https://rp.fixture.example/logout?test=${id}`;
			await database.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
				[user, `${id}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt") VALUES
			($1,$2,$3,now()+interval '1 hour',now()),($4,$5,$3,now()+interval '1 hour',now())`,
				[session, token, user, sibling, `${id}-other-token`],
			);
			await database.query(
				`INSERT INTO fixture_project."session" SELECT * FROM public."session" WHERE id=$1`,
				[session],
			);
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId","redirectUris","enableEndSession","backchannelLogoutUri",disabled)
			VALUES ($1,$1,'["https://rp.fixture.example/callback"]',true,$3,false),($2,$2,'["https://rp.fixture.example/callback"]',true,$3,true)`,
				[enabled, disabled, destination],
			);
			await database.query(
				`INSERT INTO public."oauthAccessToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
			VALUES ($1,$1,$4,$6,$8,now()+interval '1 hour',now(),'["openid"]'),
			($2,$2,$5,$6,$8,now()+interval '1 hour',now(),'["openid"]'),
			($3,$3,$4,$7,$8,now()+interval '1 hour',now(),'["openid"]')`,
				[
					`${id}-access`,
					`${id}-disabled-access`,
					`${id}-sibling-access`,
					enabled,
					disabled,
					session,
					sibling,
					user,
				],
			);
			await database.query(
				`INSERT INTO public."oauthRefreshToken" (id,token,"clientId","sessionId","userId","expiresAt","createdAt",scopes)
			VALUES ($1,$1,$4,$5,$7,now()+interval '1 hour',now(),'["openid","offline_access"]'),
			($2,$2,$4,$5,$7,now()+interval '1 hour',now(),'["openid"]'),
			($3,$3,$4,$6,$7,now()+interval '1 hour',now(),'["openid"]')`,
				[
					`${id}-offline`,
					`${id}-online`,
					`${id}-sibling-refresh`,
					enabled,
					session,
					sibling,
					user,
				],
			);
			return {
				id,
				user,
				session,
				sibling,
				enabled,
				destination,
				cookie: sessionCookie(token),
			};
		}

		async function state(data: Awaited<ReturnType<typeof seed>>) {
			const {
				rows: [sessions],
			} = await database.query(
				`SELECT
			EXISTS(SELECT 1 FROM public."session" WHERE id=$1) AS session,
			EXISTS(SELECT 1 FROM public."session" WHERE id=$2) AS sibling,
			EXISTS(SELECT 1 FROM fixture_project."session" WHERE id=$1) AS project`,
				[data.session, data.sibling],
			);
			const { rows } = await database.query(
				`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" IS NOT NULL AS bound
			FROM public."oauthAccessToken" WHERE "userId"=$1 UNION ALL
			SELECT id,revoked IS NOT NULL AS revoked,"sessionId" IS NOT NULL AS bound FROM public."oauthRefreshToken" WHERE "userId"=$1`,
				[data.user],
			);
			const { rows: events } = await database.query(
				`SELECT outcome,"actorId","userId","targetId",metadata
			FROM public."allauthEvent" WHERE type='session.deleted' AND "targetId"=$1`,
				[data.session],
			);
			return {
				...sessions,
				events,
				grants: Object.fromEntries(
					rows.map(({ id, ...grant }) => [id.slice(data.id.length + 1), grant]),
				),
			};
		}

		async function readConfirmation(
			dispatch: (
				route: string,
				request: Request,
			) => Promise<Response | undefined>,
			cookie: string,
		) {
			const prompt = await dispatch(path, logoutRequest(path, cookie));
			expect(prompt?.status).toBe(200);
			const proof = prompt?.headers
				.getSetCookie()
				.find((value) =>
					value.startsWith(`${cookieName}.oauth_logout_confirmation=`),
				)
				?.split(";", 1)[0];
			if (!proof)
				throw new Error("The fixture logout confirmation was not issued.");
			return proof;
		}

		async function confirmLogout(
			dispatch: (
				route: string,
				request: Request,
			) => Promise<Response | undefined>,
			cookie: string,
			proof: string,
		) {
			const response = await dispatch(
				confirm,
				logoutRequest(
					confirm,
					`${cookie}; ${proof}`,
					new URLSearchParams({ action: "confirm" }),
				),
			);
			expect(response?.status).toBe(200);
		}

		async function verifyDelivery(
			request: Request,
			data: Awaited<ReturnType<typeof seed>>,
		) {
			expect(request.url).toBe(data.destination);
			expect(request.method).toBe("POST");
			expect(request.redirect).toBe("error");
			const token = (await request.formData()).get("logout_token");
			if (typeof token !== "string")
				throw new Error("Missing fixture logout token.");
			const { document } = await readPlatformIssuerJwks(database);
			const { payload, protectedHeader } = await jwtVerify(
				token,
				createLocalJWKSet(document),
				{ issuer, audience: data.enabled, typ: "logout+jwt" },
			);
			expect(protectedHeader).toMatchObject({
				alg: "RS256",
				kid: expect.any(String),
			});
			expect(payload).toMatchObject({
				sub: data.user,
				sid: data.session,
				jti: expect.any(String),
				events: { [logoutEvent]: {} },
			});
			expect(payload).not.toHaveProperty("nonce");
			expect(payload.exp! - payload.iat!).toBe(120);
		}

		function candidate(
			post: (request: Request) => Promise<Response>,
			defer?: (delivery: () => Promise<void>) => void,
			transaction = store,
		) {
			return createPlatformIssuerLogout({
				store: transaction,
				signer,
				env,
				requireMfa: false,
				readBody: async () => undefined,
				clearBrowserSession() {},
				post,
				defer,
			});
		}

		it("preserves native grant, event and signed back-channel delivery scope", async () => {
			const previous = await seed();
			const next = await seed();
			const legacy = (_path: string, request: Request) =>
				native.handler(request);
			const ownedPrompt = candidate(
				async () => new Response(null, { status: 204 }),
			);
			const ownedProof = await readConfirmation(ownedPrompt, previous.cookie);
			const nativeProof = await readConfirmation(legacy, next.cookie);
			const legacyDelivery: Request[] = [];
			const fetch = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input, init) => {
					const request = new Request(input, init);
					if (request.url !== previous.destination)
						throw new Error("Unexpected fixture destination.");
					legacyDelivery.push(request);
					return new Response(null, { status: 204 });
				});
			try {
				await confirmLogout(legacy, previous.cookie, ownedProof);
			} finally {
				fetch.mockRestore();
			}
			expect(legacyDelivery).toHaveLength(1);
			await verifyDelivery(legacyDelivery[0]!, previous);
			const ownedDelivery = vi.fn(async (request: Request) => {
				expect((await state(next)).session).toBe(false);
				await verifyDelivery(request, next);
				return new Response(null, { status: 204 });
			});
			let deferred: (() => Promise<void>) | undefined;
			await confirmLogout(
				candidate(ownedDelivery, (delivery) => {
					deferred = delivery;
				}),
				next.cookie,
				nativeProof,
			);
			expect(ownedDelivery).not.toHaveBeenCalled();
			expect(deferred).toBeTypeOf("function");
			await Promise.all([deferred?.(), deferred?.()]);
			expect(ownedDelivery).toHaveBeenCalledOnce();
			for (const data of [previous, next]) {
				expect(await state(data)).toEqual({
					session: false,
					sibling: true,
					project: true,
					events: [
						{
							outcome: "success",
							actorId: null,
							userId: data.user,
							targetId: data.session,
							metadata: { path: confirm },
						},
					],
					grants: {
						access: { revoked: true, bound: false },
						"disabled-access": { revoked: true, bound: false },
						offline: { revoked: false, bound: false },
						online: { revoked: true, bound: false },
						"sibling-access": { revoked: false, bound: true },
						"sibling-refresh": { revoked: false, bound: true },
					},
				});
			}
		});

		it("revokes the exact hinted session and preserves a separate browser account", async () => {
			const target = await seed();
			const browser = await seed();
			const key = await signer.resolveSigningKey();
			const hint = await key.sign({
				iss: issuer,
				aud: target.enabled,
				sub: target.user,
				sid: target.session,
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 300,
			});
			const query = new URLSearchParams({
				client_id: target.enabled,
				id_token_hint: hint,
			});
			const delivered: Request[] = [];
			const post = vi.fn(async (request: Request) => {
				delivered.push(request);
				return new Response(null, { status: 204 });
			});
			const owned = candidate(post);
			const separate = await owned(
				path,
				logoutRequest(`${path}?${query}`, browser.cookie),
			);
			expect(await separate?.text()).toContain("Confirm logout");
			expect((await state(target)).session).toBe(true);
			expect((await state(browser)).session).toBe(true);
			expect(post).not.toHaveBeenCalled();
			for (let attempt = 0; attempt < 2; attempt++) {
				const response = await owned(
					path,
					logoutRequest(`${path}?${query}`, ""),
				);
				expect(response?.status).toBe(200);
			}
			expect(post).toHaveBeenCalledOnce();
			await verifyDelivery(delivered[0]!, target);
			expect((await state(target)).events).toEqual([
				{
					outcome: "success",
					actorId: null,
					userId: target.user,
					targetId: target.session,
					metadata: { path },
				},
			]);
			expect((await state(browser)).session).toBe(true);
		});

		it("does not deliver or persist revocation when the logout transaction rolls back", async () => {
			const data = await seed();
			const before = await state(data);
			const post = vi.fn();
			const defer = vi.fn();
			let fail = false;
			const dispatch = candidate(post, defer, {
				...store,
				transaction: (work) =>
					store.transaction(async (client) => {
						const result = await work(client);
						if (fail) throw new Error("Fixture rollback");
						return result;
					}),
			});
			const proof = await readConfirmation(dispatch, data.cookie);
			const input = () =>
				logoutRequest(
					confirm,
					`${data.cookie}; ${proof}`,
					new URLSearchParams({ action: "confirm" }),
				);
			const foreign = input();
			foreign.headers.set("origin", "https://unrelated.fixture.example");
			expect((await dispatch(confirm, foreign))?.status).toBe(403);
			fail = true;
			await expect(dispatch(confirm, input())).rejects.toThrow(
				"Fixture rollback",
			);
			expect(await state(data)).toEqual(before);
			expect(post).not.toHaveBeenCalled();
			expect(defer).not.toHaveBeenCalled();
		});

		it("keeps expired browser sessions out of the owned logout authority", async () => {
			const legacySession = await seed();
			const ownedSession = await seed();
			await database.query(
				`UPDATE public."session" SET "expiresAt"=now()-interval '1 minute' WHERE id=ANY($1::text[])`,
				[[legacySession.session, ownedSession.session]],
			);
			const legacy = (_path: string, request: Request) =>
				native.handler(request);
			const legacyProof = await readConfirmation(legacy, legacySession.cookie);
			const nativePost = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input, init) => {
					const request = new Request(input, init);
					if (request.url !== legacySession.destination)
						throw new Error("Unexpected fixture destination.");
					return new Response(null, { status: 204 });
				});
			try {
				await confirmLogout(legacy, legacySession.cookie, legacyProof);
				expect(nativePost).toHaveBeenCalledOnce();
			} finally {
				nativePost.mockRestore();
			}
			expect((await state(legacySession)).session).toBe(false);

			const before = await state(ownedSession);
			const post = vi.fn();
			const owned = candidate(post);
			const proof = await readConfirmation(owned, ownedSession.cookie);
			await confirmLogout(owned, ownedSession.cookie, proof);
			expect(await state(ownedSession)).toEqual(before);
			expect(post).not.toHaveBeenCalled();
		});
	},
);
