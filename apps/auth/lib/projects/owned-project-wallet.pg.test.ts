import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { siwe } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { verifyMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage, parseSiweMessage } from "viem/siwe";
import { describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { allauthControl } from "../control";
import {
	defaultSecurityPolicy,
	securitySubject,
} from "../control/security-policy";
import { projectEmailAliases } from "../project-email-aliases";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const slug = "owned-wallet-alias-fixture";
const origin = "https://wallet-alias.fixture.example";
const basePath = "/api/auth";
const secret = "synthetic-project-wallet-alias-signing-secret";
const owner = "canonical-wallet-alias-owner";
const alias = "reserved@wallet.fixture.example";
const canonicalEmail = "canonical@wallet.fixture.example";
const claimed = "claimed@wallet.fixture.example";

function request(path: string, body: object, ip = "203.0.113.49") {
	return new Request(`${origin}${basePath}${path}`, {
		method: "POST",
		headers: { origin, "content-type": "application/json", "x-real-ip": ip },
		body: JSON.stringify(body),
	});
}

type Dispatch = (request: Request) => Promise<Response>;

type Signer = ReturnType<typeof privateKeyToAccount>;
async function proof(
	issue: (request: Request) => Promise<Response>,
	signer: Signer,
	email: string,
	ip?: string,
) {
	const response = await issue(request("/siwe/nonce", {}, ip));
	expect(response.status, await response.clone().text()).toBe(200);
	const { nonce } = (await response.json()) as { nonce: string };
	const message = createSiweMessage({
		address: signer.address,
		domain: new URL(origin).host,
		uri: `${origin}/account`,
		chainId: 1,
		nonce,
		version: "1",
	});
	return {
		email,
		message,
		signature: await signer.signMessage({ message }),
	};
}

async function withWalletFixture(
	run: (database: Pool, writers: [Dispatch, Dispatch]) => Promise<void>,
) {
	const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
		readFileSync(fixturePath, "utf8"),
	);
	const url = new URL(fixture.DATABASE_URL);
	if (
		fixture.container !== "allauth-production-test-20261007" ||
		url.hostname !== "127.0.0.1" ||
		url.port !== "55445"
	)
		throw new Error("Wallet tests require the isolated PostgreSQL fixture.");
	const admin = new Pool({ connectionString: url.href, max: 1 });
	const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
	const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
	let database: Pool | undefined;
	let legacy: Kysely<Record<string, Record<string, unknown>>> | undefined;
	let created = false;
	try {
		await admin.query(`CREATE DATABASE "${name}"`);
		created = true;
		url.pathname = `/${name}`;
		database = new Pool({
			connectionString: url.href,
			max: 3,
			options: `-c search_path=${schema}`,
		});
		await database.query(`CREATE SCHEMA "${schema}"`);
		for (const file of [
			"001-initial-auth.sql",
			"002-control-plane.sql",
			"005-free-plugins.sql",
			"006-analytics.sql",
		])
			await database.query(
				readFileSync(
					new URL(`../../migrations/${file}`, import.meta.url),
					"utf8",
				),
			);
		legacy = new Kysely({
			dialect: new PostgresDialect({
				pool: new Pool({
					connectionString: url.href,
					max: 2,
					options: `-c search_path=${schema}`,
				}),
			}),
		});
		await database.query(
			`INSERT INTO "user" (id,email,name,"emailVerified") VALUES ($1,$2,'Alias owner',TRUE),($3,$4,'Current owner',TRUE)`,
			[owner, canonicalEmail, "claimed-wallet-email-owner", claimed],
		);
		const aliases = { [alias]: owner, [claimed]: owner };
		const { auth } = await getTestInstance(
			{
				baseURL: origin,
				basePath,
				secret,
				database: { db: legacy, type: "postgres", transaction: true },
				advanced: { cookiePrefix: `allauth_project_${slug}` },
				plugins: [
					allauthControl({
						database: legacy,
						baseURL: origin,
						secret,
						ipHeader: "x-real-ip",
						requireTrustedIP: true,
					}),
					projectEmailAliases({
						project: slug,
						readConfiguration: () => JSON.stringify(aliases),
					}),
					siwe({
						domain: new URL(origin).host,
						anonymous: false,
						getNonce: async () => randomBytes(16).toString("hex"),
						verifyMessage: ({ address, message, signature }) =>
							verifyMessage({
								address: address as `0x${string}`,
								message,
								signature: signature as `0x${string}`,
							}),
					}),
				],
				logger: { disabled: true },
			},
			{ disableTestUser: true },
		);
		const engine = createOwnedProjectEngine({
			database,
			project: { schemaName: schema, slug },
			baseURL: origin,
			basePath,
			signingSecret: secret,
			trustedOrigins: [],
			trustedIP: (request) => request.headers.get("x-real-ip"),
			policy: defaultAuthPolicy,
			walletOrigin: origin,
			emailAliases: aliases,
		});
		await run(database, [auth.handler, engine.dispatch]);
	} finally {
		try {
			await Promise.all([database?.end(), legacy?.destroy()]);
			if (created) await dropClosedFixtureDatabase(admin, name);
		} finally {
			await admin.end();
		}
	}
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL wallet account policy",
	() => {
		it("preserves native reserved-email denial, an existing wallet and a claimed-email fallback", async () => {
			await withWalletFixture(async (database, dispatches) => {
				for (const [index, dispatch] of dispatches.entries()) {
					const other = dispatches[1 - index]!;
					const signer = privateKeyToAccount(generatePrivateKey());
					const reserved = await proof(other, signer, alias);
					const denied = await dispatch(request("/siwe/verify", reserved));
					expect(denied.status, await denied.clone().text()).toBe(422);
					expect(await denied.json()).toEqual({
						code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
						message: "User already exists. Use another email.",
					});
					expect((await other(request("/siwe/verify", reserved))).status).toBe(
						401,
					);
					expect(
						(
							await database.query(
								`SELECT id FROM "user" WHERE email=$1
			 UNION ALL SELECT id FROM "walletAddress" WHERE lower(address)=lower($2)`,
								[alias, signer.address],
							)
						).rows,
					).toEqual([]);
					const fallback = await dispatch(
						request("/siwe/verify", await proof(other, signer, claimed)),
					);
					expect(fallback.status, await fallback.clone().text()).toBe(200);
					const bound = (
						await database.query<{ id: string; email: string }>(
							`SELECT u.id,u.email FROM "user" u JOIN "walletAddress" w ON w."userId"=u.id WHERE lower(w.address)=lower($1)`,
							[signer.address],
						)
					).rows[0];
					expect(bound?.email).toBe(
						`${signer.address.toLowerCase()}@siwe.placeholder.invalid`,
					);
					const verified = await other(
						request("/siwe/verify", await proof(dispatch, signer, alias)),
					);
					expect(verified.status, await verified.clone().text()).toBe(200);
					expect(await verified.json()).toMatchObject({
						user: { id: bound?.id },
					});
				}
			});
		});
		it("preserves wallet signup admission and ordinary failure buckets across both writers", async () => {
			await withWalletFixture(async (database, writers) => {
				await database.query(
					`INSERT INTO "allauthSecurityPolicy" (id,policy) VALUES ('default',$1)`,
					[{ ...defaultSecurityPolicy, maxSignUpsPerIp: 1 }],
				);
				await database.query(
					`INSERT INTO "allauthSecurityRule" (id,type,value,reason)
					 VALUES ($1,'email-domain','siwe.placeholder.invalid','Synthetic wallet policy')`,
					[randomUUID()],
				);
				const count = async (scope: string, value: string) =>
					(
						await database.query<{ count: number }>(
							`SELECT count FROM "allauthSecurityCounter" WHERE key=$1`,
							[await securitySubject(secret, scope, value)],
						)
					).rows[0]?.count ?? 0;
				const rejected = async (response: Response) => {
					expect(response.status, await response.clone().text()).toBe(403);
					expect(await response.json()).toEqual({
						code: "validation_failed",
						message: "User validation failed",
					});
					expect(response.headers.getSetCookie()).toEqual([]);
				};
				const bindings = (signer: Signer) =>
					database.query<{ userId: string }>(
						`SELECT "userId" FROM "walletAddress" WHERE lower(address)=lower($1)`,
						[signer.address],
					);
				const walletDomain = "allowed-wallet.fixture.example";
				const audit = async (ip: string) =>
					(
						await database.query(
							`SELECT type,outcome,metadata FROM "allauthEvent"
						 WHERE "ipAddress"=$1 AND type IN ('auth.sign-in','security.blocked')
						 ORDER BY type`,
							[ip],
						)
					).rows;
				const existing: Signer[] = [];
				for (const [index, writer] of writers.entries()) {
					const other = writers[1 - index]!;
					const ip = `203.0.113.${53 + index}`;
					const authenticate = async (
						dispatch: Dispatch,
						issuer: Dispatch,
						signer: Signer,
						email: string,
					) =>
						dispatch(
							request(
								"/siwe/verify",
								await proof(issuer, signer, email, ip),
								ip,
							),
						);
					const first = privateKeyToAccount(generatePrivateKey());
					await rejected(await authenticate(writer, other, first, claimed));
					expect((await bindings(first)).rows).toEqual([]);
					expect(await count("signup-ip", ip)).toBe(0);
					expect(await count("fail-ip", ip)).toBe(1);
					expect(
						await count("fail-ip-identity", `${ip}\0email:${claimed}`),
					).toBe(1);

					const signer = privateKeyToAccount(generatePrivateKey());
					const email = `wallet-${index}@${walletDomain}`;
					const allowed = await authenticate(writer, other, signer, email);
					expect(allowed.status, await allowed.clone().text()).toBe(200);
					const bound = (await bindings(signer)).rows[0]!;
					expect(await allowed.json()).toMatchObject({
						user: { id: bound.userId },
					});
					expect(await count("signup-ip", ip)).toBe(1);
					const continued = await authenticate(other, writer, signer, claimed);
					expect(continued.status, await continued.clone().text()).toBe(200);
					expect(await continued.json()).toMatchObject({
						user: { id: bound.userId },
					});
					expect(await count("signup-ip", ip)).toBe(1);
					existing.push(signer);

					const over = privateKeyToAccount(generatePrivateKey());
					const overEmail = `velocity-${index}@${walletDomain}`;
					await rejected(await authenticate(other, writer, over, overEmail));
					expect((await bindings(over)).rows).toEqual([]);
					expect(await count("signup-ip", ip)).toBe(2);
					expect(await count("fail-ip", ip)).toBe(2);
					expect(
						await count("fail-ip-identity", `${ip}\0email:${overEmail}`),
					).toBe(1);

					const expired = await proof(other, signer, email, ip);
					await database.query(
						`UPDATE "verification" SET "expiresAt"=now()-interval '1 minute' WHERE identifier=$1`,
						[`siwe:${parseSiweMessage(expired.message).nonce}`],
					);
					const stale = await writer(request("/siwe/verify", expired, ip));
					expect(stale.status, await stale.clone().text()).toBe(401);
					expect(await stale.json()).toMatchObject({
						code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
					});
					expect(await count("signup-ip", ip)).toBe(2);
					expect(await count("fail-ip", ip)).toBe(3);
					expect(await count("fail-ip-identity", `${ip}\0email:${email}`)).toBe(
						1,
					);
					expect(await count("request-ip", ip)).toBe(5);
				}
				await database.query(
					`INSERT INTO "allauthSecurityRule" (id,type,value,reason)
					 VALUES ($1,'email-domain',$2,'Synthetic stored wallet policy')`,
					[randomUUID(), walletDomain],
				);
				for (const [index, writer] of writers.entries()) {
					const ip = `203.0.113.${56 + index}`;
					const signer = existing[index]!;
					const pending = await proof(writers[1 - index]!, signer, claimed, ip);
					const response = await writer(request("/siwe/verify", pending, ip));
					expect(response.status, await response.clone().text()).toBe(429);
					expect(await response.json()).toMatchObject({
						code: "ALLAUTH_SECURITY_BLOCKED",
					});
					expect(await count("signup-ip", ip)).toBe(0);
					expect(await count("fail-ip", ip)).toBe(0);
					expect(await audit(ip)).toEqual([
						{
							type: "auth.sign-in",
							outcome: "failure",
							metadata: {
								path: "/siwe/verify",
								errorCode: "ALLAUTH_SECURITY_BLOCKED",
							},
						},
						expect.objectContaining({
							type: "security.blocked",
							outcome: "blocked",
						}),
					]);
					const admissionIP = `203.0.113.${60 + index}`;
					const unsubmitted = await proof(
						writers[1 - index]!,
						signer,
						"submitted@siwe.placeholder.invalid",
						admissionIP,
					);
					const denied = await writer(
						request("/siwe/verify", unsubmitted, admissionIP),
					);
					expect(denied.status).toBe(429);
					expect(await denied.json()).toMatchObject({
						code: "ALLAUTH_SECURITY_BLOCKED",
					});
					expect(await count("fail-ip", admissionIP)).toBe(0);
					expect(await audit(admissionIP)).toEqual([
						expect.objectContaining({
							type: "security.blocked",
							outcome: "blocked",
						}),
					]);
					expect(
						(
							await database.query(
								`SELECT 1 FROM "verification" WHERE identifier=$1`,
								[`siwe:${parseSiweMessage(unsubmitted.message).nonce}`],
							)
						).rowCount,
					).toBe(1);
				}
			});
		});
	},
);
