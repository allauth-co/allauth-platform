import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { siwe } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { verifyMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { describe, expect, it } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
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

function request(path: string, body: object) {
	return new Request(`${origin}${basePath}${path}`, {
		method: "POST",
		headers: { origin, "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL wallet aliases",
	() => {
		it("preserves native reserved-email denial, an existing wallet and a claimed-email fallback", async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Wallet tests require the isolated PostgreSQL fixture.",
				);
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
					trustedIP: () => "203.0.113.49",
					policy: defaultAuthPolicy,
					walletOrigin: origin,
					emailAliases: aliases,
				});
				const dispatches = [auth.handler, engine.dispatch];
				type Signer = ReturnType<typeof privateKeyToAccount>;
				async function proof(
					issue: (request: Request) => Promise<Response>,
					signer: Signer,
					email: string,
				) {
					const response = await issue(request("/siwe/nonce", {}));
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
			} finally {
				try {
					await Promise.all([database?.end(), legacy?.destroy()]);
					if (created) await dropClosedFixtureDatabase(admin, name);
				} finally {
					await admin.end();
				}
			}
		});
	},
);
