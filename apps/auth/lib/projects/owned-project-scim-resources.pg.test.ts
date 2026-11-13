import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { scim } from "@better-auth/scim";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import {
	scimEnterpriseUserSchema,
	scimGroupSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://accounts.scim-resources-fixture.example";
const basePath = "/api/projects/resources-fixture/auth";
const baseURL = `${origin}${basePath}`;
const secret = "isolated-scim-resources-credential-pepper";
const provisioningDomainId = "organization:resources-fixture";
const fullScopes = [
	"scim.users.read",
	"scim.users.write",
	"scim.groups.read",
	"scim.groups.write",
] as const;

function request(
	path: string,
	token: string,
	options?: { query?: URLSearchParams; body?: object },
) {
	const url = new URL(`${baseURL}/scim/v2/${path}`);
	if (options?.query) url.search = options.query.toString();
	return new Request(url, {
		method: options?.body ? "POST" : "GET",
		headers: {
			...(token ? { authorization: `Bearer ${token}` } : {}),
			...(options?.body ? { "content-type": "application/scim+json" } : {}),
		},
		...(options?.body ? { body: JSON.stringify(options.body) } : {}),
	});
}

async function legacyFixture(
	database: Kysely<Record<string, Record<string, unknown>>>,
) {
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			secret: "isolated-scim-resources-signing-key",
			database: { db: database, type: "postgres", transaction: true },
			plugins: [
				scim({
					connections: [],
					managedConnections: { credentialHashSecret: secret },
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixturePath))(
	"isolated PostgreSQL owned SCIM Users and Groups reads",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const schema = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		const other = `allauth_project_${randomUUID().replaceAll("-", "")}`;
		let admin: Pool | undefined;
		let database: Pool;
		let nativeDatabase:
			| Kysely<Record<string, Record<string, unknown>>>
			| undefined;
		let legacy: Awaited<ReturnType<typeof legacyFixture>>;
		let dispatch: ReturnType<typeof createOwnedProjectSCIMResources>;
		let token: string;
		let first: string;
		let second: string;
		let group: string;
		let created = false;

		async function issue(
			scopes: readonly (typeof fullScopes)[number][] = fullScopes,
			domain = provisioningDomainId,
		) {
			return legacy.api.createSCIMManagedConnection({
				body: {
					creationRequestId: randomUUID(),
					provisioningDomainId: domain,
					actorId: "fixture-admin",
					scopes,
					expiresAt: new Date(Date.now() + 5 * 60_000),
				},
			});
		}

		async function provision(
			resource: "Users" | "Groups",
			body: object,
			bearer = token,
		) {
			const response = await legacy.handler(
				request(resource, bearer, { body }),
			);
			const value: unknown = await response.json();
			expect(response.status, JSON.stringify(value)).toBe(201);
			if (
				!value ||
				typeof value !== "object" ||
				!("id" in value) ||
				typeof value.id !== "string"
			)
				throw new Error(
					"The legacy SCIM fixture did not return a resource id.",
				);
			return value.id;
		}

		beforeAll(async () => {
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
					"SCIM resources require the isolated PostgreSQL fixture.",
				);
			admin = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
			await admin.query(`CREATE DATABASE "${databaseName}"`);
			created = true;
			url.pathname = `/${databaseName}`;
			database = new Pool({
				connectionString: url.toString(),
				max: 2,
				options: `-c search_path=${other}`,
			});
			const client = await database.connect();
			try {
				const migration = readFileSync(
					new URL("../../migrations/001-initial-auth.sql", import.meta.url),
					"utf8",
				);
				for (const realm of [schema, other]) {
					await client.query(`CREATE SCHEMA "${realm}"`);
					await client.query(`SET search_path TO "${realm}"`);
					await client.query(migration);
				}
				await client.query(`SET search_path TO "${other}"`);
			} finally {
				client.release();
			}
			nativeDatabase = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: url.toString(),
						max: 2,
						options: `-c search_path=${schema}`,
					}),
				}),
			});
			legacy = await legacyFixture(nativeDatabase);
			dispatch = createOwnedProjectSCIMResources({
				database,
				schemaName: schema,
				credentialHashSecret: secret,
				baseURL,
			});
			token = (await issue()).token;
			first = await provision("Users", {
				schemas: [scimUserSchema, scimEnterpriseUserSchema],
				userName: "alice@scim.example",
				externalId: 'Alice and "team"',
				displayName: "Alice Example",
				active: true,
				name: {
					formatted: "Alice Example",
					givenName: "Alice",
					familyName: "Example",
				},
				emails: [
					{ value: "alice@scim.example", type: "work", primary: true },
					{ value: "alias@scim.example", type: "home" },
				],
				title: "Lead",
				locale: "en-AU",
				phoneNumbers: [{ value: "+61000000000", type: "work" }],
				roles: [{ value: "employee", type: "internal" }],
				[scimEnterpriseUserSchema]: {
					employeeNumber: "E-12",
					department: "Fixtures",
					manager: { value: "manager-12" },
				},
			});
			second = await provision("Users", {
				schemas: [scimUserSchema],
				userName: "bob@scim.example",
				externalId: "Bob",
				active: false,
				name: {
					formatted: "Bob Example",
					givenName: "Bob",
					familyName: "Example",
				},
			});
			group = await provision("Groups", {
				schemas: [scimGroupSchema],
				displayName: "Engineering",
				externalId: "Team-1",
				members: [{ value: first }, { value: second }],
			});
			await provision("Groups", {
				schemas: [scimGroupSchema],
				displayName: "Second Group",
				externalId: "Team-2",
				members: [{ value: first }],
			});
			await database.query(
				`UPDATE "${schema}"."scimUser" SET "serializedAttributes" = NULL WHERE id = $1`,
				[second],
			);
		});

		afterAll(async () => {
			await Promise.all([database?.end(), nativeDatabase?.destroy()]);
			if (!admin) return;
			try {
				if (created) await dropClosedFixtureDatabase(admin, databaseName);
			} finally {
				await admin.end();
			}
		});

		async function compare(
			path: string,
			query?: URLSearchParams,
			status = 200,
			bearer = token,
		) {
			const native = await legacy.handler(
				request(path, bearer, query ? { query } : undefined),
			);
			const candidate = await dispatch(
				request(path, bearer, query ? { query } : undefined),
			);
			const label = `${path}?${query ?? ""}`;
			expect(native.status, label).toBe(status);
			expect(candidate?.status, label).toBe(status);
			expect(candidate?.headers.get("content-type"), path).toBe(
				native.headers.get("content-type"),
			);
			expect(candidate?.headers.get("www-authenticate"), path).toBe(
				native.headers.get("www-authenticate"),
			);
			const body: unknown = await candidate?.json();
			expect(body, label).toEqual(await native.json());
			return body;
		}

		it("reads canonical and legacy mirror Users with the same detail, selection and list envelopes", async () => {
			await compare(`Users/${first}`);
			await compare(`Users/${second}`);
			await compare(
				`Users/${first}`,
				new URLSearchParams([
					["attributes", "name.familyName,emails.value"],
					["attributes", "manager.value,meta.location"],
				]),
			);
			await compare(
				`Users/${first}`,
				new URLSearchParams({
					excludedAttributes: `id,schemas,${scimEnterpriseUserSchema}:manager.value,emails.type`,
				}),
			);
			await compare("Users");
			await compare(
				"Users",
				new URLSearchParams({
					startIndex: "2",
					count: "1",
					attributes: "displayName,active",
				}),
			);
			await compare(
				"Users",
				new URLSearchParams({ startIndex: "0", count: "0" }),
			);
			await compare(
				"Users",
				new URLSearchParams({ startIndex: "9", count: "101" }),
			);
		});

		it("applies supported equality and conjunction filters to connection-scoped keys", async () => {
			for (const filter of [
				'userName EQ "ALICE@SCIM.EXAMPLE"',
				`${scimUserSchema}:userName eq "alice@scim.example" and externalId eq ${JSON.stringify('Alice and "team"')}`,
				'emails[type eq "work"].value eq " ALICE@SCIM.EXAMPLE "',
				'emails.value eq "alias@scim.example"',
				'emails[type eq "work"].value eq "alias@scim.example"',
				`id eq "${second}"`,
			])
				await compare("Users", new URLSearchParams({ filter }));
			for (const filter of [
				'displayName eq "ENGINEERING"',
				'externalId eq "Team-1"',
				'externalId eq "team-1"',
			])
				await compare("Groups", new URLSearchParams({ filter }));
		});

		it("matches Group detail, batched members, nested projection and empty selection", async () => {
			await compare(`Groups/${group}`);
			await compare(
				`Groups/${group}`,
				new URLSearchParams({ attributes: "displayName,members.$ref" }),
			);
			await compare(
				`Groups/${group}`,
				new URLSearchParams({
					excludedAttributes: "members.display,meta.lastModified",
				}),
			);
			await compare("Groups");
			await compare(
				"Groups",
				new URLSearchParams({ startIndex: "2", count: "1" }),
			);
			await compare(
				"Groups",
				new URLSearchParams({ excludedAttributes: "members" }),
			);
			await compare("Groups", new URLSearchParams({ count: "-1" }));
		});

		it("preserves native query errors and leaves non-GET or unrelated routes unclaimed", async () => {
			for (const query of [
				new URLSearchParams({ count: "1.5" }),
				new URLSearchParams({ startIndex: "NaN" }),
				new URLSearchParams({ filter: 'userName co "alice"' }),
				new URLSearchParams({ filter: 'active eq "true"' }),
				new URLSearchParams({ filter: 'id eq "unfinished' }),
				new URLSearchParams({ attributes: "displayName," }),
				new URLSearchParams({ attributes: "id", excludedAttributes: "meta" }),
				new URLSearchParams([
					["filter", 'id eq "a"'],
					["filter", 'id eq "b"'],
				]),
			])
				await compare("Users", query, 400);
			await compare(
				"Users/missing",
				new URLSearchParams({ attributes: "id," }),
				404,
			);
			expect(await dispatch(request("Users/", token))).toBeNull();
			expect(await dispatch(request("Schemas", token))).toBeNull();
			expect(await dispatch(request("Users", token, { body: {} }))).toBeNull();
		});

		it("isolates credentials, resources and memberships across connection and realm boundaries", async () => {
			const otherConnection = await issue([
				"scim.users.read",
				"scim.groups.read",
			]);
			expect(
				(await legacy.handler(request("Users", otherConnection.token))).status,
			).toBe(200);
			await compare(`Users/${first}`, undefined, 404, otherConnection.token);
			await compare(`Groups/${group}`, undefined, 404, otherConnection.token);
			expect(
				await compare("Users", undefined, 200, otherConnection.token),
			).toMatchObject({ totalResults: 0, Resources: [] });
			const foreign = await issue(fullScopes, "organization:foreign");
			const foreignUser = await provision(
				"Users",
				{
					schemas: [scimUserSchema],
					userName: "foreign@scim.example",
				},
				foreign.token,
			);
			await compare(`Users/${foreignUser}`, undefined, 404);
			const edge = randomUUID();
			await database.query(
				`INSERT INTO "${schema}"."scimGroupMember" (id, "connectionId", "groupId", "scimUserId", "membershipKey", "createdAt")
				 SELECT $1, "connectionId", id, $2, $1, statement_timestamp() FROM "${schema}"."scimGroup" WHERE id = $3`,
				[edge, foreignUser, group],
			);
			try {
				await compare(`Groups/${group}`);
			} finally {
				await database.query(
					`DELETE FROM "${schema}"."scimGroupMember" WHERE id = $1`,
					[edge],
				);
			}
			const usersOnly = await issue(["scim.users.read"]);
			await compare("Groups", undefined, 403, usersOnly.token);
			await compare("Users", undefined, 401, "");
			const wrongRealm = createOwnedProjectSCIMResources({
				database,
				schemaName: other,
				credentialHashSecret: secret,
				baseURL,
			});
			expect((await wrongRealm(request(`Users/${first}`, token)))?.status).toBe(
				401,
			);
			expect(
				(await database.query("SELECT current_schema() AS schema")).rows[0],
			).toEqual({ schema: other });
		});

		it("refuses corrupt resource domains and prevents a Group from projecting a mismatched User", async () => {
			await database.query(
				`UPDATE "${schema}"."scimUser" SET "provisioningDomainId" = 'organization:mismatched' WHERE id = $1`,
				[first],
			);
			try {
				await compare(`Users/${first}`, undefined, 409);
				await compare(
					"Users",
					new URLSearchParams({ filter: `id eq "${second}"` }),
					409,
				);
				expect(
					(await dispatch(request(`Groups/${group}`, token)))?.status,
				).toBe(409);
				await compare(
					`Groups/${group}`,
					new URLSearchParams({ excludedAttributes: "members" }),
				);
			} finally {
				await database.query(
					`UPDATE "${schema}"."scimUser" SET "provisioningDomainId" = $2 WHERE id = $1`,
					[first, provisioningDomainId],
				);
			}
			await database.query(
				`UPDATE "${schema}"."scimGroup" SET "provisioningDomainId" = 'organization:mismatched' WHERE id = $1`,
				[group],
			);
			try {
				await compare(`Groups/${group}`, undefined, 409);
				await compare("Groups", undefined, 409);
			} finally {
				await database.query(
					`UPDATE "${schema}"."scimGroup" SET "provisioningDomainId" = $2 WHERE id = $1`,
					[group, provisioningDomainId],
				);
			}
		});
	},
);
