import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { ControlDatabase } from "./control/types";

const selected = vi.hoisted(() => ({ database: undefined as ControlDatabase | undefined }));
vi.mock("@/lib/api", () => ({ apiRoute: async (_request: Request, callback: () => Promise<Response>) => callback(), json: (value: unknown) => Response.json(value), requireSameOrigin: () => undefined }));
vi.mock("@/lib/console/database", () => ({ consoleDatabase: async () => selected.database, requireConsoleAdministrator: async () => undefined, consoleBody: async () => ({}) }));
import { GET } from "../app/api/admin/organizations/route";

const fixturePath = new URL("../../../.secrets/local-postgres.json", import.meta.url);
const request = (query = "") => GET(new Request(`http://localhost:3000/api/admin/organizations${query}`));
interface Page { organizations: { id: string; memberCount: number; teamCount: number }[]; total: number; limit: number; offset: number }
// Native authentication scope is covered separately; this exercises the actual route and query on PostgreSQL.
describe.skipIf(!existsSync(fixturePath))("organization console pagination", () => {
 const schema = `org_pages_${randomUUID().replaceAll("-", "")}`;
 let database: ControlDatabase;
 beforeAll(async () => {
  const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
  const url = new URL(fixture.DATABASE_URL);
  if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Only the isolated local fixture is permitted.");
  database = new Kysely({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 2, options: `-c search_path=${schema}` }) }) });
  await sql`CREATE SCHEMA ${sql.id(schema)}`.execute(database);
  await sql.raw(readFileSync(new URL("../migrations/001-initial-auth.sql", import.meta.url), "utf8")).execute(database);
  selected.database = database;
  for (let index=0; index<27; index++) await sql`INSERT INTO organization (id,name,slug,"createdAt") VALUES (${`org-${index}`},${`Fixture organization ${index}`},${`fixture-${index}`},${new Date(Date.UTC(2026,0,index+1))})`.execute(database);
 });
 afterAll(async () => { if(database) { await sql`DROP SCHEMA ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); } });
 it("returns non-overlapping default 25 pages matching console offsets", async () => {
  const first = await (await request()).json() as Page; const second = await (await request("?offset=25")).json() as Page;
  expect(first).toMatchObject({ total:27,limit:25,offset:0 }); expect(first.organizations).toHaveLength(25);
  expect(second).toMatchObject({ total:27,limit:25,offset:25 }); expect(second.organizations).toHaveLength(2);
  expect(second.organizations.some(row=>first.organizations.some(prior=>prior.id===row.id))).toBe(false);
 });
 it("honors bounded page sizes and rejects invalid ranges before querying", async () => {
  const result = await (await request("?limit=10&offset=10")).json() as Page; expect(result.organizations).toHaveLength(10); expect(result).toMatchObject({ total:27,limit:10,offset:10 });
  for(const query of ["?limit=0","?limit=101","?limit=2.5","?limit=invalid","?offset=-1","?offset=100001"]) await expect(request(query)).rejects.toMatchObject({ name:"ZodError" });
 });
 it("searches literal wildcard characters without changing the complete population", async () => {
  expect((await (await request("?search=%25")).json() as Page).total).toBe(0);
  expect((await (await request("?search=Fixture")).json() as Page).total).toBe(27);
 });
});
