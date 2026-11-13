import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { getTestInstance } from "better-auth/test";
import { admin, anonymous, organization } from "better-auth/plugins";
import { parseSetCookieHeader } from "better-auth/cookies";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { productionTwoFactor } from "../mfa";
import { allauthControl } from "./index";
import { createActivityRecorder } from "./analytics-activity";
import { analyticsEntitiesQuery, analyticsQuery, analyticsWindow, queryControlAnalytics, queryControlAnalyticsEntities } from "./analytics-queries";
import type { AnalyticsEntitiesFilters, AnalyticsFilters } from "./analytics-types";
import type { ControlDatabase } from "./types";

const DAY = 86_400_000;
const day = (offset = 0) => new Date(new Date().setUTCHours(0, 0, 0, 0) + offset * DAY).toISOString().slice(0, 10);
const stamp = (offset: number) => new Date(`${day(offset)}T12:00:00.000Z`);
const filters = (extra: Partial<AnalyticsFilters> = {}): AnalyticsFilters => ({ entity: "users", range: "7d", bucket: "day", end: day(-1), ...extra });
const entityFilters = (cohort: AnalyticsEntitiesFilters["cohort"], extra: Partial<AnalyticsEntitiesFilters> = {}): AnalyticsEntitiesFilters => ({ ...filters(), cohort, limit: 100, offset: 0, ...extra });
const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);

describe("analytics date and parameter boundaries", () => {
	it("validates real UTC dates, paired overrides and bounded pagination/search", () => {
		for (const input of [{ end: "2026-02-30" }, { from: day(-2) }, { to: day(-1) }, { end: "2026-13-01" }, { bucket: "hour" }, { q: "private" }]) expect(analyticsQuery.safeParse(input).success).toBe(false);
		for (const input of [{ limit: 101 }, { offset: -1 }, { q: "x".repeat(129) }, { cohort: "invented" }]) expect(analyticsEntitiesQuery.safeParse(input).success).toBe(false);
		expect(analyticsQuery.parse({})).toEqual({ entity: "users", range: "30d", bucket: "day" });
	});
	it("uses inclusive UTC calendar windows and clamps six-month month ends", () => {
		expect(analyticsWindow(filters({ from: "2026-09-01", to: "2026-09-07" }), new Date("2026-10-07T12:00:00Z"))).toEqual({ from: "2026-09-01", to: "2026-09-07", previousFrom: "2026-08-25", previousTo: "2026-08-31", days: 7 });
		expect(analyticsWindow(filters({ range: "6m", end: "2026-08-31" }), new Date("2026-10-07T12:00:00Z"))).toMatchObject({ from: "2026-03-01", to: "2026-08-31", days: 184 });
		for (const dates of [{ from: "2026-09-02", to: "2026-09-01" }, { from: "2025-01-01", to: "2026-09-01" }, { from: "2026-10-08", to: "2026-10-09" }]) expect(() => analyticsWindow(filters(dates), new Date("2026-10-07T12:00:00Z"))).toThrow();
	});
});

describe.skipIf(!existsSync(fixturePath))("actual PostgreSQL durable analytics, native hooks and isolation", () => {
	const schema = `analytics_test_${randomUUID().replaceAll("-", "_")}`;
	const otherSchema = `${schema}_other`;
	let database: ControlDatabase;
	let other: ControlDatabase;
	let analyticsQueries = 0;
	const benchmarks: { description: string; entities: number; dailyRows: number; buckets: number; queries: number; milliseconds: number }[] = [];
	const makeInstance = () => getTestInstance({ database: { db: database, type: "postgres", transaction: true }, baseURL: "http://localhost:3000", logger: { disabled: true }, emailAndPassword: { enabled: true, autoSignIn: false }, session: { cookieCache: { enabled: true } }, plugins: [admin(), organization(), anonymous(), productionTwoFactor("http://localhost:3000"), allauthControl({ database })] }, { disableTestUser: true });
	let instance: Awaited<ReturnType<typeof makeInstance>>;
	async function migrate(target: ControlDatabase, name: string) {
		await sql`CREATE SCHEMA ${sql.id(name)}`.execute(target);
		for (const migration of ["001-initial-auth.sql", "002-control-plane.sql", "005-free-plugins.sql", "006-analytics.sql"]) await sql.raw(readFileSync(new URL(`../../migrations/${migration}`, import.meta.url), "utf8")).execute(target);
	}
	async function user(id: string, created: number, anonymous = false) {
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","createdAt","updatedAt","isAnonymous","privateMetadata") VALUES (${id},${`User ${id}`},${`${id}@fixture.example`},true,${stamp(created)},CURRENT_TIMESTAMP,${anonymous},'{"secret":"analytics-private-profile"}')`.execute(database);
	}
	async function activity(entity: "users" | "organizations", id: string, offset: number) {
		await sql`INSERT INTO "allauthAnalyticsActivity" ("entityType","entityId",day,sources) VALUES (${entity},${id},${day(offset)}::date,2)`.execute(database);
	}
	async function seed() {
		for (const [id, offset] of [["new-active", -2], ["new-idle", -3], ["retained", -60], ["reactivated", -60], ["churned", -60], ["first-active", -50], ["unknown-old", -150], ["deleted", -2]] as const) await user(id, offset);
		for (const [id, offsets] of [["new-active", [-2]], ["retained", [-10, -2]], ["reactivated", [-30, -2]], ["churned", [-10]], ["first-active", [-2]], ["unknown-old", [-2]], ["deleted", [-2]]] as const) for (const offset of offsets) await activity("users", id, offset);
		await sql`DELETE FROM "user" WHERE id='deleted'`.execute(database);
	}
	async function nativeUser(role = "user") {
		const email = `${randomUUID()}@native-fixture.example`;
		const password = `Fixture-${randomUUID()}`;
		const result = await instance.auth.api.signUpEmail({ body: { email, password, name: "Native Analytics Fixture" } });
		await sql`UPDATE "user" SET "emailVerified"=true,role=${role} WHERE id=${result.user.id}`.execute(database);
		const signedIn = await instance.auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
		const cookies = parseSetCookieHeader(signedIn.headers.get("set-cookie") || "");
		const headers = new Headers({ origin: "http://localhost:3000", cookie: [...cookies].map(([name, value]) => `${name}=${value.value}`).join("; ") });
		return { id: result.user.id, email, password, headers };
	}
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath, "utf8"));
		const url = new URL(fixture.DATABASE_URL);
		if (fixture.container !== "allauth-production-test-20261007" || url.hostname !== "127.0.0.1" || url.port !== "55445") throw new Error("Analytics proof requires the isolated local PostgreSQL container.");
		const connect = (name: string) => new Kysely<Record<string, Record<string, unknown>>>({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL, max: 4, options: `-c search_path=${name}` }) }), log(event) { if (event.level === "query" && event.query.sql.includes('"allauthAnalytics')) analyticsQueries++; } });
		database = connect(schema); other = connect(otherSchema);
		await migrate(database, schema); await migrate(other, otherSchema);
		instance = await makeInstance();
	});
	beforeEach(async () => {
		await sql`TRUNCATE "user",organization,"allauthAnalyticsEntity","allauthAnalyticsDaily","allauthEvent" CASCADE`.execute(database);
		await sql`UPDATE "allauthAnalyticsCoverage" SET "startedAt"=${stamp(-90)} WHERE id='native-v1'`.execute(database);
	});
	afterAll(async () => {
		if (database) { await sql`DROP SCHEMA IF EXISTS ${sql.id(schema)} CASCADE`.execute(database); await database.destroy(); }
		if (other) { await sql`DROP SCHEMA IF EXISTS ${sql.id(otherSchema)} CASCADE`.execute(other); await other.destroy(); }
		if (benchmarks.length) {
			const output = new URL("../../../../output/analytics-local-test-proof.json", import.meta.url);
			mkdirSync(new URL(".", output), { recursive: true });
			writeFileSync(output, JSON.stringify({ fixture: "isolated PostgreSQL schemas on 127.0.0.1:55445", benchmarks, semantics: "Native authenticated activity; no product engagement inferred; no secrets or profile snapshots stored." }, null, 2));
		}
	});
	it("returns exact observed cohorts, preserves deleted facts without profiles and distinguishes unknown prior history", async () => {
		await seed();
		const result = await queryControlAnalytics(database, filters());
		expect(Object.fromEntries(Object.entries(result.metrics).map(([key,value]) => [key,value.value]))).toEqual({ active: 6, new: 3, retained: 1, reactivated: 1, churned: 1, firstActive: 1, unknown: 1, all: 7 });
		expect(result.coverage).toMatchObject({ current: "complete", previous: "complete", includesAnonymous: false, includesImpersonation: false, independentOfAuditRetention: true });
		expect(result.metrics.reactivated.complete).toBe(false);
		for (const [cohort, expected] of [["retained", ["retained"]], ["reactivated", ["reactivated"]], ["churned", ["churned"]], ["firstActive", ["first-active"]], ["unknown", ["unknown-old"]], ["new", ["deleted", "new-active", "new-idle"]]] as const) {
			const members = await queryControlAnalyticsEntities(database, entityFilters(cohort));
			expect(members.entities.map((entry) => entry.id).sort()).toEqual([...expected].sort()); expect(members.total).toBe(result.metrics[cohort].value);
		}
		const deleted = (await queryControlAnalyticsEntities(database, entityFilters("new"))).entities.find((entry) => entry.id === "deleted");
		expect(deleted).toMatchObject({ id: "deleted", deleted: true, name: null, email: null });
		expect(JSON.stringify(result)).not.toContain("analytics-private-profile");
	});
	it("keeps unknown precollection buckets null and reports measured partial values without invented zeros", async () => {
		await user("existing", -100); await activity("users", "existing", -1);
		await sql`UPDATE "allauthAnalyticsCoverage" SET "startedAt"=${stamp(-1)} WHERE id='native-v1'`.execute(database);
		const result = await queryControlAnalytics(database, filters());
		expect(result.coverage.current).toBe("partial"); expect(result.metrics.active).toEqual({ value: 1, complete: false });
		expect(result.series.slice(0, -1).every((point) => point.coverage === "unknown" && point.values.active === null && point.signIns === null)).toBe(true);
		expect(result.series.at(-1)).toMatchObject({ coverage: "partial", values: { active: null }, observed: { active: 1, unknown: 1 } });
	});
	it("retains sign-in counts and activity after audit pruning and counts failures once without account enumeration", async () => {
		await user("actual", -40);
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","createdAt",metadata) VALUES ('good','auth.sign-in','success','actual',${stamp(-2)},'{}'),('bad','auth.sign-in','failure',NULL,${stamp(-2)},'{}'),('mirror','security.sign-in-failed','failure',NULL,${stamp(-2)},'{}'),('mfa','auth.mfa-required','success','actual',${stamp(-2)},'{}')`.execute(database);
		const before = await queryControlAnalytics(database, filters());
		expect(before.traffic).toMatchObject({ signIns: { value: 1 }, failedSignIns: { value: 1 } }); expect(before.metrics.active.value).toBe(1);
		await sql`DELETE FROM "allauthEvent"`.execute(database);
		const after = await queryControlAnalytics(database, filters());
		expect(after.metrics).toEqual(before.metrics); expect(after.traffic).toEqual(before.traffic);
	});
	it("counts direct scoped organization creation/deletion but never equates an admin creation with activity", async () => {
		await sql`INSERT INTO organization (id,name,slug,"createdAt") VALUES ('member-org','Member org','member-org',${stamp(-60)}),('created-by-admin','Admin creation','created-by-admin',${stamp(-2)}),('deleted-org','Deleted org','deleted-org',${stamp(-2)})`.execute(database);
		await activity("organizations", "member-org", -10); await activity("organizations", "member-org", -2);
		await sql`DELETE FROM organization WHERE id='deleted-org'`.execute(database);
		const result = await queryControlAnalytics(database, filters({ entity: "organizations" }));
		expect(result.metrics.active.value).toBe(1); expect(result.metrics.new.value).toBe(2); expect(result.metrics.retained.value).toBe(1); expect(result.metrics.all.value).toBe(2);
		expect(result.series.every((point) => point.signIns === null)).toBe(true);
		const members = await queryControlAnalyticsEntities(database, entityFilters("new", { entity: "organizations" }));
		expect(members.entities.map((entry) => entry.id).sort()).toEqual(["created-by-admin", "deleted-org"]);
	});
	it("daily, Monday-week and calendar-month charts drill down to the same exact cohort members", async () => {
		await seed();
		for (const bucket of ["day", "week", "month"] as const) {
			const result = await queryControlAnalytics(database, filters({ range: "30d", bucket }));
			for (const point of result.series) {
				for (const cohort of ["active", "new", "retained", "reactivated", "churned", "firstActive", "unknown"] as const) {
					const members = await queryControlAnalyticsEntities(database, entityFilters(cohort, { from: point.from, to: point.to }));
					expect(members.total, `${bucket} ${point.from} ${cohort}`).toBe(point.observed[cohort]);
				}
			}
			expect(result.series[0].from).toBe(result.window.from); expect(result.series.at(-1)?.to).toBe(result.window.to);
		}
	});
	it("bounds search, pagination and six-month aggregation without leaking fields or another realm", async () => {
		await seed();
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","createdAt","updatedAt") VALUES ('other-realm','Other Realm','other@fixture.example',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`.execute(other);
		const first = await queryControlAnalyticsEntities(database, entityFilters("active", { limit: 2 }));
		const next = await queryControlAnalyticsEntities(database, entityFilters("active", { limit: 2, offset: 2 }));
		expect(first.total).toBe(6); expect(new Set([...first.entities, ...next.entities].map((entry) => entry.id)).size).toBe(4);
		for (const q of ["' OR 1=1 --", "%", "other-realm"]) expect((await queryControlAnalyticsEntities(database, entityFilters("all", { q }))).total).toBe(0);
		const start = performance.now(); const queryCount = analyticsQueries;
		const result = await queryControlAnalytics(database, filters({ range: "6m" }));
		expect(result.series.length).toBeGreaterThanOrEqual(181); expect(result.series.length).toBeLessThanOrEqual(184);
		expect(analyticsQueries - queryCount).toBe(4); expect(performance.now() - start).toBeLessThan(2000);
		benchmarks.push({ description: "Six-month daily chart and cohorts", entities: 8, dailyRows: 9, buckets: result.series.length, queries: analyticsQueries - queryCount, milliseconds: Math.round(performance.now() - start) });
		expect(JSON.stringify((await queryControlAnalyticsEntities(database, entityFilters("all"))).entities)).not.toMatch(/privateMetadata|password|session|token|analytics-private-profile|other@fixture/);
	});
	it("aggregates a real 2000-identity / 28000-day-row workload with bounded SQL round trips", async () => {
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","createdAt","updatedAt") SELECT 'load-'||g::text,'Load fixture','load-'||g::text||'@fixture.example',true,${stamp(-45)},CURRENT_TIMESTAMP FROM generate_series(1,2000) g`.execute(database);
		await sql`INSERT INTO "allauthAnalyticsActivity" ("entityType","entityId",day,sources) SELECT 'users','load-'||g::text,${day()}::date+d,2 FROM generate_series(1,2000) g CROSS JOIN generate_series(-14,-1) d`.execute(database);
		const start = performance.now(); const before = analyticsQueries;
		const result = await queryControlAnalytics(database, filters({ range: "6m" }));
		const duration = Math.round(performance.now() - start);
		expect(result.metrics.active.value).toBe(2000); expect(result.metrics.all.value).toBe(2000); expect(result.series.at(-1)?.observed.retained).toBe(2000);
		expect(analyticsQueries - before).toBe(4); expect(duration).toBeLessThan(3000);
		benchmarks.push({ description: "Six-month daily chart over 2000 identities and 28000 durable daily activity rows", entities: 2000, dailyRows: 28000, buckets: result.series.length, queries: analyticsQueries - before, milliseconds: duration });
	});
	it("deduplicates concurrent polling to one daily write, merges source bits and caps memory across user floods", async () => {
		await user("polling", -20);
		const recorder = createActivityRecorder(database, 3);
		const before = analyticsQueries;
		const results = await Promise.all(Array.from({ length: 1000 }, () => recorder.record("users", "polling", 2)));
		expect(results.filter(Boolean)).toHaveLength(1); expect(analyticsQueries - before).toBe(1);
		expect(await recorder.record("users", "polling", 4)).toBe(true);
		const row = (await sql<{ sources: number }>`SELECT sources FROM "allauthAnalyticsActivity" WHERE "entityId"='polling'`.execute(database)).rows[0]; expect(row.sources).toBe(6);
		for (let index = 0; index < 8; index++) { await user(`flood-${index}`, -20); await recorder.record("users", `flood-${index}`, 2); }
		expect(recorder.cachedKeys()).toBe(3); expect(await recorder.record("users", "polling", 2)).toBe(false);
	});
	it("collects actual native sign-in/get-session activity, excludes revoked sessions and admin explorer reads", async () => {
		const owner = await nativeUser("admin");
		await sql`TRUNCATE "allauthAnalyticsActivity"`.execute(database);
		await instance.auth.api.controlAnalytics!({ headers: owner.headers, query: { range: "7d" } });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity"`.execute(database)).rows).toHaveLength(0);
		await instance.auth.api.getSession({ headers: owner.headers });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity" WHERE "entityId"=${owner.id} AND sources=2`.execute(database)).rows).toHaveLength(1);
		await sql`DELETE FROM session WHERE "userId"=${owner.id}`.execute(database); await sql`TRUNCATE "allauthAnalyticsActivity"`.execute(database);
		const cold = await makeInstance(); await cold.auth.api.getSession({ headers: owner.headers });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity"`.execute(database)).rows).toHaveLength(0);
	});
	it("validates current organization membership before attributing session activity", async () => {
		const member = await nativeUser();
		const organizationResult = await instance.auth.api.createOrganization({ headers: member.headers, body: { name: "Actual native org", slug: randomUUID() } });
		if (!organizationResult) throw new Error("Native organization creation returned no organization.");
		await instance.auth.api.setActiveOrganization({ headers: member.headers, body: { organizationId: organizationResult.id } });
		await instance.auth.api.getSession({ headers: member.headers });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity" WHERE "entityType"='organizations' AND "entityId"=${organizationResult.id}`.execute(database)).rows).toHaveLength(1);
		await sql`DELETE FROM member WHERE "userId"=${member.id}`.execute(database); await sql`TRUNCATE "allauthAnalyticsActivity"`.execute(database);
		const cold = await makeInstance(); await cold.auth.api.getSession({ headers: member.headers });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity" WHERE "entityType"='organizations'`.execute(database)).rows).toHaveLength(0);
	});
	it("actual native failed sign-ins count attempts without exposing account existence or creating activity", async () => {
		const person = await nativeUser();
		await sql`TRUNCATE "allauthAnalyticsActivity","allauthAnalyticsDaily","allauthEvent"`.execute(database);
		const wrongPassword = `Wrong-${randomUUID()}`;
		const existing = await instance.auth.api.signInEmail({ body: { email: person.email, password: wrongPassword }, asResponse: true });
		const absent = await instance.auth.api.signInEmail({ body: { email: `${randomUUID()}@absent-fixture.example`, password: wrongPassword }, asResponse: true });
		expect(existing.status).toBe(absent.status); expect(existing.status).toBeGreaterThanOrEqual(400); expect(await existing.json()).toEqual(await absent.json());
		const result = await queryControlAnalytics(database, filters({ end: day() }));
		expect(result.traffic).toMatchObject({ signIns: { value: 0 }, failedSignIns: { value: 2 } }); expect(result.metrics.active.value).toBe(0);
		const events = (await sql<Record<string, unknown>>`SELECT * FROM "allauthEvent" WHERE type='auth.sign-in' AND outcome='failure'`.execute(database)).rows;
		expect(events).toHaveLength(2); expect(events.every((event) => event.userId === null && event.actorId === null)).toBe(true); expect(JSON.stringify(events)).not.toContain(wrongPassword); expect(JSON.stringify(events)).not.toContain(person.email);
	});
	it("native analytics requires fresh verified admin authority and never serializes native tokens", async () => {
		const owner = await nativeUser("admin");
		const response = await instance.auth.api.controlAnalyticsEntities!({ headers: owner.headers, query: { cohort: "all" }, asResponse: true });
		expect(response.status).toBe(200); expect(response.headers.get("cache-control")).toBe("no-store"); expect(await response.text()).not.toMatch(/token|password|privateMetadata/);
		await sql`UPDATE "user" SET role='user' WHERE id=${owner.id}`.execute(database);
		await expect(instance.auth.api.controlAnalytics!({ headers: owner.headers, query: {} })).rejects.toMatchObject({ statusCode: 403 });
		await sql`UPDATE "user" SET role='admin',"emailVerified"=false WHERE id=${owner.id}`.execute(database);
		await expect(instance.auth.api.controlAnalyticsEntities!({ headers: owner.headers, query: {} })).rejects.toMatchObject({ statusCode: 403 });
		await expect(instance.auth.api.controlAnalytics!({ headers: new Headers(), query: {} })).rejects.toMatchObject({ statusCode: 401 });
	});
	it("preserves the unavailable result when analytics collection has no coverage record", async () => {
		const owner = await nativeUser("admin");
		const { rows: [coverage] } = await sql<{ startedAt: Date }>`
			DELETE FROM "allauthAnalyticsCoverage" WHERE id='native-v1' RETURNING "startedAt"
		`.execute(database);
		const message = "Analytics collection has not been initialized.";
		try {
			await expect(queryControlAnalytics(database, filters())).rejects.toMatchObject({
				statusCode: 503,
				message,
			});
			const response = await instance.auth.api.controlAnalytics!({
				headers: owner.headers,
				query: {},
				asResponse: true,
			});
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ message });
		} finally {
			await sql`INSERT INTO "allauthAnalyticsCoverage" (id,"startedAt") VALUES ('native-v1',${coverage.startedAt})`.execute(database);
		}
	});
	it("excludes actual native anonymous and administrator impersonation sessions", async () => {
		const guest = await instance.auth.api.signInAnonymous({ asResponse: true });
		const guestCookies = parseSetCookieHeader(guest.headers.get("set-cookie") || "");
		const guestHeaders = new Headers({ cookie: [...guestCookies].map(([name,value]) => `${name}=${value.value}`).join("; ") });
		await instance.auth.api.getSession({ headers: guestHeaders });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity"`.execute(database)).rows).toHaveLength(0);
		const owner = await nativeUser("admin"); const target = await nativeUser();
		await sql`TRUNCATE "allauthAnalyticsActivity","allauthAnalyticsDaily"`.execute(database);
		const impersonation = await instance.auth.api.impersonateUser({ headers: owner.headers, body: { userId: target.id }, asResponse: true });
		expect(impersonation.status).toBe(200);
		const impersonationCookies = parseSetCookieHeader(impersonation.headers.get("set-cookie") || "");
		const acting = new Headers({ origin: "http://localhost:3000", cookie: [...impersonationCookies].map(([name,value]) => `${name}=${value.value}`).join("; ") });
		expect((await instance.auth.api.getSession({ headers: acting }))?.user.id).toBe(target.id);
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity"`.execute(database)).rows).toHaveLength(0); expect((await sql`SELECT 1 FROM "allauthAnalyticsDaily"`.execute(database)).rows).toHaveLength(0);
	});
	it("does not mark a real native MFA provisional session as completed sign-in or active", async () => {
		const person = await nativeUser();
		await sql`UPDATE "user" SET "twoFactorEnabled"=true WHERE id=${person.id}`.execute(database);
		await sql`TRUNCATE "allauthAnalyticsActivity","allauthAnalyticsDaily"`.execute(database);
		const challenge = await instance.auth.api.signInEmail({ headers: person.headers, body: { email: person.email, password: person.password }, asResponse: true });
		expect(challenge.status).toBe(200); expect(await challenge.json()).toMatchObject({ twoFactorRedirect: true });
		expect((await sql`SELECT 1 FROM "allauthAnalyticsActivity"`.execute(database)).rows).toHaveLength(0); expect((await sql`SELECT 1 FROM "allauthAnalyticsDaily"`.execute(database)).rows).toHaveLength(0);
	});
});
