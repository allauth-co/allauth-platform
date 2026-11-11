import { existsSync, readFileSync } from "node:fs";
import { createHmac, randomUUID } from "node:crypto";
import type { BetterAuthPlugin } from "@better-auth/core";
import { getTestInstance } from "better-auth/test";
import { admin } from "better-auth/plugins";
import { symmetricEncrypt } from "better-auth/crypto";
import { Kysely, PostgresDialect, sql } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { allauthControl, requireControlAdmin } from "./index";
import { recordControlEvent } from "./events";
import { createControlWebhooks, deliverPendingWebhooks, isPublicWebhookAddress, publicWebhookEnvelope, pruneWebhookDeliveries, validateWebhookDestination, webhookSignature } from "./webhooks";

const signingSecret = `whsec_${btoa("s".repeat(32))}`;
describe("webhook signature and destination boundaries", () => {
	it.each(["1.1.1.1","8.8.8.8","93.184.216.34","2606:4700::1111","2001:4860:4860::8888"])("allows public address %s", (address) => expect(isPublicWebhookAddress(address)).toBe(true));
	it.each(["127.0.0.1","0.0.0.0","10.0.0.1","172.16.0.1","192.168.1.1","169.254.169.254","100.64.0.1","192.0.2.1","198.18.0.1","203.0.113.1","224.0.0.1","255.255.255.255","::1","::ffff:127.0.0.1","fe80::1","fc00::1","2001:2::1","2001:db8::1","2002:c0a8:0101::1","3fff::1","64:ff9b::a00:1"])("refuses private/special address %s", (address) => expect(isPublicWebhookAddress(address)).toBe(false));
	it("requires exact public HTTPS URLs and refuses mixed public/private DNS answers", async () => {
		const publicDNS = async () => [{ address: "93.184.216.34", family: 4 }];
		for (const url of ["http://hooks.example.com/", "https://hooks.example.com:8443/", "https://user:pass@hooks.example.com/", "https://localhost/", "https://127.0.0.1/", "https://0x7f000001/", "https://hooks.example.com/#fragment"]) await expect(validateWebhookDestination(url, publicDNS)).rejects.toThrow("INVALID_DESTINATION");
		await expect(validateWebhookDestination("https://hooks.example.com/", async () => [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.1", family: 4 }])).rejects.toThrow("UNSAFE_DESTINATION");
		const destination = await validateWebhookDestination("https://hooks.example.com/receive?version=1", publicDNS); expect(destination).toMatchObject({ address: { address: "93.184.216.34", family: 4 } }); expect(destination.url.hostname).toBe("hooks.example.com");
	});
	it("signs the exact delivery ID, timestamp and payload bytes using Standard Webhooks format", async () => {
		const body = '{"id":"event-one","type":"user.created"}';
		const expected = createHmac("sha256", "s".repeat(32)).update(`delivery-one.1791331200.${body}`).digest("base64");
		expect(await webhookSignature(signingSecret,"delivery-one","1791331200",body)).toBe(`v1,${expected}`);
		expect(await webhookSignature(signingSecret,"delivery-two","1791331200",body)).not.toBe(`v1,${expected}`);
		await expect(webhookSignature("whsec_invalid","one","1",body)).rejects.toThrow();
	});
	it("projects only safe audit/profile snapshots from queued payloads", () => {
		const output = publicWebhookEnvelope({ id: "ignored", secret: "private", data: { event: { id: "event-one", type: "user.created", outcome: "success", createdAt: new Date(), token: "private", metadata: { password: "private", reason: "fixture" } }, user: { id: "user-one", name: "Owner", email: "owner@example.com", emailVerified: true, image: "https://example.com/avatar.png", publicMetadata: { plan: "paid" }, privateMetadata: { secret: "private" }, password: "private", token: "private" } } });
		expect(output.data.user).toMatchObject({ id: "user-one", emailVerified: true, publicMetadata: { plan: "paid" } }); expect(JSON.stringify(output)).not.toMatch(/private|password|token|secret/);
	});
});

const fixturePath = new URL("../../../../.secrets/local-postgres.json", import.meta.url);
describe.skipIf(!existsSync(fixturePath))("PostgreSQL durable signed webhook outbox", () => {
	const schema = `webhook_test_${randomUUID().replaceAll("-","_")}`;
	const secondSchema = `${schema}_second`;
	const secret = "fixture-webhook-encryption-secret-longer-than-thirty-two";
	const origin = "http://localhost:3000";
	const destinationDNS = async () => [{ address: "93.184.216.34", family: 4 }];
	let database: Kysely<Record<string,Record<string,unknown>>>;
	let secondDatabase: Kysely<Record<string,Record<string,unknown>>>;
	let endpointId: string;
	let instance: Awaited<ReturnType<typeof makeInstance>>;
	function makeInstance() {
		const base = allauthControl();
		const webhooks = createControlWebhooks({ database, secret, baseURL: origin, requireAdmin: requireControlAdmin, recordEvent: (ctx,event) => recordControlEvent(ctx,event), resolver: destinationDNS });
		const plugin = { ...base, endpoints: { ...base.endpoints, ...webhooks.endpoints } } satisfies BetterAuthPlugin;
		return getTestInstance({ database: { db: database, type: "postgres", transaction: true }, baseURL: origin, secret, emailAndPassword: { enabled: true, autoSignIn: false }, plugins: [admin(),plugin] }, { disableTestUser: true });
	}
	beforeAll(async () => {
		const fixture: { container: string; DATABASE_URL: string } = JSON.parse(readFileSync(fixturePath,"utf8")); const url = new URL(fixture.DATABASE_URL);
		if (fixture.container!=="allauth-production-test-20261007" || url.hostname!=="127.0.0.1" || url.port!=="55445") throw new Error("Webhook tests require the isolated local AllAuth PostgreSQL container.");
		for (const name of [schema,secondSchema]) {
			const db = new Kysely<Record<string,Record<string,unknown>>>({ dialect: new PostgresDialect({ pool: new Pool({ connectionString: fixture.DATABASE_URL,max:6,options:`-c search_path=${name},public` }) }) });
			await sql`CREATE SCHEMA ${sql.id(name)}`.execute(db);
			for (const migration of ["001-initial-auth.sql","002-control-plane.sql","004-webhooks.sql"]) await sql.raw(readFileSync(new URL(`../../migrations/${migration}`,import.meta.url),"utf8")).execute(db);
			if (name===schema) database=db; else secondDatabase=db;
		}
		instance=await makeInstance();
		await sql`INSERT INTO "user" (id,name,email,"emailVerified","createdAt","updatedAt","privateMetadata","publicMetadata") VALUES ('fixture-user','Fixture User','fixture@example.com',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'{"private":"private-profile"}','{"plan":"paid"}')`.execute(database);
	});
	beforeEach(async () => {
		await sql`TRUNCATE "allauthWebhookDelivery","allauthWebhookEndpoint","allauthEvent"`.execute(database);
		await sql`TRUNCATE "allauthWebhookDelivery","allauthWebhookEndpoint","allauthEvent"`.execute(secondDatabase);
		endpointId=crypto.randomUUID();
		await sql`INSERT INTO "allauthWebhookEndpoint" (id,url,description,"eventTypes","encryptedSecret") VALUES (${endpointId},'https://hooks.example.com/receiver','Fixture','["user.*"]',${await symmetricEncrypt({ key:secret,data:signingSecret })})`.execute(database);
	});
	afterAll(async () => { for (const [db,name] of [[database,schema],[secondDatabase,secondSchema]] as const) if (db) { await sql`DROP SCHEMA IF EXISTS ${sql.id(name)} CASCADE`.execute(db); await db.destroy(); } });
	const event = async (id = crypto.randomUUID(), db=database, type="user.created") => { await sql`INSERT INTO "allauthEvent" (id,type,outcome,"userId","createdAt",metadata) VALUES (${id},${type},'success','fixture-user',CURRENT_TIMESTAMP,'{}')`.execute(db); return id; };
	it("queues subscribed events atomically in the correct project schema and captures only safe profiles", async () => {
		const id=await event(); await event(crypto.randomUUID(),database,"session.created");
		const delivery=(await sql<{ eventId:string;payload:unknown }>`SELECT "eventId",payload FROM "allauthWebhookDelivery"`.execute(database)).rows;
		expect(delivery).toHaveLength(1); expect(delivery[0].eventId).toBe(id); expect(delivery[0].payload).toMatchObject({ data:{ user:{ id:"fixture-user",emailVerified:true,publicMetadata:{ plan:"paid" } } } }); expect(JSON.stringify(delivery)).not.toContain("private-profile");
		await event(crypto.randomUUID(),secondDatabase); expect((await sql`SELECT id FROM "allauthWebhookDelivery"`.execute(secondDatabase)).rows).toHaveLength(0);
		await expect(database.transaction().execute(async (tx) => { await sql`INSERT INTO "allauthEvent" (id,type,outcome,"createdAt",metadata) VALUES ('rolled-back','user.created','success',CURRENT_TIMESTAMP,'{}')`.execute(tx); throw new Error("rollback-fixture"); })).rejects.toThrow("rollback-fixture");
		expect((await sql`SELECT id FROM "allauthWebhookDelivery" WHERE "eventId"='rolled-back'`.execute(database)).rows).toHaveLength(0);
	});
	it("delivers signed exact payloads with pinned destinations and claims once across concurrent workers", async () => {
		await event(); const transport=vi.fn(async () => 204);
		const jobs=await Promise.all([deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport }),deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport })]);
		expect(jobs.reduce((total,job)=>total+job.claimed,0)).toBe(1); expect(transport).toHaveBeenCalledTimes(1);
		const sent=transport.mock.calls[0] as unknown as [{ destination:{ address:{ address:string };url:URL };headers:Record<string,string>;body:string }];
		expect(sent[0].destination.address.address).toBe("93.184.216.34"); expect(sent[0].destination.url.hostname).toBe("hooks.example.com");
		expect(sent[0].headers["webhook-signature"]).toBe(await webhookSignature(signingSecret,sent[0].headers["webhook-id"],sent[0].headers["webhook-timestamp"],sent[0].body));
		expect((await sql`SELECT status,attempts FROM "allauthWebhookDelivery"`.execute(database)).rows[0]).toMatchObject({ status:"delivered",attempts:1 });
	});
	it("revalidates DNS at delivery and never invokes transport for rebinding/private destinations", async () => {
		await event(); const transport=vi.fn(async () => 204);
		expect(await deliverPendingWebhooks({ database,secret,resolver:async()=>[{ address:"169.254.169.254",family:4 }],transport })).toMatchObject({ failed:1,delivered:0 }); expect(transport).not.toHaveBeenCalled();
		expect((await sql`SELECT "lastError" FROM "allauthWebhookDelivery"`.execute(database)).rows[0]).toMatchObject({ lastError:"UNSAFE_DESTINATION" });
	});
	it("refuses redirects and retries transient failures with bounded exponential delay and eight attempts", async () => {
		await event(); const now=new Date(Date.now()+1000); const transport=vi.fn(async()=>503);
		expect(await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport,now:()=>now })).toMatchObject({ retried:1 });
		let row=(await sql<{ attempts:number;nextAttemptAt:Date;status:string }>`SELECT attempts,"nextAttemptAt",status FROM "allauthWebhookDelivery"`.execute(database)).rows[0]; expect(row.attempts).toBe(1); expect(row.nextAttemptAt.getTime()).toBe(now.getTime()+10000);
		expect((await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport,now:()=>now })).claimed).toBe(0);
		await sql`UPDATE "allauthWebhookDelivery" SET attempts=7,"nextAttemptAt"=${now}`.execute(database);
		expect(await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport,now:()=>now })).toMatchObject({ failed:1 });
		expect((await sql`SELECT attempts,status FROM "allauthWebhookDelivery"`.execute(database)).rows[0]).toMatchObject({ attempts:8,status:"failed" });
		await sql`TRUNCATE "allauthWebhookDelivery","allauthEvent"`.execute(database); await event();
		expect(await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport:async()=>302 })).toMatchObject({ failed:1 }); expect((await sql`SELECT "lastError" FROM "allauthWebhookDelivery"`.execute(database)).rows[0]).toMatchObject({ lastError:"REDIRECT_REFUSED" });
	});
	it("recovers only expired processing leases and cleans old delivery snapshots in bounded batches", async () => {
		await event(); await sql`UPDATE "allauthWebhookDelivery" SET status='processing',attempts=1,"lockedUntil"=CURRENT_TIMESTAMP+INTERVAL '1 minute',"leaseId"='previous'`.execute(database);
		expect((await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport:async()=>204 })).claimed).toBe(0);
		await sql`UPDATE "allauthWebhookDelivery" SET "lockedUntil"=CURRENT_TIMESTAMP-INTERVAL '1 minute'`.execute(database);
		expect((await deliverPendingWebhooks({ database,secret,resolver:destinationDNS,transport:async()=>204 })).delivered).toBe(1);
		await sql`UPDATE "allauthWebhookDelivery" SET "createdAt"=CURRENT_TIMESTAMP-INTERVAL '31 days'`.execute(database); expect(await pruneWebhookDeliveries(database)).toBe(1);
	});
	it("requires fresh administrator/same-origin writes and reveals signing secrets only on create/rotate", async () => {
		const signup=await instance.auth.api.signUpEmail({ headers:new Headers({ origin }),body:{ name:"Administrator",email:"webhook-admin@example.com",password:"fixture-webhook-password" } });
		await sql`UPDATE "user" SET "emailVerified"=true WHERE id=${signup.user.id}`.execute(database);
		const login=await instance.signInWithUser("webhook-admin@example.com","fixture-webhook-password"); const headers=login.headers; headers.set("origin",origin);
		await expect(instance.auth.api.controlWebhooks({ headers })).rejects.toMatchObject({ statusCode:403 });
		await sql`UPDATE "user" SET role='admin' WHERE id=${signup.user.id}`.execute(database);
		const create=await instance.auth.api.controlWebhookCreate({ headers,body:{ url:"https://hooks.example.com/receiver",eventTypes:["user.*","session.*","passkey.*","sso.*","api-key.*"] } });
		expect(create.endpoint.eventTypes).toEqual(["user.*","session.*","passkey.*","sso.*","api-key.*"]);
		expect(create.secret).toMatch(/^whsec_/); expect(create.endpoint).not.toHaveProperty("encryptedSecret");
		const listing=await instance.auth.api.controlWebhooks({ headers }); expect(JSON.stringify(listing)).not.toContain(create.secret); expect(JSON.stringify(listing)).not.toContain("encryptedSecret");
		const wrongOrigin=new Headers(headers); wrongOrigin.set("origin","https://attacker.example");
		await expect(instance.auth.api.controlWebhookRotate({ headers:wrongOrigin,body:{ id:create.endpoint.id } })).rejects.toMatchObject({ statusCode:403 });
		const rotated=await instance.auth.api.controlWebhookRotate({ headers,body:{ id:create.endpoint.id } }); expect(rotated.secret).not.toBe(create.secret);
		const history=await instance.auth.api.controlWebhookDeliveries({ headers }); expect(JSON.stringify(history)).not.toMatch(/payload|encryptedSecret|whsec_/);
		await instance.auth.api.controlWebhookDelete({ headers,body:{ id:create.endpoint.id } });
		expect((await instance.auth.api.controlWebhooks({ headers })).endpoints.some((endpoint)=>endpoint.id===create.endpoint.id)).toBe(false);
	});
});
