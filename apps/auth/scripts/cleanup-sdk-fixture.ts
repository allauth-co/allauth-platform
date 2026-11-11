import assert from "node:assert/strict";
import { readFileSync, unlinkSync } from "node:fs";
import { Pool } from "pg";
import { checkedProjectSchema } from "../lib/projects/validation";

/** Remove the exact retained browser fixtures from the isolated local database. */
const path = new URL("../../../.secrets/sdk-browser-qa.json", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("../../../.secrets/local-postgres.json", import.meta.url), "utf8")) as { container: string; DATABASE_URL: string };
const url = new URL(fixture.DATABASE_URL);
assert.ok(fixture.container === "allauth-production-test-20261007" && url.hostname === "127.0.0.1" && url.port === "55445", "Cleanup refuses a non-fixture database.");
assert.ok(!process.env.DATABASE_URL || process.env.DATABASE_URL === fixture.DATABASE_URL, "Cleanup refuses another configured database.");
const qa = JSON.parse(readFileSync(path, "utf8")) as { version: number; databaseFixtureContainer: string; databaseFixtureHost: string; cleanup: { project: { id: string; slug: string; schemaName: string }; brokerClientId: string; rootUserId: string; rootEmail: string; ip: string; counterKeys: string[] } };
assert.ok(qa.version === 1 && qa.databaseFixtureContainer === fixture.container && qa.databaseFixtureHost === "127.0.0.1:55445", "Cleanup journal must match the current local fixture.");
const { project, brokerClientId, rootUserId, rootEmail, ip, counterKeys } = qa.cleanup;
assert.match(project.slug, /^check-[a-f0-9]{16}-1$/);
assert.match(rootEmail, /^project-owner-[a-f0-9]{16}@example\.com$/);
assert.equal(project.slug.slice(6, 22), rootEmail.slice(14, 30), "Fixture ownership markers must match.");
assert.ok(rootUserId && brokerClientId && counterKeys.length === 3);
const pool = new Pool({ connectionString: fixture.DATABASE_URL, max: 1 });
const connection = await pool.connect();
try {
	await connection.query("BEGIN");
	const persisted = (await connection.query<{ schemaName: string; brokerClientId: string; createdBy: string }>('SELECT "schemaName","brokerClientId","createdBy" FROM public."allauthProject" WHERE id=$1 AND slug=$2 FOR UPDATE', [project.id, project.slug])).rows[0];
	assert.ok(!persisted || (persisted.schemaName === project.schemaName && persisted.brokerClientId === brokerClientId && persisted.createdBy === rootUserId), "The current project must still match the exact cleanup journal.");
	const owner = (await connection.query<{ email: string }>('SELECT email FROM public."user" WHERE id=$1', [rootUserId])).rows[0];
	assert.ok(!owner || owner.email === rootEmail, "The current fixture owner must match the journal.");
	await connection.query(`DROP SCHEMA IF EXISTS "${checkedProjectSchema(project.schemaName)}" CASCADE`);
	await connection.query('DELETE FROM public."allauthProject" WHERE id=$1 AND slug=$2', [project.id, project.slug]);
	await connection.query('DELETE FROM public."oauthClient" WHERE "clientId"=$1 AND metadata->>\'allauthProjectBroker\'=$2', [brokerClientId, project.slug]);
	const targets = [rootUserId, project.id, brokerClientId];
	await connection.query('DELETE FROM public."allauthAudit" WHERE "actorId"=ANY($1::text[]) OR "targetId"=ANY($1::text[])', [targets]);
	await connection.query('DELETE FROM public."allauthEvent" WHERE "actorId"=ANY($1::text[]) OR "userId"=ANY($1::text[]) OR "targetId"=ANY($1::text[]) OR "clientId"=ANY($1::text[]) OR "ipAddress"=$2', [targets, ip]);
	await connection.query('DELETE FROM public."user" WHERE id=$1 AND email=$2', [rootUserId, rootEmail]);
	await connection.query('DELETE FROM public."rateLimit" WHERE "key" LIKE $1', [`%${ip}%`]);
	await connection.query('DELETE FROM public."allauthSecurityCounter" WHERE "key"=ANY($1::text[])', [counterKeys]);
	await connection.query("COMMIT");
	unlinkSync(path);
	console.log("Removed the retained local SDK project, its fixture owner, credentials, and cleanup journal.");
} catch (error) {
	await connection.query("ROLLBACK");
	throw error;
} finally { connection.release(); await pool.end(); }
