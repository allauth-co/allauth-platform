import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout } from "node:timers/promises";
import { promisify } from "node:util";
import { getCookies } from "better-auth/cookies";

const execute = promisify(execFile);
const image = process.argv[2] || "allauth-auth:railway";
const suffix = randomUUID().slice(0, 8);
const network = `allauth-container-check-${suffix}`;
const database = `${network}-db`;
const application = `${network}-app`;
const password = randomUUID();
const authSecret = randomUUID();
const variables = [
	"-e",
	`DATABASE_URL=postgresql://postgres:${password}@${database}:5432/allauth`,
	"-e",
	`BETTER_AUTH_SECRET=${authSecret}`,
	"-e",
	`SCIM_CREDENTIAL_HASH_SECRET=${randomUUID()}`,
	"-e",
	"BETTER_AUTH_URL=https://allauth.co",
];
async function docker(args) {
	try {
		return (
			await execute("docker", args, { maxBuffer: 4 * 1024 * 1024 })
		).stdout.trim();
	} catch (error) {
		throw new Error(error.stderr?.trim() || "Docker check command failed");
	}
}
async function waitForDatabase() {
	for (let attempt = 0; attempt < 30; attempt++) {
		try {
			await docker([
				"exec",
				database,
				"pg_isready",
				"-U",
				"postgres",
				"-d",
				"allauth",
			]);
			return;
		} catch {
			await setTimeout(1000);
		}
	}
	throw new Error("The isolated test database did not start");
}
async function query(sql) {
	return docker(["exec", database, "psql", "-U", "postgres", "-d", "allauth", "-v", "ON_ERROR_STOP=1", "-tAX", "-c", sql]);
}
async function checkProjectProvisioning(origin) {
	// These records live only in this script's disposable database. No production
	// owner, password, email delivery, or third-party sign-in participates.
	const userId = randomUUID();
	const sessionId = randomUUID();
	const token = `${randomUUID()}${randomUUID()}`;
	await query(`INSERT INTO public."user" (id,name,email,"emailVerified",role,banned,"twoFactorEnabled") VALUES ('${userId}','Container Fixture','container-fixture@example.invalid',true,'admin',false,false); INSERT INTO public."session" (id,"expiresAt",token,"updatedAt","userId") VALUES ('${sessionId}',NOW()+INTERVAL '10 minutes','${token}',NOW(),'${userId}');`);
	const require = createRequire(import.meta.resolve("@better-auth/core"));
	const { serializeSignedCookie } = await import(require.resolve("better-call"));
	const definition = getCookies({ baseURL: "https://allauth.co" }).sessionToken;
	const signed = await serializeSignedCookie(definition.name, token, authSecret, { ...definition.attributes, maxAge: 600 });
	const cookie = signed.split(";", 1)[0];
	const headers = { origin: "https://allauth.co", cookie, "x-real-ip": "192.0.2.44" };
	const owner = await fetch(`${origin}/api/auth/get-session`, { headers });
	assert.equal(owner.status, 200, "The native signed fixture cookie must authenticate in the compiled image");
	assert.equal((await owner.json())?.user.id, userId);
	const slug = `container-fixture-${suffix}`;
	const projectResponse = await fetch(`${origin}/api/admin/projects`, {
		method: "POST", headers: { ...headers, "content-type": "application/json" },
		body: JSON.stringify({ name: "Container Fixture", slug, primaryOrigin: "https://app.fixture.example", origins: [] }),
	});
	assert.equal(projectResponse.status, 201, "The compiled project route must provision all packaged runtime migrations");
	const { project } = await projectResponse.json();
	assert.equal(project.slug, slug);
	assert.equal(project.primaryOrigin, "https://app.fixture.example");
	assert.match(project.id, /^[a-f\d-]{36}$/);
	assert.equal(project.applicationId, project.id);
	assert.equal(project.environment, "production");
	const schema = await query(`SELECT "schemaName" FROM public."allauthProject" WHERE id='${project.id}'`);
	assert.match(schema, /^allauth_project_[a-f\d]{32}$/);
	assert.equal(await query(`SELECT COUNT(*) FROM "${schema}"."allauthMigrations" WHERE name='005-free-plugins.sql' AND length(checksum)=64`), "1", "The free-plugin migration must be present in a new tenant's ledger");
	for (const name of ["006-analytics.sql", "007-auth-configuration.sql", "008-application-environments.sql"]) {
		assert.equal(await query(`SELECT COUNT(*) FROM "${schema}"."allauthMigrations" WHERE name='${name}' AND length(checksum)=64`), "1", `${name} must be packaged for a fresh environment`);
	}
	const developmentResponse = await fetch(`${origin}/api/admin/projects`, {
		method: "POST", headers: { ...headers, "content-type": "application/json" },
		body: JSON.stringify({ name: "Container Fixture", slug: `${slug}-dev`, primaryOrigin: "http://localhost:3300", origins: [], applicationId: project.applicationId, environment: "development" }),
	});
	assert.equal(developmentResponse.status, 201, "A sibling environment must provision a separate realm");
	const { project: development } = await developmentResponse.json();
	assert.equal(development.applicationId, project.applicationId);
	assert.equal(development.environment, "development");
	const developmentSchema = await query(`SELECT "schemaName" FROM public."allauthProject" WHERE id='${development.id}'`);
	assert.notEqual(developmentSchema, schema);
	assert.equal(await query(`SELECT COUNT(*) FROM "${developmentSchema}"."user"`), "0");
	const duplicateEnvironment = await fetch(`${origin}/api/admin/projects`, {
		method: "POST", headers: { ...headers, "content-type": "application/json" },
		body: JSON.stringify({ name: "Duplicate", slug: `${slug}-duplicate`, primaryOrigin: "http://localhost:3301", origins: [], applicationId: project.applicationId, environment: "development" }),
	});
	assert.equal(duplicateEnvironment.status, 409, "Each application may have only one realm per environment");
	assert.equal(await query('SELECT COUNT(*) FROM public."allauthProject"'), "2", "Rejected duplicate environments must roll back");
	const policyResponse = await fetch(`${origin}/api/admin/configuration?project=${slug}`, { headers });
	assert.equal(policyResponse.status, 200, "The packaged console must read scoped authentication policy");
	const policyBody = await policyResponse.json();
	assert.equal(policyBody.policy.emailAndPasswordEnabled, true);
	const analyticsResponse = await fetch(`${origin}${project.authPath}/control/analytics?entity=users&range=7d&bucket=day`, { headers });
	assert.equal(analyticsResponse.status, 200, "The compiled analytics route must use the isolated realm");
	const analyticsBody = await analyticsResponse.json();
	assert.equal(analyticsBody.entity, "users");
	for (const table of ["deviceCode", "walletAddress", "agentHost", "agent", "agentCapabilityGrant", "approvalRequest"]) {
		assert.equal(await query(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${schema}' AND table_name='${table}'`), "1", `A new tenant must have the ${table} plugin table`);
	}
	assert.equal(await query(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='${schema}' AND table_name='user' AND column_name IN ('username','displayUsername','isAnonymous')`), "3", "A new tenant must have the native free-plugin user fields");
	assert.equal(await query(`SELECT COUNT(*) FROM "${schema}"."user"`), "0", "A fresh project must not copy platform users");
	assert.equal(await query(`SELECT COUNT(*) FROM "${schema}"."session"`), "0", "A fresh project must not copy platform sessions");
	assert.equal(await query('SELECT COUNT(*) FROM public."user"'), "1", "Provisioning must preserve the isolated platform fixture");
	const config = await fetch(`${origin}${project.authPath}/sdk/config`, { headers: { "x-real-ip": "192.0.2.44" } });
	assert.equal(config.status, 200, "The newly provisioned realm must load its packaged native plugins");
	const { branding, ...capabilities } = await config.json();
	assert.deepEqual(capabilities, { emailPassword: true, google: false, organizations: true, twoFactor: true });
	assert.deepEqual(branding, { name: "Container Fixture", supportEmail: null, logoUrl: null, logoDarkUrl: null, faviconUrl: null, primaryColor: "#315bff", darkPrimaryColor: "#7892ff", showPoweredBy: true }, "A new application must expose shared default branding before its first settings write");
	assert.equal(config.headers.get("cache-control"), "no-store");
	const tenantSession = await fetch(`${origin}${project.authPath}/get-session`, { headers });
	assert.equal(tenantSession.status, 200);
	assert.equal(await tenantSession.json(), null, "A platform cookie must never become a tenant session");
	const retainedOwner = await fetch(`${origin}/api/auth/get-session`, { headers });
	assert.equal((await retainedOwner.json())?.user.id, userId, "Realm initialization must preserve platform authentication");
}
try {
	await docker(["network", "create", network]);
	await docker([
		"run",
		"-d",
		"--name",
		database,
		"--network",
		network,
		"-e",
		`POSTGRES_PASSWORD=${password}`,
		"-e",
		"POSTGRES_DB=allauth",
		"postgres:18-alpine",
	]);
	await waitForDatabase();
	await docker([
		"run",
		"-d",
		"--name",
		application,
		"--network",
		network,
		"-p",
		"127.0.0.1::3000",
		...variables,
		image,
	]);
	const origin = `http://${await docker(["port", application, "3000/tcp"])}`;
	for (let attempt = 0; attempt < 30; attempt++) {
		try {
			await fetch(`${origin}/api/health`, {
				signal: AbortSignal.timeout(5000),
			});
			break;
		} catch {
			if (attempt === 29)
				throw new Error("The standalone server did not start");
			await setTimeout(1000);
		}
	}
	const notMigrated = await fetch(`${origin}/api/health`);
	assert.equal(
		notMigrated.status,
		503,
		"An unmigrated database must not be ready",
	);
	assert.deepEqual(await notMigrated.json(), { status: "unavailable" });
	await docker([
		"run",
		"--rm",
		"--network",
		network,
		...variables,
		image,
		"node",
		"scripts/database.mjs",
		"migrate",
	]);
	const ready = await fetch(`${origin}/api/health`);
	assert.equal(ready.status, 200, "The migrated database must be ready");
	assert.deepEqual(await ready.json(), { status: "ok" });
	assert.equal(ready.headers.get("cache-control"), "no-store");
	const signIn = await fetch(`${origin}/sign-in`);
	assert.equal(signIn.status, 200);
	const html = await signIn.text();
	assert.match(html, /AllAuth/);
	const localAsset = html.match(/src="(\/_next\/static\/[^\"]+)"/);
	assert.ok(
		localAsset,
		"The sign-in page must include a compiled client asset",
	);
	assert.equal((await fetch(new URL(localAsset[1], origin))).status, 200);
	const session = await fetch(`${origin}/api/auth/get-session`);
	assert.equal(
		session.status,
		200,
		"Linked auth packages must execute in the image",
	);
	assert.equal(await session.json(), null);
	await checkProjectProvisioning(origin);
	await docker([
		"exec",
		database,
		"psql",
		"-U",
		"postgres",
		"-d",
		"allauth",
		"-c",
		"UPDATE \"allauthMigrations\" SET checksum = 'wrong'",
	]);
	assert.equal(
		(await fetch(`${origin}/api/health`)).status,
		503,
		"A mismatched schema must not be ready",
	);
	console.log(
		"Container checks passed: readiness before/after migration, checksum mismatch, hosted sign-in, static asset, linked auth runtime, native fixture cookie, all eight migrations, isolated application environments, duplicate-environment rollback, scoped configuration and analytics.",
	);
} finally {
	await docker(["rm", "-f", "-v", application, database]).catch(() => {});
	await docker(["network", "rm", network]).catch(() => {});
}
