import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout } from "node:timers/promises";
import { promisify } from "node:util";
import { getCookies } from "better-auth/cookies";
import { clerkCompatiblePasswords } from "../../lib/clerk-password";
import { signEdgeRequest } from "../../lib/domains/edge";
import { platformWorkspaceId } from "../../lib/workspaces/types";
import { createRailwayProjectEngineTransport } from "./railway-project-engine-transport";

const execute = promisify(execFile);
const [target, argument] = process.argv.slice(2);
const internalSelection = target === "--internal";
if (target === "--railway")
	assert.ok(argument, "Pass the isolated Railway fixture profile.");
const railway =
	target === "--railway" && argument
		? await createRailwayProjectEngineTransport(argument)
		: undefined;
const [releaseImage, rehearsalImage] = railway
	? ["release", "candidate"]
	: internalSelection
		? [argument, argument]
		: [target, argument];
assert.ok(
	releaseImage && rehearsalImage,
	"Pass the normal release and project-engine-rehearsal Docker images.",
);
if (!internalSelection) assert.notEqual(releaseImage, rehearsalImage);
const run = randomUUID().replaceAll("-", "");
const network = `allauth-engine-rehearsal-${run}`;
const database = `${network}-db`;
const application = `${network}-app`;
const source = railway?.profile.source ?? `allauth_engine_rehearsal_${run}`;
const restored =
	railway?.profile.restored ??
	`allauth_engine_rehearsal_${randomUUID().replaceAll("-", "")}`;
const authSecret =
	railway?.profile.authSecret ?? randomBytes(32).toString("hex");
const edgeSecret =
	railway?.profile.edgeSecret ?? randomBytes(32).toString("hex");
const credentialSecret = randomBytes(32).toString("hex");
const databasePassword = randomBytes(32).toString("hex");
const databaseNonce =
	railway?.profile.databaseNonce ?? randomBytes(32).toString("hex");
const platform = railway
	? `https://${railway.profile.domain}`
	: "https://project-engine-rehearsal.invalid";
const portalDomain = "allauth.example.com";
const customDomain = "project-engine-rehearsal.example.com";
const host = `accounts.${customDomain}`;
const oldPassword = `Rehearsal-original-${randomUUID()}!`;
const newPassword = `Rehearsal-updated-${randomUUID()}!`;
const accountId = randomUUID();
const accountEmail = "account@project-engine-rehearsal.invalid";

interface Realm {
	id: string;
	slug: string;
	workspaceId: string;
	applicationId: string;
	primaryOrigin: string;
	environment: string;
	proxyVersion: string;
}

async function docker(...args: string[]) {
	return (
		await execute("docker", args, { maxBuffer: 2_097_152, timeout: 60_000 })
	).stdout.trim();
}

async function query(db: string, sql: string) {
	if (railway) return railway.query(db, sql);
	return docker(
		"exec",
		database,
		"psql",
		"-X",
		"-U",
		"postgres",
		"-d",
		db,
		"-v",
		"ON_ERROR_STOP=1",
		"-tAq",
		"-c",
		sql,
	);
}

async function until(check: () => Promise<boolean>, description: string) {
	for (let attempt = 0; attempt < 60; attempt++) {
		try {
			if (await check()) return;
		} catch {
			// A newly started fixture process may not accept connections yet.
		}
		await setTimeout(250);
	}
	throw new Error(description);
}

function environment(db: string, values: Record<string, string> = {}) {
	return Object.entries({
		DATABASE_URL: `postgresql://postgres:${databasePassword}@${database}:5432/${db}`,
		ALLAUTH_AUTH_URL: platform,
		ALLAUTH_AUTH_SECRET: authSecret,
		SCIM_CREDENTIAL_HASH_SECRET: credentialSecret,
		ALLAUTH_EDGE_SECRET: edgeSecret,
		ALLAUTH_HOSTING_BASE_DOMAIN: portalDomain,
		CLOUDFLARE_SAAS_READY: "true",
		CLOUDFLARE_SAAS_ZONE_ID: run,
		CLOUDFLARE_SAAS_API_TOKEN: "disposable-hostname-fixture",
		CLOUDFLARE_SAAS_CNAME_TARGET: "ingress.example.com",
		...values,
	}).flatMap(([key, value]) => ["-e", `${key}=${value}`]);
}

async function request(
	path: string,
	{
		body,
		cookie,
		realm,
		host,
		clientIP = "192.0.2.54",
	}: {
		body?: object;
		cookie?: string;
		realm?: Realm;
		host?: string;
		clientIP?: string;
	} = {},
) {
	const method = body ? "POST" : "GET";
	const data = body ? JSON.stringify(body) : "";
	const headers = new Headers({
		origin: host ? `https://${host}` : (realm?.primaryOrigin ?? platform),
		...(body ? { "content-type": "application/json" } : {}),
		...(cookie ? { cookie } : {}),
	});
	let ingress = headers;
	if (host) {
		ingress = await signEdgeRequest(
			new Request(`${platform}${path}`, {
				method,
				headers,
				body: data || undefined,
			}),
			edgeSecret,
			host,
			clientIP,
		);
	} else if (realm) {
		const time = String(Math.floor(Date.now() / 1000));
		const key = createHmac("sha256", authSecret)
			.update(`allauth:proxy:${realm.id}:${realm.proxyVersion}`)
			.digest("hex");
		const digest = createHash("sha256").update(data).digest("hex");
		ingress.set("allauth-proxy-timestamp", time);
		ingress.set("allauth-proxy-origin", realm.primaryOrigin);
		ingress.set("allauth-proxy-ip", clientIP);
		ingress.set(
			"allauth-proxy-signature",
			createHmac("sha256", key)
				.update(
					[time, method, path, realm.primaryOrigin, clientIP, digest].join(
						"\n",
					),
				)
				.digest("hex"),
		);
	} else if (!railway) {
		ingress.set("x-real-ip", clientIP);
	}
	if (railway) {
		const response = await fetch(`${platform}${path}`, {
			method,
			headers: ingress,
			body: data || undefined,
			redirect: "manual",
			signal: AbortSignal.timeout(15_000),
		});
		return {
			status: response.status,
			cookies: response.headers.getSetCookie(),
			body: await response.text(),
		};
	}
	ingress.set("host", new URL(platform).hostname);
	ingress.set("x-forwarded-proto", "https");
	// Use the container's loopback only. The fixture network and listener have no public ingress.
	const serialized = await docker(
		"exec",
		application,
		"node",
		"--input-type=module",
		"-e",
		`
		const { path, method, headers, body } = JSON.parse(process.argv[1]);
		const response = await fetch("http://127.0.0.1:3000" + path, {
			method, headers, body, redirect: "manual", signal: AbortSignal.timeout(7000),
		});
		const cookies = response.headers.getSetCookie();
		console.log(JSON.stringify({ status: response.status, cookies, body: await response.text() }));
	`,
		JSON.stringify({
			path,
			method,
			headers: Object.fromEntries(ingress),
			body: data || undefined,
		}),
	);
	return JSON.parse(serialized) as {
		status: number;
		cookies: string[];
		body: string;
	};
}

function expectStatus(
	response: Awaited<ReturnType<typeof request>>,
	status: number,
	action: string,
) {
	assert.equal(response.status, status, action);
}

function sessionCookie(response: Awaited<ReturnType<typeof request>>) {
	const cookie = response.cookies.find(
		(item) => item.includes(".session_token=") && !item.includes("Max-Age=0"),
	);
	assert.ok(cookie, "The compiled route must issue a session cookie.");
	return cookie.split(";", 1)[0];
}

async function start(
	image: string,
	db: string,
	values: Record<string, string> = {},
) {
	if (railway) await railway.start(image, db, values);
	else
		await docker(
			"run",
			"-d",
			"--name",
			application,
			"--network",
			network,
			...environment(db, values),
			image,
		);
	await until(
		async () => (await request("/api/health")).status === 200,
		"The compiled app did not report ready.",
	);
}

async function stop(db: string) {
	if (railway) await railway.stop();
	else {
		await docker("stop", "--time", "10", application);
		await docker("rm", application);
	}
	await until(
		async () =>
			(await query(
				"postgres",
				`SELECT count(*) FROM pg_stat_activity WHERE datname='${db}'`,
			)) === "0",
		"The previous phase retained a PostgreSQL connection.",
	);
}

async function seed() {
	const user = randomUUID();
	const token = randomBytes(32).toString("hex");
	await query(
		source,
		`
		INSERT INTO public."user" (id,name,email,"emailVerified",role)
		VALUES ('${user}','Fixture Owner','owner@project-engine-rehearsal.invalid',true,'admin');
		INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt")
		VALUES ('${randomUUID()}','${token}','${user}',now()+interval '1 hour',now());
	`,
	);
	const require = createRequire(import.meta.resolve("@better-auth/core"));
	const { serializeSignedCookie } = await import(
		require.resolve("better-call")
	);
	const definition = getCookies({ baseURL: platform }).sessionToken;
	const signed: string = await serializeSignedCookie(
		definition.name,
		token,
		authSecret,
		definition.attributes,
	);
	const cookie = signed.split(";", 1)[0];
	async function createFixtureWorkspace() {
		const response = await request("/api/workspaces", {
			cookie,
			body: {
				name: "Project Engine Rehearsal",
				slug: "compiled-engine-rehearsal",
			},
		});
		expectStatus(
			response,
			201,
			"Create a workspace through the compiled platform.",
		);
		return (JSON.parse(response.body) as { workspace: { id: string } })
			.workspace.id;
	}
	const workspaceId = internalSelection
		? platformWorkspaceId
		: await createFixtureWorkspace();
	assert.match(workspaceId, /^[a-f0-9-]{36}$/);
	async function create(slug: string, env: string, applicationId?: string) {
		const response = await request("/api/admin/projects", {
			cookie,
			body: {
				name: slug,
				slug,
				primaryOrigin: `https://${slug}.project-engine-rehearsal.invalid`,
				origins: [],
				workspaceId,
				environment: env,
				...(applicationId ? { applicationId } : {}),
			},
		});
		expectStatus(
			response,
			201,
			"Provision the realm through the compiled platform.",
		);
		const { project } = JSON.parse(response.body) as { project: Realm };
		assert.match(project.id, /^[a-f0-9-]{36}$/);
		assert.equal(project.environment, env);
		assert.equal(project.workspaceId, workspaceId);
		const schema = `allauth_project_${project.id.replaceAll("-", "")}`;
		const password = await clerkCompatiblePasswords.hash(oldPassword);
		assert.match(password, /^[0-9a-f]+:[0-9a-f]+$/);
		await query(
			source,
			`
			INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role)
			VALUES ('${accountId}','Fixture Account','${accountEmail}',true,'user');
			INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt")
			VALUES ('${accountId}','${accountId}','credential','${accountId}','${password}',now());
		`,
		);
		const proxyVersion = await query(
			source,
			`SELECT "proxyVersion" FROM public."allauthProject" WHERE id='${project.id}'`,
		);
		assert.match(proxyVersion, /^[a-f0-9-]{36}$/);
		return { ...project, proxyVersion };
	}
	const control = await create("compiled-engine-control", "production");
	const owned = await create(
		"compiled-engine-owned",
		"development",
		control.applicationId,
	);
	const pairId = randomUUID();
	await query(
		source,
		`
		INSERT INTO public."allauthDomainPair" (id,"projectId",domain,"createdBy")
		VALUES ('${pairId}','${owned.id}','${customDomain}','${user}');
		INSERT INTO public."allauthCustomHostname"
		(id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerId","providerStatus","sslStatus","routingVerifiedAt")
		VALUES
		 ('${randomUUID()}','${pairId}','${owned.id}','accounts','${host}','${randomUUID()}',now(),'${randomUUID()}','active','active',now()),
		 ('${randomUUID()}','${pairId}','${owned.id}','frontend-api','api.${customDomain}','${randomUUID()}',now(),'${randomUUID()}','active','active',now());
	`,
	);
	return { owned, control, rootCookie: cookie };
}

let networkCreated = false;
try {
	if (!railway) {
		await docker("network", "create", "--internal", network);
		networkCreated = true;
		await docker(
			"run",
			"-d",
			"--name",
			database,
			"--network",
			network,
			"-e",
			`POSTGRES_PASSWORD=${databasePassword}`,
			"-e",
			`POSTGRES_DB=${source}`,
			"postgres:18-alpine",
		);
		await until(
			async () =>
				(
					await docker(
						"exec",
						database,
						"pg_isready",
						"-h",
						"127.0.0.1",
						"-d",
						source,
					)
				).endsWith("accepting connections"),
			"The isolated fixture database did not start.",
		);
		await docker(
			"run",
			"--rm",
			"--network",
			network,
			...environment(source),
			releaseImage,
			"node",
			"scripts/database.mjs",
			"migrate",
		);
	}
	await start(releaseImage, source);
	const { owned, control, rootCookie } = await seed();
	const direct = `/api/projects/${owned.slug}/auth`;
	const controlPath = `/api/projects/${control.slug}/auth`;
	const selected = {
		ALLAUTH_REHEARSAL_PROJECT_ID: owned.id,
		ALLAUTH_REHEARSAL_WORKSPACE_ID: owned.workspaceId,
		ALLAUTH_REHEARSAL_DATABASE_NONCE: databaseNonce,
	};
	const login = { email: accountEmail, password: oldPassword };
	const original = await request(`${direct}/sign-in/email`, {
		realm: owned,
		body: login,
	});
	expectStatus(
		original,
		200,
		"Native sign-in through the signed project proxy.",
	);
	const originalCookie = sessionCookie(original);
	const originalHosted = await request("/api/auth/sign-in/email", {
		host,
		body: login,
	});
	expectStatus(
		originalHosted,
		200,
		"Native sign-in through the verified hosted binding.",
	);
	const originalHostedCookie = sessionCookie(originalHosted);
	expectStatus(
		await request(`${direct}/not-installed`, { realm: owned }),
		404,
		"The baseline writer is legacy.",
	);
	await stop(source);
	await query(
		"postgres",
		`CREATE DATABASE "${restored}" WITH TEMPLATE "${source}"`,
	);
	await query(
		restored,
		`
		CREATE TABLE public."allauthEngineRehearsal" ("projectId" text PRIMARY KEY, "workspaceId" text NOT NULL, "nonceHash" text NOT NULL);
		INSERT INTO public."allauthEngineRehearsal" VALUES ('${owned.id}','${owned.workspaceId}','${createHash("sha256").update(databaseNonce).digest("hex")}');
	`,
	);

	async function checkInvalidMarker() {
		expectStatus(
			await request(`${direct}/get-session`, {
				realm: owned,
				cookie: originalCookie,
			}),
			503,
			"The selected realm rejects an invalid database marker.",
		);
		expectStatus(
			await request(`${controlPath}/not-installed`, { realm: control }),
			404,
			"A failed selection does not change its sibling.",
		);
	}
	if (!railway && !internalSelection) {
		await start(rehearsalImage, restored);
		expectStatus(
			await request(`${direct}/not-installed`, { realm: owned }),
			404,
			"The rehearsal image defaults to the legacy writer.",
		);
		await stop(restored);
		await start(rehearsalImage, restored, {
			...selected,
			ALLAUTH_REHEARSAL_DATABASE_NONCE: randomBytes(32).toString("hex"),
		});
		await checkInvalidMarker();
		await stop(restored);
	}

	async function currentSession(
		path: string,
		options: Parameters<typeof request>[1],
	) {
		const response = await request(path, options);
		expectStatus(
			response,
			200,
			"Read a live session through the compiled route.",
		);
		return (
			(JSON.parse(response.body) as { user: { id: string } } | null)?.user.id ??
			null
		);
	}

	if (internalSelection) {
		await start(releaseImage, restored, {
			ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: owned.id,
			EMAIL_PROVIDER: "cloudflare",
			EMAIL_FROM: "security@project-engine-rehearsal.invalid",
			CLOUDFLARE_ACCOUNT_ID: run,
			CLOUDFLARE_EMAIL_API_TOKEN: run,
		});
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host }),
			200,
			"The internal realm uses the first-party hosted API.",
		);
	} else {
		await start(rehearsalImage, restored, selected);
	}
	if (railway) {
		const marker = createHash("sha256").update(databaseNonce).digest("hex");
		await query(
			restored,
			`UPDATE public."allauthEngineRehearsal" SET "nonceHash"='${randomBytes(32).toString("hex")}'`,
		);
		try {
			await checkInvalidMarker();
		} finally {
			await query(
				restored,
				`UPDATE public."allauthEngineRehearsal" SET "nonceHash"='${marker}'`,
			);
		}
	}
	const ownedDispatch = await request(`${direct}/not-installed`, {
		realm: owned,
	});
	expectStatus(ownedDispatch, 501, "The direct route dispatches to AllAuth.");
	assert.equal(
		JSON.parse(ownedDispatch.body).code,
		"ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
	);
	expectStatus(
		await request("/api/auth/not-installed", { host }),
		501,
		"The verified hosted route dispatches to AllAuth.",
	);
	expectStatus(
		await request(`${controlPath}/not-installed`, { realm: control }),
		404,
		"The sibling realm remains on legacy.",
	);
	expectStatus(
		await request("/api/auth/not-installed"),
		404,
		"The shared platform remains on legacy.",
	);
	assert.ok(
		await currentSession("/api/auth/get-session", { cookie: rootCookie }),
		"The platform owner retains their original session.",
	);
	assert.equal(
		await currentSession(`${direct}/get-session`, {
			realm: owned,
			cookie: originalCookie,
		}),
		accountId,
	);
	assert.equal(
		await currentSession("/api/auth/get-session", {
			host,
			cookie: originalHostedCookie,
		}),
		accountId,
	);
	assert.equal(
		await currentSession(`${controlPath}/get-session`, {
			realm: control,
			cookie: originalCookie,
		}),
		null,
	);
	const fixturePassword = internalSelection ? oldPassword : newPassword;
	async function switchDirectSession() {
		if (internalSelection) {
			const signedOut = await request("/api/auth/sign-out", {
				host,
				cookie: originalHostedCookie,
				body: {},
			});
			expectStatus(
				signedOut,
				200,
				"The AllAuth writer revokes the original hosted session.",
			);
			const loginResponse = await request(`${direct}/sign-in/email`, {
				realm: owned,
				body: login,
			});
			expectStatus(
				loginResponse,
				200,
				"The internal project signs in through the AllAuth writer.",
			);
			return sessionCookie(loginResponse);
		}
		const changed = await request(`${direct}/change-password`, {
			realm: owned,
			cookie: originalCookie,
			body: {
				currentPassword: oldPassword,
				newPassword,
				revokeOtherSessions: true,
			},
		});
		expectStatus(
			changed,
			200,
			"Change the legacy password through the owned writer.",
		);
		assert.equal(
			await currentSession("/api/auth/get-session", {
				host,
				cookie: originalHostedCookie,
			}),
			null,
		);
		return sessionCookie(changed);
	}
	const ownedCookie = await switchDirectSession();
	const ownedHosted = await request("/api/auth/sign-in/email", {
		host,
		body: { ...login, password: fixturePassword },
	});
	expectStatus(ownedHosted, 200, "The AllAuth hosted route signs in.");
	const ownedHostedCookie = sessionCookie(ownedHosted);
	const createdKey = await request("/api/auth/api-key/create", {
		host,
		cookie: ownedHostedCookie,
		body: { name: "Compiled fixture key" },
	});
	expectStatus(
		createdKey,
		200,
		"Create a personal key through the compiled hosted route.",
	);
	const { id: keyId } = JSON.parse(createdKey.body) as { id: string };
	assert.ok(keyId);
	const keyQuery = new URLSearchParams({ id: keyId });
	async function checkKey(
		path: string,
		options: Parameters<typeof request>[1],
	) {
		const response = await request(`${path}/api-key/get?${keyQuery}`, options);
		expectStatus(
			response,
			200,
			"The verified request must retain the key ID query parameter.",
		);
		assert.equal(JSON.parse(response.body).id, keyId);
	}
	await checkKey(direct, { realm: owned, cookie: ownedCookie });
	await checkKey("/api/auth", { host, cookie: ownedHostedCookie });
	await stop(restored);

	await start(releaseImage, restored, selected);
	expectStatus(
		await request(`${direct}/not-installed`, { realm: owned }),
		404,
		"The normal image rolls the project back to legacy.",
	);
	expectStatus(
		await request("/api/auth/not-installed", { host }),
		404,
		"The restored hosted route rolls back to native.",
	);
	assert.equal(
		await currentSession(`${direct}/get-session`, {
			realm: owned,
			cookie: ownedCookie,
		}),
		accountId,
	);
	assert.equal(
		await currentSession("/api/auth/get-session", {
			host,
			cookie: ownedHostedCookie,
		}),
		accountId,
	);
	await checkKey("/api/auth", { host, cookie: ownedHostedCookie });
	assert.equal(
		await currentSession("/api/auth/get-session", {
			host,
			cookie: originalHostedCookie,
		}),
		null,
	);
	expectStatus(
		await request(`${direct}/sign-in/email`, {
			realm: owned,
			body: { ...login, password: fixturePassword },
		}),
		200,
		"Native reads the project password after rollback.",
	);
	if (!internalSelection) {
		expectStatus(
			// A second synthetic browser has its own admission bucket.
			await request(`${direct}/sign-in/email`, {
				realm: owned,
				body: login,
				clientIP: "192.0.2.55",
			}),
			401,
			"Rollback retains password revocation.",
		);
	}
	expectStatus(
		await request(`${controlPath}/sign-in/email`, {
			realm: control,
			body: login,
		}),
		200,
		"The sibling realm retains its password.",
	);
	await stop(restored);
	console.log(
		internalSelection
			? "Compiled internal project selection passed from legacy to AllAuth and back."
			: "Compiled project rehearsal passed from legacy to AllAuth and back.",
	);
} finally {
	await railway?.stop();
	if (networkCreated) {
		await docker("rm", "-f", application, database).catch(() => undefined);
		await docker("network", "rm", network);
	}
}
