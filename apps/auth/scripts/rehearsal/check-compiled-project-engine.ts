import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout } from "node:timers/promises";
import { promisify } from "node:util";
import { getCookies } from "better-auth/cookies";
import type { JSONWebKeySet } from "jose";
import { createLocalJWKSet, jwtVerify } from "jose";
import { defaultAuthPolicy } from "../../lib/auth-policy/policy";
import { clerkCompatiblePasswords } from "../../lib/clerk-password";
import { signEdgeRequest } from "../../lib/domains/edge";
import { hostedMagicLinkCallbacks } from "../../lib/domains/hosted-sdk-policy";
import { projectEmailAliasVariable } from "../../lib/project-email-alias-config";
import { signProjectIssuerQuery } from "../../lib/projects/owned-project-issuer-authorization-query";
import { projectSecret } from "../../lib/projects/project-secret";
import { platformWorkspaceId } from "../../lib/workspaces/types";
import {
	developmentAgentReplayBridgeIdsSetting,
	productionAgentReplayBridgeIdsSetting,
} from "../project-agent-replay-evidence.mjs";
import {
	developmentProjectEngineRevisionsSetting,
	productionProjectEngineRevisionsSetting,
} from "../project-engine-rollout-selection.mjs";
import { createRailwayProjectEngineTransport } from "./railway-project-engine-transport";

const execute = promisify(execFile);
const [target, argument] = process.argv.slice(2);
const productionCohort = target === "--production-cohort";
const developmentCohort = target === "--development-cohort";
const enrolledCohort = productionCohort || developmentCohort;
const cohortEnvironment = developmentCohort ? "development" : "production";
const enrolledRevisionsSetting = developmentCohort
	? developmentProjectEngineRevisionsSetting
	: productionProjectEngineRevisionsSetting;
const enrolledAgentBridgeSetting = developmentCohort
	? developmentAgentReplayBridgeIdsSetting
	: productionAgentReplayBridgeIdsSetting;
const fencedSelection = target === "--internal" || target === "--internal-railway" || enrolledCohort;
const onRailway = target === "--railway" || target === "--internal-railway";
if (onRailway) assert.ok(argument, "Pass the isolated Railway fixture profile.");
const railway = onRailway && argument
	? await createRailwayProjectEngineTransport(argument)
	: undefined;
const [releaseImage, rehearsalImage] = railway
	? ["release", "candidate"]
	: fencedSelection
		? [argument, argument]
		: [target, argument];
assert.ok(
	releaseImage && rehearsalImage,
	"Pass the normal release and project-engine-rehearsal Docker images.",
);
if (!fencedSelection) assert.notEqual(releaseImage, rehearsalImage);
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
const alternateEmail = "alias@project-engine-rehearsal.invalid";
const ownedSlug = "compiled-engine-owned";

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
		accept,
		method = body ? "POST" : "GET",
		clientIP = "192.0.2.54",
	}: {
		body?: object;
		cookie?: string;
		realm?: Realm;
		host?: string;
		accept?: string;
		method?: "GET" | "POST" | "PATCH";
		clientIP?: string;
	} = {},
) {
	const form = body instanceof URLSearchParams;
	const data = form ? body.toString() : body ? JSON.stringify(body) : "";
	const headers = new Headers({
		origin: host ? `https://${host}` : (realm?.primaryOrigin ?? platform),
		...(body ? { "content-type": form ? "application/x-www-form-urlencoded" : "application/json" } : {}),
		...(accept ? { accept } : {}),
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
			location: response.headers.get("location"),
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
		console.log(JSON.stringify({
			status: response.status, cookies, location: response.headers.get("location"), body: await response.text(),
		}));
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
		location: string | null;
		body: string;
	};
}

async function startConnectedApplication(realm: Realm, cookie: string) {
	const schema = `allauth_project_${realm.id.replaceAll("-", "")}`;
	const client = randomUUID();
	const redirect = `${realm.primaryOrigin}/oauth/callback`;
	const issuer = `https://${host}/api/auth`;
	await query(source, `
		INSERT INTO "${schema}"."oauthClient"
		(id,"clientId","redirectUris","grantTypes",scopes,"tokenEndpointAuthMethod","skipConsent","requirePKCE","createdAt","updatedAt")
		VALUES ('${client}','${client}','["${redirect}"]','["authorization_code","refresh_token"]',
		'["openid","profile","offline_access"]','none',true,true,now(),now());
	`);
	const state = randomUUID();
	const verifier = randomBytes(32).toString("base64url");
	const queryString = new URLSearchParams({
		client_id: client,
		redirect_uri: redirect,
		response_type: "code",
		scope: "openid profile offline_access",
		state,
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
		code_challenge_method: "S256",
	});
	const authorization = await request(`/api/auth/oauth2/authorize?${queryString}`, {
		cookie, host, accept: "application/json",
	});
	assert.ok(authorization.status === 200 || authorization.status === 302,
		"Native authorizes the connected fixture application.");
	const location = authorization.location ?? (JSON.parse(authorization.body) as { url?: string }).url;
	assert.ok(location);
	const callback = new URL(location);
	assert.equal(callback.origin + callback.pathname, redirect);
	assert.equal(callback.searchParams.get("state"), state);
	assert.equal(callback.searchParams.get("iss"), issuer);
	const code = callback.searchParams.get("code");
	assert.ok(code, "Native issues an authorization code.");

	async function exchange(grant: Record<string, string>) {
		const response = await request("/api/auth/oauth2/token", {
			host, body: new URLSearchParams({ client_id: client, ...grant }),
		});
		expectStatus(response, 200, "The connected application exchanges its project grant.");
		const tokens = JSON.parse(response.body) as { id_token: string; refresh_token: string };
		assert.ok(tokens.id_token && tokens.refresh_token);
		const jwks = await request("/api/auth/jwks", { host });
		expectStatus(jwks, 200, "The same issuer publishes its signing keys.");
		const signed = await jwtVerify(
			tokens.id_token, createLocalJWKSet(JSON.parse(jwks.body) as JSONWebKeySet),
			{ issuer, audience: client },
		);
		assert.equal(signed.payload.sub, accountId);
		return { refresh: tokens.refresh_token, keyId: signed.protectedHeader.kid };
	}
	let grant = await exchange({
		grant_type: "authorization_code",
		redirect_uri: redirect,
		code,
		code_verifier: verifier,
	});
	assert.ok(grant.keyId);
	return {
		queryString,
		async rotate() {
			const updated = await exchange({ grant_type: "refresh_token", refresh_token: grant.refresh });
			assert.equal(updated.keyId, grant.keyId, "The project issuer retains the signing key.");
			assert.ok(updated.refresh !== grant.refresh, "The issuer rotates the offline grant.");
			grant = updated;
		},
	};
}

async function startConfiguredWebhook(realm: Realm, cookie: string) {
	const schema = `allauth_project_${realm.id.replaceAll("-", "")}`;
	const id = randomUUID();
	const path = `/api/projects/${realm.slug}/auth/control/webhooks`;
	const fixturePolicy = {
		...defaultAuthPolicy,
		mfaMode: "optional" as const,
		requireEmailVerification: false,
		signUpEnabled: false,
	};
	const policy = JSON.stringify(fixturePolicy).replaceAll("'", "''");
	await query(source, `
		INSERT INTO public."allauthAuthConfiguration" (id,policy,version,"updatedBy")
		VALUES ('${realm.id}','${policy}',1,'isolated-writer-rehearsal');
		INSERT INTO "${schema}"."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret",enabled)
		VALUES ('${id}','https://webhook.rehearsal.invalid/events','["mfa.*","api-key.*","session.created","passkey.*"]','disabled-fixture-placeholder',false);
	`);
	async function read() {
		const result = await request(path, { cookie });
		expectStatus(result, 200, "The compiled project lists its existing configured webhook.");
		const { endpoints } = JSON.parse(result.body) as {
			endpoints: { id: string; eventTypes: string[]; enabled: boolean }[];
		};
		const endpoint = endpoints.find((item) => item.id === id);
		assert.deepEqual(endpoint?.eventTypes, ["mfa.*", "api-key.*", "session.created", "passkey.*"]);
		assert.equal(endpoint?.enabled, false);
		assert.ok(!result.body.includes("encryptedSecret"));
	}
	function changePolicy() {
		return request(`/api/admin/configuration?project=${realm.slug}`, {
			cookie,
			method: "PATCH",
			body: { version: 1, policy: { ...fixturePolicy, requireEmailVerification: true } },
		});
	}
	await read();
	return {
		async rotate() {
			await read();
			expectStatus(await changePolicy(), 409, "The active writer refuses an incompatible webhook policy.");
			const result = await request(`${path}/rotate`, { cookie, body: { id } });
			expectStatus(result, 200, "The AllAuth writer rotates the configured webhook credential.");
			assert.ok(typeof (JSON.parse(result.body) as { secret?: unknown }).secret === "string");
			assert.equal(
				await query(restored, `SELECT ("encryptedSecret"<>'disabled-fixture-placeholder')::text FROM "${schema}"."allauthWebhookEndpoint" WHERE id='${id}'`),
				"true",
			);
		},
		async removeAfterRollback() {
			await read();
			expectStatus(await changePolicy(), 200, "Legacy accepts the same policy change after rollback.");
			const result = await request(`${path}/delete`, { cookie, body: { id } });
			expectStatus(result, 200, "The restored legacy writer removes the same endpoint.");
			assert.equal(
				await query(restored, `SELECT count(*) FROM "${schema}"."allauthWebhookEndpoint" WHERE id='${id}'`),
				"0",
			);
		},
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
	readiness = 200,
) {
	if (fencedSelection)
		values = {
			...values,
			[projectEmailAliasVariable(ownedSlug)]: JSON.stringify({ [alternateEmail]: accountId }),
		};
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
		async () => (await request("/api/health")).status === readiness,
		"The compiled app did not report the expected readiness.",
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
	async function createFixtureWorkspace(suffix = "") {
		const response = await request("/api/workspaces", {
			cookie,
			body: {
				name: `Project Engine Rehearsal${suffix ? ` ${suffix}` : ""}`,
				slug: `compiled-engine-rehearsal${suffix}`,
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
	const workspaceId = fencedSelection && !enrolledCohort
		? platformWorkspaceId
		: await createFixtureWorkspace();
	assert.match(workspaceId, /^[a-f0-9-]{36}$/);
	async function create(
		slug: string,
		env: string,
		applicationId?: string,
		projectWorkspaceId = workspaceId,
	) {
		const primaryOrigin = developmentCohort && slug === ownedSlug
			? "http://localhost:3210"
			: `https://${slug}.project-engine-rehearsal.invalid`;
		const response = await request("/api/admin/projects", {
			cookie,
			body: {
				name: slug,
				slug,
				primaryOrigin,
				origins: [],
				workspaceId: projectWorkspaceId,
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
		assert.equal(project.workspaceId, projectWorkspaceId);
		assert.equal(project.primaryOrigin, primaryOrigin);
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
	const control = await create("compiled-engine-control", productionCohort ? "development" : "production");
	const owned = await create(
		ownedSlug,
		productionCohort ? "production" : "development",
		control.applicationId,
	);
	const unselected = enrolledCohort
		? await create(
				"compiled-engine-unselected",
				cohortEnvironment,
				undefined,
				developmentCohort ? await createFixtureWorkspace("-other") : workspaceId,
			)
		: undefined;
	if (developmentCohort) {
		assert.equal(control.applicationId, owned.applicationId);
		assert.notEqual(unselected?.workspaceId, owned.workspaceId);
	}
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
	return { owned, control, unselected, rootCookie: cookie };
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
						"pg_isready", // cspell:ignore isready
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
	const { owned, control, unselected, rootCookie } = await seed();
	const configuredWebhook = fencedSelection
		? await startConfiguredWebhook(owned, rootCookie)
		: undefined;
	const googleClient = "allauth-engine-rehearsal.apps.googleusercontent.com";
	if (fencedSelection && !railway) {
		expectStatus(
			await request(`/api/admin/projects/${owned.slug}/providers/google`, {
				cookie: rootCookie,
				method: "PATCH",
				body: {
					version: 0,
					google: {
						enabled: true,
						clientId: googleClient,
						clientSecret: "synthetic-google-credential",
					},
				},
			}),
			200,
			"Configure the isolated Google sign-in fixture.",
		);
	}
	const direct = `/api/projects/${owned.slug}/auth`;
	const controlPath = `/api/projects/${control.slug}/auth`;
	const selected = {
		ALLAUTH_REHEARSAL_PROJECT_ID: owned.id,
		ALLAUTH_REHEARSAL_WORKSPACE_ID: owned.workspaceId,
		ALLAUTH_REHEARSAL_DATABASE_NONCE: databaseNonce,
	};
	const login = { email: accountEmail, password: oldPassword };
	const ownedLogin = fencedSelection ? { ...login, email: alternateEmail } : login;
	const original = await request(`${direct}/sign-in/email`, {
		realm: owned,
		body: ownedLogin,
	});
	expectStatus(
		original,
		200,
		"Native sign-in through the signed project proxy.",
	);
	const originalCookie = sessionCookie(original);
	const originalHosted = await request("/api/auth/sign-in/email", {
		host,
		body: ownedLogin,
	});
	expectStatus(
		originalHosted,
		200,
		"Native sign-in through the verified hosted binding.",
	);
	const originalHostedCookie = sessionCookie(originalHosted);
	const connected = fencedSelection ? await startConnectedApplication(owned, originalHostedCookie) : undefined;
	const managedHost = `${owned.slug}-accounts.${portalDomain}`;
	const managedApi = `${owned.slug}-api.${portalDomain}`;
	const nativeHostedSessions: { hostname: string; cookie: string; id: string }[] = [];
	let ownedManagedCookie: string | undefined;
	if (fencedSelection) {
		for (const { hostname, clientIP } of [
			{ hostname: managedHost, clientIP: "192.0.2.56" },
			{ hostname: host, clientIP: "192.0.2.57" },
		]) {
			const native = await request("/api/auth/sign-in/email", {
				host: hostname,
				clientIP,
				body: ownedLogin,
			});
			expectStatus(native, 200, "Native sign-in works on the verified accounts hostname.");
			const cookie = sessionCookie(native);
			const current = await readSession("/api/auth/get-session", { host: hostname, cookie });
			assert.equal(current?.user.id, accountId);
			assert.ok(current?.session.id);
			nativeHostedSessions.push({ hostname, cookie, id: current.session.id });
			assert.ok(
				native.cookies
					.filter((cookie) => cookie.includes(".session_token="))
					.every((cookie) => !/; domain=/i.test(cookie)),
			);
		}
		const redirects = await query(
			source,
			`SELECT c."redirectUris"::text FROM public."oauthClient" c
			 JOIN public."allauthProject" p ON p."brokerClientId"=c."clientId" WHERE p.id='${owned.id}'`,
		);
		assert.ok(
			(JSON.parse(redirects) as string[]).includes(
				`https://${managedHost}/api/auth/callback/allauth`,
			),
		);
	}
	expectStatus(
		await request(`${direct}/not-installed`, { realm: owned }),
		404,
		"The baseline writer is legacy.",
	);
	if (enrolledCohort) {
		const registration = `register-${cohortEnvironment}`;
		await assert.rejects(projectWriter("status"));
		await assert.rejects(writerOperator(registration, owned.id, randomUUID()));
		if (developmentCohort) {
			await assert.rejects(writerOperator("register-production", owned.id, owned.workspaceId));
			await assert.rejects(writerOperator(registration, control.id, control.workspaceId));
		}
		await writerOperator(registration, owned.id, owned.workspaceId);
		assert.deepEqual(await projectWriter("status"), { writer: "legacy", revision: 0 });
		expectStatus(await request(`${direct}/not-installed`, { realm: owned }), 404,
			`Registering a ${cohortEnvironment} project keeps its legacy writer.`);
	}
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
	if (!railway && !fencedSelection) {
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

	async function writerOperator(...args: string[]) {
		return railway
			? await railway.internalWriter(args)
			: await docker(
				"exec", application, "node", "scripts/project-engine-writer.mjs", ...args,
			);
	}

	async function projectWriter(...args: string[]) {
		const output = await writerOperator(...(enrolledCohort
			? [developmentCohort ? "--development" : "--project", owned.id, ...args]
			: args));
		return JSON.parse(output) as { writer: string; revision: number };
	}

	async function hostedPage(hostname: string, firstParty: boolean) {
		const page = await request("/sign-in", { host: hostname });
		expectStatus(page, 200, "Render sign-in for the verified project hostname.");
		assert.equal(page.body.includes("/api/auth/hosted-ui"), firstParty);
	}

	async function readSession(
		path: string,
		options: Parameters<typeof request>[1],
	) {
		const response = await request(path, options);
		expectStatus(
			response,
			200,
			"Read a live session through the compiled route.",
		);
		return JSON.parse(response.body) as {
			session: { id: string };
			user: { id: string };
		} | null;
	}

	async function currentSession(
		path: string,
		options: Parameters<typeof request>[1],
	) {
		return (await readSession(path, options))?.user.id ?? null;
	}

	async function checkOriginalHostedSessions() {
		assert.equal(nativeHostedSessions.length, 2);
		for (const { hostname, cookie, id } of nativeHostedSessions) {
			const current = await readSession("/api/auth/hosted-ui/get-session", {
				host: hostname,
				cookie,
				accept: "application/json",
			});
			assert.equal(current?.user.id, accountId);
			assert.equal(current?.session.id, id);
		}
	}

	function projectSelection(id: string, revision = 0): Record<string, string> {
		return enrolledCohort
			? { [enrolledRevisionsSetting]: JSON.stringify({ [id]: revision }) }
			: { ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id };
	}
	let fencedEnvironment: Record<string, string> = {};
	if (fencedSelection) {
		const mail = {
			EMAIL_PROVIDER: "cloudflare",
			EMAIL_FROM: "security@project-engine-rehearsal.invalid",
			CLOUDFLARE_ACCOUNT_ID: run,
			CLOUDFLARE_EMAIL_API_TOKEN: run,
		};
		if (unselected) {
			await start(
				releaseImage,
				restored,
				{ [enrolledAgentBridgeSetting]: unselected.id },
				503,
			);
			await stop(restored);
			await start(
				releaseImage,
				restored,
				{ [enrolledAgentBridgeSetting]: owned.id },
			);
			assert.deepEqual(await projectWriter("status"), {
				writer: "legacy",
				revision: 0,
			});
			expectStatus(
				await request(`${direct}/not-installed`, { realm: owned }),
				404,
				"The registered Agent bridge starts on the legacy writer before candidate selection.",
			);
			await stop(restored);
		}
		if (!railway) {
			await start(
				releaseImage,
				restored,
				{ ...mail, ...projectSelection(unselected?.id ?? control.id) },
				503,
			);
			expectStatus(
				await request(`${controlPath}/not-installed`, { realm: control }),
				404,
				"An ineligible project fails readiness and retains the legacy writer.",
			);
			await stop(restored);
			await start(
				releaseImage,
				restored,
				projectSelection(owned.id),
				503,
			);
			await stop(restored);
		}
		fencedEnvironment = { ...mail, ...projectSelection(owned.id) };
		await start(rehearsalImage, restored, fencedEnvironment);
		assert.deepEqual(await projectWriter("status"), { writer: "legacy", revision: 0 });
		expectStatus(
			await request(`${direct}/not-installed`, { realm: owned }),
			404,
			"The selected project keeps the legacy writer until the database switch.",
		);
		await hostedPage(managedHost, false);
		await hostedPage(host, false);
		assert.deepEqual(await projectWriter("switch", "legacy", "0", "allauth"), {
			writer: "allauth", revision: 1,
		});
		await assert.rejects(projectWriter("switch", "legacy", "0", "allauth"));
		await hostedPage(managedHost, true);
		await hostedPage(host, true);
		await configuredWebhook?.rotate();
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host }),
			200,
			"The selected realm uses the first-party hosted API.",
		);
		if (!railway && connected) {
			const authorization = new URLSearchParams(connected.queryString);
			authorization.set("state", `${"signed-application-state".repeat(171)}+one&two`);
			const secret = projectSecret({ ALLAUTH_AUTH_SECRET: authSecret }, owned.id);
			const destination = `/oauth2/continue?${signProjectIssuerQuery(authorization, secret)}`;
			const body = {
				email: "unregistered@project-engine-rehearsal.invalid",
				...hostedMagicLinkCallbacks(destination, `https://${host}`),
			};
			assert.ok(Buffer.byteLength(JSON.stringify(body)) > 8192);
			expectStatus(
				await request("/api/auth/hosted-ui/sign-in/magic-link", {
					host,
					body,
					accept: "application/json",
				}),
				200,
				"The compiled hosted route accepts the long signed browser continuation.",
			);
			expectStatus(
				await request("/api/auth/sign-in/magic-link", { host, body }),
				400,
				"The standard project route retains the existing request limit.",
			);
			const schema = `allauth_project_${owned.id.replaceAll("-", "")}`;
			assert.equal(
				await query(restored, `SELECT count(*) FROM "${schema}"."verification" WHERE identifier LIKE 'magic-link:%'`),
				"0",
			);
			const callbackURL = new URL(destination, `https://${host}`).href;
			const socialBody = {
				provider: "google",
				callbackURL,
				newUserCallbackURL: callbackURL,
				disableRedirect: true,
			};
			assert.ok(Buffer.byteLength(JSON.stringify(socialBody)) > 8192);
			const social = await request("/api/auth/hosted-ui/sign-in/social", {
				host,
				body: socialBody,
				accept: "application/json",
			});
			expectStatus(
				social,
				200,
				"The compiled hosted route starts Google with the long signed continuation.",
			);
			const provider = new URL((JSON.parse(social.body) as { url: string }).url);
			assert.equal(provider.origin, "https://accounts.google.com");
			assert.equal(provider.searchParams.get("client_id"), googleClient);
			assert.equal(
				provider.searchParams.get("redirect_uri"),
				`https://${host}/api/auth/callback/google`,
			);
			expectStatus(
				await request("/api/auth/sign-in/social", { host, body: socialBody }),
				400,
				"The standard social route retains the existing request limit.",
			);
		}
	} else {
		await start(rehearsalImage, restored, selected);
	}
	if (railway && !fencedSelection) {
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
	if (unselected)
		expectStatus(await request(`/api/projects/${unselected.slug}/auth/not-installed`, { realm: unselected }),
			404, `An unregistered ${cohortEnvironment} project remains on legacy.`);
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
	await connected?.rotate();
	const fixturePassword = fencedSelection ? oldPassword : newPassword;
	async function switchDirectSession() {
		if (fencedSelection) {
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
				body: ownedLogin,
			});
			expectStatus(
				loginResponse,
				200,
				"The internal project signs in through the AllAuth writer.",
			);
			assert.equal(JSON.parse(loginResponse.body).user.id, accountId);
			assert.equal(JSON.parse(loginResponse.body).user.email, accountEmail);
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
	const ownedHosted = await request(
		fencedSelection ? "/api/auth/hosted-ui/sign-in/email" : "/api/auth/sign-in/email",
		{
			host,
			accept: "application/json",
			body: { ...ownedLogin, password: fixturePassword },
		},
	);
	expectStatus(ownedHosted, 200, "The AllAuth hosted route signs in.");
	const ownedHostedCookie = sessionCookie(ownedHosted);
	if (fencedSelection) {
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host: managedHost }),
			200,
			"The managed accounts hostname uses the first-party hosted API.",
		);
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host: managedApi }),
			404,
			"The frontend API hostname keeps its existing hosted UI boundary.",
		);
		await checkOriginalHostedSessions();
		const ownedManaged = await request("/api/auth/hosted-ui/sign-in/email", {
			host: managedHost,
			clientIP: "192.0.2.56",
			accept: "application/json",
			body: ownedLogin,
		});
		expectStatus(
			ownedManaged,
			200,
			"AllAuth sign-in works on the managed accounts hostname.",
		);
		assert.ok(
			ownedManaged.cookies
				.filter((cookie) => cookie.includes(".session_token="))
				.every((cookie) => !/; domain=/i.test(cookie)),
		);
		ownedManagedCookie = sessionCookie(ownedManaged);
	}
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

	if (fencedSelection) {
		if (!railway) {
			await start(releaseImage, restored, {}, 503);
			expectStatus(await request(`${direct}/get-session`, { realm: owned, cookie: ownedCookie }),
				503, "A replica missing the active realm selection fails closed.");
			expectStatus(await request(`${controlPath}/not-installed`, { realm: control }),
				404, "A replica missing the active realm selection cannot cross into its sibling.");
			if (enrolledCohort) {
				expectStatus(await request("/api/auth/get-session", { host, cookie: ownedHostedCookie }),
					503, `The unselected active ${cohortEnvironment} accounts API fails closed.`);
				const stalePage = await request("/sign-in", { host });
				assert.ok(stalePage.body.includes("Sign-in is temporarily unavailable"));
			} else await stop(restored);
		}
		if (!enrolledCohort) await start(releaseImage, restored, fencedEnvironment);
		assert.deepEqual(await projectWriter("status"), { writer: "allauth", revision: 1 });
		if (!enrolledCohort)
			expectStatus(
				await request(`${direct}/not-installed`, { realm: owned }),
				501,
				"The restored deployment reads the committed AllAuth writer.",
			);
		assert.deepEqual(await projectWriter("switch", "allauth", "1", "legacy"), {
			writer: "legacy", revision: 2,
		});
		await assert.rejects(projectWriter("switch", "legacy", "2", "allauth"));
		assert.deepEqual(await projectWriter("status"), { writer: "legacy", revision: 2 });
		expectStatus(await request("/api/health"), 200, "The restored writer remains ready.");
		await hostedPage(managedHost, false);
		await hostedPage(host, false);
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host: managedHost }),
			200,
			"A first-party page already open at rollback keeps its transport.",
		);
		await checkOriginalHostedSessions();
	} else await start(releaseImage, restored, selected);
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
	await connected?.rotate();
	await configuredWebhook?.removeAfterRollback();
	if (ownedManagedCookie)
		assert.equal(
			await currentSession("/api/auth/get-session", {
				host: managedHost,
				cookie: ownedManagedCookie,
			}),
			accountId,
		);
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
			body: { ...ownedLogin, password: fixturePassword },
		}),
		200,
		"Native reads the project password after rollback.",
	);
	if (!fencedSelection) {
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
	if (fencedSelection)
		expectStatus(
			await request(`${controlPath}/sign-in/email`, {
				realm: control,
				body: ownedLogin,
				clientIP: "192.0.2.57",
			}),
			401,
			"The sibling realm declines the other project's configured alias.",
		);
	await stop(restored);
	if (developmentCohort) {
		await query(
			restored,
			`UPDATE public."allauthCustomHostname" SET "routingVerifiedAt"=NULL WHERE "projectId"='${owned.id}'`,
		);
		await start(releaseImage, restored, {
			...fencedEnvironment,
			...projectSelection(owned.id, 2),
			ALLAUTH_DEPLOYMENT_MODE: "self-hosted",
			CLOUDFLARE_SAAS_READY: "false",
		});
		assert.deepEqual(await projectWriter("switch", "legacy", "2", "allauth"), {
			writer: "allauth",
			revision: 3,
		});
		expectStatus(await request("/api/health"), 200, "A direct-only development writer is ready.");
		assert.equal(
			await currentSession(`${direct}/get-session`, { realm: owned, cookie: ownedCookie }),
			accountId,
		);
		assert.deepEqual(await projectWriter("switch", "allauth", "3", "legacy"), {
			writer: "legacy",
			revision: 4,
		});
		await stop(restored);
	}
	console.log(
		enrolledCohort
			? `Compiled ${cohortEnvironment} project enrollment, cutover and rollback passed.`
			: fencedSelection
				? "Compiled internal project writer fence and hosted sign-in passed from legacy to AllAuth and back."
				: "Compiled project rehearsal passed from legacy to AllAuth and back.",
	);
} finally {
	await railway?.stop();
	if (networkCreated) {
		await docker("rm", "-f", application, database).catch(() => undefined);
		await docker("network", "rm", network);
	}
}
