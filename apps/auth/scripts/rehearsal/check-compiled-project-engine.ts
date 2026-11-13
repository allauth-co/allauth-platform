import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { getCookies } from "better-auth/cookies";
import type { JSONWebKeySet } from "jose";
import { createLocalJWKSet, jwtVerify } from "jose";
import { defaultAuthPolicy } from "../../lib/auth-policy/policy";
import { clerkCompatiblePasswords } from "../../lib/clerk-password";
import { signEdgeRequest } from "../../lib/domains/edge";
import { hostedMagicLinkCallbacks } from "../../lib/domains/hosted-sdk-policy";
import { projectEmailAliasVariable } from "../../lib/project-email-alias-config";
import { verifyLegacySessionCookie } from "../../lib/projects/legacy-session-cookie";
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
const sessionKeyRing = `7:${authSecret},2:${randomBytes(32).toString("hex")}`;
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
const customApi = `api.${customDomain}`;
const oldPassword = `Rehearsal-original-${randomUUID()}!`;
const newPassword = `Rehearsal-updated-${randomUUID()}!`;
const accountId = randomUUID();
const accountEmail = "account@project-engine-rehearsal.invalid";
const alternateEmail = "alias@project-engine-rehearsal.invalid";
const ownedSlug = "compiled-engine-owned";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";

interface Realm {
	id: string;
	slug: string;
	workspaceId: string;
	applicationId: string;
	primaryOrigin: string;
	environment: string;
	proxyVersion: string;
}

type ProxyFactory = typeof import("../../sdk/next").createAllAuthProxy;
const sdkFolders: string[] = [];

function proxyKey(realm: Realm) {
	return createHmac("sha256", authSecret)
		.update(`allauth:proxy:${realm.id}:${realm.proxyVersion}`)
		.digest("hex");
}

async function archivedProxy(realm: Realm, version: "1.0.0" | "2.0.0") {
	const directory = new URL("../../public/sdk/", import.meta.url);
	const name = `allauth-react-${version}.tgz`;
	const archive = new URL(name, directory);
	const checksums = JSON.parse(
		await readFile(new URL("integrity.json", directory), "utf8"),
	) as Record<string, string>;
	assert.equal(
		createHash("sha256")
			.update(await readFile(archive))
			.digest("hex"),
		checksums[name],
	);
	const folder = await mkdtemp(join(tmpdir(), "allauth-compiled-sdk-"));
	sdkFolders.push(folder);
	await execute("tar", ["-xzf", fileURLToPath(archive), "-C", folder]);
	const { createAllAuthProxy } = (await import(
		pathToFileURL(join(folder, "package/next.ts")).href
	)) as { createAllAuthProxy: ProxyFactory };
	const handler = createAllAuthProxy({
		project: realm.slug,
		proxySecret: proxyKey(realm),
		appOrigin: realm.primaryOrigin,
		allauthURL: platform,
	});
	return async (
		endpoint: "sign-in/email" | "get-session",
		body?: object,
		cookie?: string,
	) => {
		const response = await handler(
			new Request(`${realm.primaryOrigin}/api/allauth/${endpoint}`, {
				method: body ? "POST" : "GET",
				headers: {
					origin: realm.primaryOrigin,
					...(body ? { "content-type": "application/json" } : {}),
					...(cookie ? { cookie } : {}),
				},
				body: body ? JSON.stringify(body) : undefined,
			}),
			{ params: Promise.resolve({ all: endpoint.split("/") }) },
		);
		return {
			status: response.status,
			cookies: response.headers.getSetCookie(),
			location: response.headers.get("location"),
			body: await response.text(),
		};
	};
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
		flight = false,
		method = body ? "POST" : "GET",
		clientIP = "192.0.2.54",
	}: {
		body?: object;
		cookie?: string;
		realm?: Realm;
		host?: string;
		accept?: string;
		flight?: boolean;
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
		...(flight ? { rsc: "1" } : {}),
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
		const digest = createHash("sha256").update(data).digest("hex");
		ingress.set("allauth-proxy-timestamp", time);
		ingress.set("allauth-proxy-origin", realm.primaryOrigin);
		ingress.set("allauth-proxy-ip", clientIP);
		ingress.set(
			"allauth-proxy-signature",
			createHmac("sha256", proxyKey(realm))
				.update(
					[time, method, path, realm.primaryOrigin, clientIP, digest].join(
						"\n",
					),
				)
				.digest("hex"),
		);
		// The Docker fixture connects through loopback without a hosting ingress.
		if (!railway && !clientIP) ingress.set("x-real-ip", "192.0.2.60");
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
		VALUES ('${client}','${client}','["${redirect}"]','["authorization_code","refresh_token","${deviceGrant}"]',
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
		client,
		queryString,
		async rotate() {
			const updated = await exchange({ grant_type: "refresh_token", refresh_token: grant.refresh });
			assert.equal(updated.keyId, grant.keyId, "The project issuer retains the signing key.");
			assert.ok(updated.refresh !== grant.refresh, "The issuer rotates the offline grant.");
			grant = updated;
		},
	};
}

async function startConnectedDevice(realm: Realm, client: string) {
	const schema = `allauth_project_${realm.id.replaceAll("-", "")}`;
	const scope = "openid profile offline_access";
	const response = await request("/api/auth/device/code", {
		host,
		body: new URLSearchParams({ client_id: client, scope }),
	});
	expectStatus(
		response,
		200,
		"The native project issuer starts device authorization.",
	);
	assert.deepEqual(response.cookies, []);
	const codes = JSON.parse(response.body) as {
		device_code: string;
		user_code: string;
		verification_uri: string;
		verification_uri_complete: string;
	};
	assert.match(codes.device_code, /^[A-Za-z0-9]{40}$/);
	assert.match(codes.user_code, /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/);
	const verification = new URL(codes.verification_uri_complete);
	const apex = new URL("/device", platform);
	apex.searchParams.set("project", realm.slug);
	assert.equal(codes.verification_uri, apex.href);
	apex.searchParams.set("user_code", codes.user_code);
	assert.equal(verification.href, apex.href);

	function persisted(db: string) {
		return query(
			db,
			`
			SELECT json_build_object('status',status,'userId',"userId")::text
			FROM "${schema}"."deviceCode" WHERE "oauthClientId"='${client}'
			AND "deviceCode"='${codes.device_code}' AND "userCode"='${codes.user_code}'
		`,
		);
	}
	async function expectPending(db: string, userId: string | null) {
		assert.deepEqual(JSON.parse(await persisted(db)), {
			status: "pending",
			userId,
		});
	}
	await expectPending(source, null);

	return {
		async review(
			platformCookie: string,
			projectCookie: string,
			credentials: { email: string; password: string },
			managedHostname: string,
		) {
			const publicPath = verification.pathname + verification.search;
			const apexCookies = `${platformCookie}; ${projectCookie}`;
			const direct = await request(publicPath, { cookie: apexCookies });
			expectStatus(
				direct,
				200,
				"A fresh project session can review on the original platform URL.",
			);
			assert.match(direct.body, /Approve a device/);
			await expectPending(restored, null);
			const directSession = await request(
				`/api/projects/${realm.slug}/auth/get-session?disableRefresh=true`,
				{
					realm,
					cookie: projectCookie,
				},
			);
			expectStatus(
				directSession,
				200,
				"Read the exact fresh apex project session.",
			);
			const { session } = JSON.parse(directSession.body) as {
				session: { id: string };
			};
			assert.match(session.id, /^[A-Za-z0-9_-]+$/);
			const shiftFixtureSessionAge = (direction: "-" | "+") =>
				query(restored, `
					BEGIN;
					SET LOCAL allauth.project_engine_project_id = '${realm.id}';
					SET LOCAL allauth.project_engine_writer = 'allauth';
					SET LOCAL allauth.project_engine_writer_revision = '1';
					UPDATE "${schema}"."session" SET "createdAt"="createdAt" ${direction} interval '6 minutes' WHERE id='${session.id}';
					COMMIT;
				`);
			let handoff: Awaited<ReturnType<typeof request>>;
			await shiftFixtureSessionAge("-");
			try {
				handoff = await request(publicPath, { cookie: apexCookies });
			} finally {
				await shiftFixtureSessionAge("+");
			}
			assert.deepEqual(handoff.cookies, []);
			const userCode = new URLSearchParams({ user_code: codes.user_code });
			const reviewPath = `/account/device?${userCode}`;
			const destination = new URL(reviewPath, `https://${managedHostname}`);
			expectTemporaryRedirect(handoff, destination.href, "Hand off the original device link.");
			const browser = { host: destination.hostname, clientIP: "192.0.2.65" };
			const page = await request(reviewPath, browser);
			expectStatus(
				page,
				200,
				"The verified accounts host renders device review.",
			);
			assert.match(page.body, /Approve a device/);
			assert.ok(!page.body.includes(codes.device_code));
			await expectPending(restored, null);

			const signInQuery = new URLSearchParams({ callbackUrl: reviewPath });
			const signIn = await request(`/sign-in?${signInQuery}`, browser);
			expectStatus(
				signIn,
				200,
				"Device reauthentication uses the project's hosted sign-in.",
			);
			assert.ok(signIn.body.includes("/api/auth/hosted-ui"));
			const signedIn = await request("/api/auth/hosted-ui/sign-in/email", {
				...browser,
				accept: "application/json",
				body: { ...credentials, callbackURL: destination.href },
			});
			expectStatus(
				signedIn,
				200,
				"AllAuth signs in the project account on the review hostname.",
			);
			const signedInBody = JSON.parse(signedIn.body) as {
				url: string;
				user: { id: string };
			};
			assert.equal(signedInBody.url, destination.href);
			assert.equal(signedInBody.user.id, accountId);
			const cookie = frontendSessionCookie(signedIn, destination.hostname);
			expectStatus(
				await request(reviewPath, { ...browser, cookie }),
				200,
				"Sign-in returns to the same-host review page.",
			);
			await expectPending(restored, null);

			const readDevice = () =>
				request(`/api/auth/device?${userCode}`, {
					...browser,
					cookie,
					accept: "application/json",
				});
			const review = await readDevice();
			expectStatus(
				review,
				200,
				"The verified project account explicitly reviews the native device code.",
			);
			const expectedReview = {
				user_code: codes.user_code,
				status: "pending",
				client_id: client,
				scope,
			};
			assert.deepEqual(JSON.parse(review.body), expectedReview);
			await expectPending(restored, accountId);
			return async () => {
				const restoredPage = await request(reviewPath, { ...browser, cookie });
				expectStatus(
					restoredPage,
					200,
					"The open review URL remains available after rollback.",
				);
				assert.match(restoredPage.body, /Approve a device/);
				const restoredReview = await readDevice();
				expectStatus(
					restoredReview,
					200,
					"The native writer recognizes the same project session and reviewed code.",
				);
				assert.deepEqual(JSON.parse(restoredReview.body), expectedReview);
				await expectPending(restored, accountId);
				const approval = await request("/api/auth/device/approve", {
					...browser,
					cookie,
					body: { userCode: codes.user_code },
				});
				expectStatus(
					approval,
					200,
					"The restored native writer approves the reviewed device code.",
				);
				assert.deepEqual(JSON.parse(approval.body), { success: true });
				assert.deepEqual(JSON.parse(await persisted(restored)), {
					status: "approved",
					userId: accountId,
				});

				const exchange = () =>
					request("/api/auth/oauth2/token", {
						host,
						body: new URLSearchParams({
							grant_type: deviceGrant,
							client_id: client,
							device_code: codes.device_code,
						}),
					});
				const redeemed = await exchange();
				expectStatus(
					redeemed,
					200,
					"The original project issuer exchanges the approved grant.",
				);
				assert.deepEqual(redeemed.cookies, []);
				const tokens = JSON.parse(redeemed.body) as {
					access_token: string;
					refresh_token: string;
					id_token: string;
					token_type: string;
					scope: string;
				};
				assert.ok(
					tokens.access_token && tokens.refresh_token && tokens.id_token,
				);
				assert.equal(tokens.token_type, "Bearer");
				assert.equal(tokens.scope, scope);
				const jwks = await request("/api/auth/jwks", { host });
				expectStatus(
					jwks,
					200,
					"The original project issuer still publishes its keys.",
				);
				await jwtVerify(
					tokens.id_token,
					createLocalJWKSet(JSON.parse(jwks.body) as JSONWebKeySet),
					{
						issuer: `https://${host}/api/auth`,
						audience: client,
						subject: accountId,
					},
				);
				assert.equal(await persisted(restored), "");
				const replay = await exchange();
				expectStatus(
					replay,
					400,
					"The original device code is consumed only once.",
				);
				assert.equal(JSON.parse(replay.body).error, "invalid_grant");
			};
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
	let version = 1;
	function changePolicy(changes: Partial<typeof fixturePolicy>) {
		return request(`/api/admin/configuration?project=${realm.slug}`, {
			cookie,
			method: "PATCH",
			body: { version, policy: { ...fixturePolicy, ...changes } },
		});
	}
	await read();
	return {
		async withPasswordDisabled(check: () => Promise<void>) {
			const disabled = await changePolicy({ emailAndPasswordEnabled: false });
			expectStatus(disabled, 200, "Disable passwords while the fixture Google provider is enabled.");
			version += 1;
			try {
				await check();
			} finally {
				const restored = await changePolicy({});
				expectStatus(restored, 200, "Restore the fixture password policy.");
				version += 1;
			}
		},
		async rotate() {
			await read();
			expectStatus(await changePolicy({ requireEmailVerification: true }), 409, "The active writer refuses an incompatible webhook policy.");
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
			expectStatus(await changePolicy({ requireEmailVerification: true }), 200, "Legacy accepts the same policy change after rollback.");
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

function expectTemporaryRedirect(
	response: Awaited<ReturnType<typeof request>>,
	destination: string,
	action: string,
) {
	if (response.status === 307) {
		assert.equal(response.location, destination, action);
		return;
	}
	// Next uses a refresh tag if it has already streamed the response headers.
	expectStatus(response, 200, action);
	const redirect = response.body.match(
		/<meta id="__next-page-redirect" http-equiv="refresh" content="1;url=([^"<>]+)"\s*\/?\s*>/,
	);
	assert.equal(redirect?.[1], destination, action);
}

function sessionCookie(response: Awaited<ReturnType<typeof request>>) {
	const cookie = response.cookies.find(
		(item) => item.includes(".session_token=") && !item.includes("Max-Age=0"),
	);
	assert.ok(cookie, "The compiled route must issue a session cookie.");
	return cookie.split(";", 1)[0];
}

function frontendSessionCookie(
	response: Awaited<ReturnType<typeof request>>,
	hostname: string,
) {
	const cookie = sessionCookie(response);
	const issued = response.cookies.find((value) =>
		value.startsWith(`${cookie};`),
	);
	assert.ok(issued, `${hostname} issues the project session cookie.`);
	assert.match(cookie, /^__Secure-allauth_project_/);
	for (const attribute of [
		/;\s*Secure(?:;|$)/i,
		/;\s*HttpOnly(?:;|$)/i,
		/;\s*SameSite=Lax(?:;|$)/i,
		/;\s*Path=\/(?:;|$)/i,
	])
		assert.match(
			issued,
			attribute,
			`${hostname} sets the browser cookie attributes.`,
		);
	assert.doesNotMatch(
		issued,
		/;\s*Domain=/i,
		`${hostname} issues a host-only cookie.`,
	);
	return cookie;
}

function deviceCookie(
	response: Awaited<ReturnType<typeof request>>,
	realm: Realm,
) {
	const name = `__Secure-allauth_project_${realm.slug}.control_device=`;
	const cookie = response.cookies
		.find((item) => item.startsWith(name))
		?.split(";", 1)[0];
	assert.ok(cookie, "The compiled route must issue its known-device cookie.");
	const secret = projectSecret({ ALLAUTH_AUTH_SECRET: authSecret }, realm.id);
	assert.ok(
		verifyLegacySessionCookie(
			decodeURIComponent(cookie.slice(name.length)),
			secret,
		),
		"The known-device cookie uses the stable project key.",
	);
	return cookie;
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
			BETTER_AUTH_SECRETS: sessionKeyRing,
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
		 ('${randomUUID()}','${pairId}','${owned.id}','frontend-api','${customApi}','${randomUUID()}',now(),'${randomUUID()}','active','active',now());
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
	const sdk =
		railway && fencedSelection
			? {
					v1: await archivedProxy(owned, "1.0.0"),
					v2: await archivedProxy(owned, "2.0.0"),
				}
			: undefined;
	function signInThroughProxy(
		version: "v1" | "v2",
		body: typeof ownedLogin,
		cookie?: string,
	) {
		return sdk
			? sdk[version]("sign-in/email", body, cookie)
			: request(`${direct}/sign-in/email`, {
					realm: owned,
					body,
					cookie,
					clientIP: fencedSelection ? "" : undefined,
				});
	}
	async function expectArchivedSession(
		version: "v1" | "v2",
		cookie: string,
		db: string,
	) {
		if (!sdk) return;
		const response = await sdk[version]("get-session", undefined, cookie);
		expectStatus(
			response,
			200,
			"The published SDK reads a session through the signed app proxy.",
		);
		assert.equal(JSON.parse(response.body)?.user?.id, accountId);
		const signed = decodeURIComponent(cookie.slice(cookie.indexOf("=") + 1));
		const digest = createHash("sha256")
			.update(JSON.stringify([owned.id, signed]))
			.digest("hex");
		const schema = `allauth_project_${owned.id.replaceAll("-", "")}`;
		assert.equal(
			await query(
				db,
				`SELECT count(*) FROM "${schema}"."rateLimit" WHERE "key"='bff-session:v2:${digest}'`,
			),
			"1",
			"The versioned session uses the signed per-cookie admission bucket.",
		);
	}
	async function deviceCount(db: string) {
		const schema = `allauth_project_${owned.id.replaceAll("-", "")}`;
		return query(
			db,
			`SELECT count(*) FROM "${schema}"."allauthKnownDevice" WHERE "userId"='${accountId}'`,
		);
	}
	const original = await signInThroughProxy("v1", ownedLogin);
	expectStatus(
		original,
		200,
		"Native sign-in through the signed project proxy.",
	);
	const originalCookie = sessionCookie(original);
	const originalDevice = fencedSelection ? deviceCookie(original, owned) : undefined;
	await expectArchivedSession("v2", originalCookie, source);
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
	const frontendHosts = [
		{ hostname: managedApi, clientIP: "192.0.2.63" },
		{ hostname: customApi, clientIP: "192.0.2.64" },
	];
	type HostedSession = { hostname: string; cookie: string; id: string };
	const nativeHostedSessions: HostedSession[] = [];
	const nativeFrontendSessions: HostedSession[] = [];
	const ownedFrontendSessions: HostedSession[] = [];
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
		for (const { hostname, clientIP } of frontendHosts) {
			await hostedPage(hostname, false);
			expectStatus(
				await request("/api/auth/hosted-ui/sdk/config", { host: hostname }),
				404,
				"An unselected frontend hostname keeps its existing hosted UI boundary.",
			);
			const native = await request("/api/auth/sign-in/email", {
				host: hostname,
				clientIP,
				body: ownedLogin,
			});
			expectStatus(
				native,
				200,
				"Native signs in on the verified frontend hostname.",
			);
			nativeFrontendSessions.push(
				await captureFrontendSession(native, hostname, false),
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
	const connectedDevice = connected
		? await startConnectedDevice(owned, connected.client)
		: undefined;
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

	async function hostedPage(
		hostname: string,
		firstParty: boolean,
		path = "/sign-in",
	) {
		const page = await request(path, { host: hostname });
		expectStatus(page, 200, "Render sign-in for the verified project hostname.");
		assert.equal(page.body.includes("/api/auth/hosted-ui"), firstParty);
	}

	async function expectHostedPresentation(
		hostname: string,
		mode: "legacy" | "allauth",
	) {
		const response = await request("/api/auth/hosted-presentation", { host: hostname });
		expectStatus(response, 200, "Read the current mode for the verified project hostname.");
		assert.deepEqual(JSON.parse(response.body), { mode });
		assert.deepEqual(response.cookies, []);
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

	async function captureFrontendSession(
		response: Awaited<ReturnType<typeof request>>,
		hostname: string,
		firstParty: boolean,
	): Promise<HostedSession> {
		const cookie = frontendSessionCookie(response, hostname);
		const current = await readSession(
			firstParty ? "/api/auth/hosted-ui/get-session" : "/api/auth/get-session",
			{ host: hostname, cookie, accept: "application/json" },
		);
		assert.equal(current?.user.id, accountId);
		assert.ok(current?.session.id);
		await checkFrontendConsole(hostname, cookie);
		return { hostname, cookie, id: current.session.id };
	}

	async function checkFrontendConsole(hostname: string, cookie: string) {
		expectStatus(
			await request("/console", { host: hostname, cookie }),
			404,
			"The gateway denies console access from a signed-in frontend hostname.",
		);
	}

	async function checkFrontendSessions(sessions: HostedSession[]) {
		for (const { hostname, cookie, id } of sessions) {
			const current = await readSession("/api/auth/hosted-ui/get-session", {
				host: hostname,
				cookie,
				accept: "application/json",
			});
			assert.equal(current?.user.id, accountId);
			assert.equal(current?.session.id, id);
			await checkFrontendConsole(hostname, cookie);
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
		await expectHostedPresentation(managedHost, "legacy");
		expectStatus(
			await request("/api/auth/hosted-presentation"),
			404,
			"The platform origin does not expose a project presentation.",
		);
		assert.deepEqual(await projectWriter("switch", "legacy", "0", "allauth"), {
			writer: "allauth", revision: 1,
		});
		await assert.rejects(projectWriter("switch", "legacy", "0", "allauth"));
		await hostedPage(managedHost, true);
		await hostedPage(host, true);
		for (const { hostname } of frontendHosts) {
			await hostedPage(hostname, true);
			expectStatus(
				await request("/api/auth/hosted-ui/sdk/config", { host: hostname }),
				200,
				"The selected writer serves first-party configuration on the frontend hostname.",
			);
		}
		const hostedTransports = [managedHost, host, ...frontendHosts.map(({ hostname }) => hostname)];
		for (const hostname of hostedTransports) {
			await expectHostedPresentation(hostname, "allauth");
			await hostedPage(hostname, true, "/sign-in?callbackUrl=%2faccount%3fdisplay%3dtwo%20words");
			// With only the RSC marker, Next expects its empty cache-busting hash.
			const flight = await request("/sign-in?_rsc", {
				host: hostname,
				flight: true,
				accept: "text/x-component",
			});
			expectStatus(flight, 200, "The verified hostname serves App Router navigation.");
			assert.ok(flight.body.includes("/api/auth/hosted-ui"));
		}
		if (connected) {
			const rejectedQuery = new URLSearchParams(connected.queryString);
			const state = `rejected-continuation-${randomUUID()}`;
			rejectedQuery.set("state", state);
			// Use an honestly signed but expired browser continuation.
			const clock = Date.now;
			const elapsed = clock() - 120_000;
			let expired: URLSearchParams;
			try {
				Date.now = () => elapsed;
				expired = signProjectIssuerQuery(rejectedQuery, authSecret);
			} finally {
				Date.now = clock;
			}
			for (const hostname of hostedTransports) {
				const browser = { host: hostname };
				const rejected = await request(`/sign-in?${expired}`, browser);
				expectTemporaryRedirect(rejected, "/auth-error", "Reject the expired project continuation.");
				assert.deepEqual(rejected.cookies, []);
				const guidance = await request("/auth-error", browser);
				expectStatus(guidance, 200, "Show the first-party hosted sign-in error.");
				assert.match(guidance.body, /Sign-in did not finish/);
				assert.ok(!guidance.body.includes(state));
			}
		}
		if (!railway) {
			assert.ok(configuredWebhook, "The policy fixture owns the configuration revision.");
			await configuredWebhook.withPasswordDisabled(async () => {
				for (const hostname of hostedTransports) {
					const browser = { host: hostname };
					for (const path of ["/sign-in?method=username", "/forgot-password"]) {
						const page = await request(path, browser);
						expectStatus(page, 200, "Render first-party guidance for a disabled sign-in method.");
						assert.match(page.body, /Sign-in option unavailable/);
						const destination = frontendHosts.some((frontend) => frontend.hostname === hostname)
							? "%2Faccount"
							: "%2Fconsole";
						assert.ok(page.body.includes(`/sign-in?returnTo=${destination}`));
					}
					await hostedPage(hostname, true, "/reset-link-sent");
				}
			});
		}
		assert.equal(nativeFrontendSessions.length, frontendHosts.length);
		await checkFrontendSessions(nativeFrontendSessions);
		await configuredWebhook?.rotate();
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host }),
			200,
			"The selected realm uses the first-party hosted API.",
		);
		if (connected) {
			for (const { hostname, clientIP } of [
				{ hostname: host, clientIP: "192.0.2.62" },
				...frontendHosts,
			]) {
				const authorization: URLSearchParams = new URLSearchParams(
					connected.queryString,
				);
				const frontend = hostname !== host;
				const state = frontend
					? `${randomUUID()}+one&two`
					: `${"signed-application-state".repeat(355)}+one&two`;
				authorization.set("state", state);
				const oauthQuery = signProjectIssuerQuery(
					authorization,
					authSecret,
				).toString();
				const callbackURL = `https://${hostname}/oauth2/continue?${oauthQuery}`;
				const transport = {
					host: hostname,
					clientIP,
					accept: "application/json",
				};
				const body = { ...ownedLogin, callbackURL };
				if (frontend) await hostedPage(hostname, true, `/sign-in?${oauthQuery}`);
				else assert.ok(Buffer.byteLength(JSON.stringify(body)) > 8192);
				const signedIn = await request("/api/auth/hosted-ui/sign-in/email", {
					...transport,
					body,
				});
				expectStatus(
					signedIn,
					200,
					"Password sign-in accepts the signed app return.",
				);
				const signInResult = JSON.parse(signedIn.body);
				assert.equal(signInResult.url, callbackURL);
				assert.equal(signInResult.user.id, accountId);
				const signedSession = frontend
					? await captureFrontendSession(signedIn, hostname, true)
					: undefined;
				if (signedSession) ownedFrontendSessions.push(signedSession);
				const continued = await request("/api/auth/oauth2/continue", {
					...transport,
					cookie: signedSession?.cookie ?? sessionCookie(signedIn),
					body: { selected: true, oauth_query: oauthQuery },
				});
				expectStatus(
					continued,
					200,
					"The compiled issuer finishes the same signed app return.",
				);
				const redirect = new URL(JSON.parse(continued.body).url);
				assert.equal(
					redirect.origin + redirect.pathname,
					authorization.get("redirect_uri"),
				);
				assert.equal(redirect.searchParams.get("state"), state);
				assert.equal(redirect.searchParams.get("iss"), `https://${hostname}/api/auth`);
				assert.ok(redirect.searchParams.has("code"));
			}
		}
		assert.equal(ownedFrontendSessions.length, frontendHosts.length);
		if (!railway && connected) {
			const authorization = new URLSearchParams(connected.queryString);
			authorization.set("state", `${"signed-application-state".repeat(171)}+one&two`);
			const destination = `/oauth2/continue?${signProjectIssuerQuery(authorization, authSecret)}`;
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
			const known = await deviceCount(restored);
			const loginResponse = await signInThroughProxy(
				"v2",
				ownedLogin,
				originalDevice,
			);
			expectStatus(
				loginResponse,
				200,
				"The internal project signs in through the AllAuth writer.",
			);
			assert.equal(JSON.parse(loginResponse.body).user.id, accountId);
			assert.equal(JSON.parse(loginResponse.body).user.email, accountEmail);
			assert.ok(
				deviceCookie(loginResponse, owned) === originalDevice,
				"AllAuth retains the same known-device cookie.",
			);
			assert.equal(
				await deviceCount(restored),
				known,
				"AllAuth keeps the existing device record.",
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
	await expectArchivedSession("v1", ownedCookie, restored);
	const ownedHosted = await request(
		fencedSelection ? "/api/auth/hosted-ui/sign-in/email" : "/api/auth/sign-in/email",
		{
			host,
			clientIP: "192.0.2.58",
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
	const finishDevice = await connectedDevice?.review(
		rootCookie,
		ownedCookie,
		ownedLogin,
		managedHost,
	);
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
		for (const { hostname } of frontendHosts) await hostedPage(hostname, false);
		await expectHostedPresentation(managedHost, "legacy");
		await expectHostedPresentation(customApi, "legacy");
		expectStatus(
			await request("/api/auth/hosted-ui/sdk/config", { host: managedHost }),
			200,
			"A first-party page already open at rollback keeps its transport.",
		);
		await checkOriginalHostedSessions();
		await checkFrontendSessions([
			...nativeFrontendSessions,
			...ownedFrontendSessions,
		]);
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
	await finishDevice?.();
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
	const known = fencedSelection ? await deviceCount(restored) : undefined;
	const rolledBack = fencedSelection
		? await signInThroughProxy(
				"v1",
				{ ...ownedLogin, password: fixturePassword },
				originalDevice,
			)
		: await request(`${direct}/sign-in/email`, {
				realm: owned,
				clientIP: "192.0.2.59",
				body: { ...ownedLogin, password: fixturePassword },
			});
	expectStatus(
		rolledBack,
		200,
		"Native reads the project password after rollback.",
	);
	if (fencedSelection) {
		assert.ok(
			deviceCookie(rolledBack, owned) === originalDevice,
			"Rollback retains the same known-device cookie.",
		);
		assert.equal(
			await deviceCount(restored),
			known,
			"Rollback keeps the existing device record.",
		);
	}
	await expectArchivedSession("v2", ownedCookie, restored);
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
	try {
		await railway?.stop();
		if (networkCreated) {
			await docker("rm", "-f", application, database).catch(() => undefined);
			await docker("network", "rm", network);
		}
	} finally {
		await Promise.all(sdkFolders.map((folder) => rm(folder, { recursive: true, force: true })));
	}
}
