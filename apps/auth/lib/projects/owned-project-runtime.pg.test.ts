import { execFile, fork } from "node:child_process";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { JSONWebKeySet } from "jose";
import {
	createLocalJWKSet,
	exportPKCS8,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { Pool } from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { authPolicyRepository } from "../auth-policy/storage";
import { clerkCompatiblePasswords } from "../clerk-password";
import { defaultSecurityPolicy } from "../control/security-policy";
import type { ControlPrincipal } from "../control/types";
import { signEdgeRequest } from "../domains/edge";
import { googleProviderRepository } from "../project-providers/repository";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createWorkspace } from "../workspaces/repository";
import { signProjectIssuerQuery } from "./owned-project-issuer-authorization-query";
import type { ProjectRuntimeFixtureBoot } from "./owned-project-runtime-fixture";
import {
	runtimeFixtureApple,
	runtimeFixtureAppleOrigin,
	runtimeFixtureAssetOrigin,
	runtimeFixtureAssetSecret,
	runtimeFixtureGoogle,
	runtimeFixtureMicrosoft,
	runtimeProviderFixtureCode,
} from "./owned-project-runtime-provider-fixture";
import {
	createRuntimeSamlKeys,
	runtimeSamlAuthnRequest,
	runtimeSamlConfiguration,
	runtimeSamlEntity,
	runtimeSamlOrigin,
	runtimeSamlProvider,
	runtimeSamlResponse,
	runtimeSamlSPMetadata,
	runtimeSamlSubject,
} from "./owned-project-runtime-saml-fixture";
import { projectProxySecret } from "./proxy";
import type { Project } from "./registry";
import { projectRegistryPool, provisionProject } from "./registry";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const appRoot = fileURLToPath(new URL("../..", import.meta.url));
const worker = fileURLToPath(
	new URL("./owned-project-runtime-fixture.ts", import.meta.url),
);
const platformOrigin = "https://project-runtime-fixture.example";
const edgeSecret = "disposable-project-runtime-fixture-edge-signing-secret";
const platformSecret =
	"disposable-project-runtime-fixture-platform-signing-secret";
const versionedSigningSecret = "isolated-runtime-fixture-current-key-version";
const versionedEncryption = `7:${versionedSigningSecret},2:isolated-runtime-fixture-previous-key-version`;
const oauthClientId = "runtime-issuer-fixture-client";
const oauthRedirectURI = "https://rp.runtime.fixture.example/callback";
const supportOrigin = "https://support.runtime.fixture.example";
const supportCallback = `${supportOrigin}/api/allauth/support/callback`;
const supportTarget = "fixture-support-target";
const directoryOrg = "fixture-directory";
const directoryProvider = "fixture-directory-provider";
const directoryIssuer = "https://idp.runtime-fixture.example.net";
const scimUser = "urn:ietf:params:scim:schemas:core:2.0:User";
const scimPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const credentials = {
	platform: { id: "fixture-owner", email: "owner@runtime.fixture.example" },
	project: {
		id: "fixture-project-account",
		email: "account@runtime.fixture.example",
	},
	password: "Fixture-native-password-92!",
	updated: "Fixture-rotated-password-73!",
};

type AppleFixture = {
	credentialKey: string;
	issuerKey: string;
	project: string;
};

function childEnvironment(
	microsoftProject?: string,
	apple?: AppleFixture,
): NodeJS.ProcessEnv {
	const { clientId, clientSecret, tenantId } = runtimeFixtureMicrosoft;
	return {
		PATH: process.env.PATH,
		NODE_ENV: "test",
		AUTH_RUNTIME: "node",
		ALLAUTH_AUTH_URL: platformOrigin,
		ALLAUTH_AUTH_SECRET: platformSecret,
		BETTER_AUTH_URL: platformOrigin,
		BETTER_AUTH_SECRET: platformSecret,
		BETTER_AUTH_SECRETS: versionedEncryption,
		TRUSTED_ORIGINS: "",
		EMAIL_FROM: "",
		SCIM_CREDENTIAL_HASH_SECRET:
			"disposable-project-runtime-fixture-credential-hash-key",
		ALLAUTH_EDGE_SECRET: edgeSecret,
		ALLAUTH_ASSET_ORIGIN: runtimeFixtureAssetOrigin,
		ALLAUTH_ASSET_SECRET: runtimeFixtureAssetSecret,
		CLOUDFLARE_SAAS_READY: "true",
		ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co",
		...(microsoftProject
			? {
					ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({
						[microsoftProject]: { clientId, clientSecret, tenantId },
					}),
				}
			: {}),
		...(apple
			? {
					ALLAUTH_PROJECT_APPLE_PROVIDERS: JSON.stringify({
						[apple.project]: {
							clientId: runtimeFixtureApple.clientId,
							appBundleIdentifier: runtimeFixtureApple.appBundleIdentifier,
							teamId: runtimeFixtureApple.teamId,
							keyId: runtimeFixtureApple.keyId,
							privateKey: apple.credentialKey,
						},
					}),
				}
			: {}),
	};
}

function cookie(response: Response) {
	return response.headers
		.getSetCookie()
		.filter((item) => !item.includes("Max-Age=0"))
		.map((item) => item.split(";", 1)[0])
		.join("; ");
}

async function openProcess(
	databaseURL: string,
	project: Project,
	owned: boolean,
	microsoftProject = project.slug,
	apple?: AppleFixture,
) {
	const child = fork(worker, [], {
		cwd: appRoot,
		env: childEnvironment(microsoftProject, apple),
		execArgv: ["--import", "tsx"],
		stdio: ["ignore", "ignore", "pipe", "ipc"],
	});
	let diagnostics = "";
	child.stderr?.on("data", (chunk: Uint8Array) => {
		if (diagnostics.length < 8_192)
			diagnostics += Buffer.from(chunk).toString("utf8");
	});
	const exited = once(child, "close");
	const mail: { to: string; subject: string; text: string }[] = [];
	const logout: string[] = [];
	child.on(
		"message",
		(message: { mail?: (typeof mail)[number]; logout?: string }) => {
			if (message.mail) mail.push(message.mail);
			if (message.logout) logout.push(message.logout);
		},
	);
	const boot: ProjectRuntimeFixtureBoot = {
		databaseURL,
		projectId: project.id,
		projectSlug: project.slug,
		schemaName: project.schemaName,
		owned,
		appleIssuerKey: apple?.issuerKey,
	};
	child.send(boot);
	try {
		const port = await Promise.race([
			once(child, "message", { signal: AbortSignal.timeout(15_000) }).then(
				([value]) => (value as { port: number }).port,
			),
			exited.then(() => {
				throw new Error(
					`Fixture HTTP process stopped during startup. ${diagnostics}`,
				);
			}),
		]);
		if (!Number.isInteger(port))
			throw new Error("Fixture HTTP process did not supply a port.");
		return {
			mail,
			logout,
			async request(
				path: string,
				options: {
					cookie?: string;
					body?: Record<string, unknown> | URLSearchParams;
					host?: string;
					origin?: string;
					clientIP?: string;
					proxy?: Project;
					authorization?: string;
					method?: "PATCH";
				} = {},
			) {
				const origin = options.host
					? `https://${options.host}`
					: platformOrigin;
				const headers = new Headers({ origin: options.origin ?? origin });
				if (options.cookie) headers.set("cookie", options.cookie);
				if (options.authorization)
					headers.set("authorization", options.authorization);
				const form = options.body instanceof URLSearchParams;
				const body =
					options.body === undefined
						? undefined
						: form
							? options.body.toString()
							: JSON.stringify(options.body);
				if (body)
					headers.set(
						"content-type",
						form ? "application/x-www-form-urlencoded" : "application/json",
					);
				const method = options.method ?? (body === undefined ? "GET" : "POST");
				if (options.proxy) {
					const proxyOrigin = headers.get("origin")!;
					const timestamp = Math.floor(Date.now() / 1000).toString();
					const signature = createHmac(
						"sha256",
						projectProxySecret(options.proxy, childEnvironment()),
					)
						.update(
							[
								timestamp,
								method,
								path,
								proxyOrigin,
								"",
								createHash("sha256")
									.update(body ?? "")
									.digest("hex"),
							].join("\n"),
						)
						.digest("hex");
					headers.set("allauth-proxy-signature", signature);
					headers.set("allauth-proxy-origin", proxyOrigin);
					headers.set("allauth-proxy-timestamp", timestamp);
				}
				const forwarded = options.host
					? await signEdgeRequest(
							new Request(`${origin}${path}`, { headers, method, body }),
							edgeSecret,
							options.host,
							options.clientIP ?? "192.0.2.55",
						)
					: headers;
				return fetch(`http://127.0.0.1:${port}${path}`, {
					headers: forwarded,
					method,
					body,
					redirect: "manual",
					signal: AbortSignal.timeout(10_000),
				});
			},
			async stop() {
				if (child.connected) child.send("stop");
				const deadline = setTimeout(() => child.kill("SIGKILL"), 12_000);
				try {
					const [code] = await exited;
					if (code !== 0)
						throw new Error(
							`Fixture HTTP process stopped unexpectedly. ${diagnostics}`,
						);
				} finally {
					clearTimeout(deadline);
				}
			},
		};
	} catch (error) {
		child.kill();
		await exited.catch(() => undefined);
		throw error;
	}
}

const oauthVerifier = "runtime-restart-fixture-project-issuer-proof-verifier";

function fixtureAuthorizationQuery(state = randomUUID()) {
	return new URLSearchParams({
		response_type: "code",
		client_id: oauthClientId,
		redirect_uri: oauthRedirectURI,
		scope: "openid profile",
		state,
		code_challenge_method: "S256",
		code_challenge: createHash("sha256")
			.update(oauthVerifier)
			.digest("base64url"),
	});
}

async function fixtureRedirect(response: Response) {
	const location =
		response.headers.get("location") ??
		((await response.json()) as { url?: string }).url;
	expect(location).toBeTruthy();
	return new URL(location!, platformOrigin);
}

type SamlTransport = {
	prefix: string;
	baseURL: string;
	destination: string;
	host?: string;
};

async function startRuntimeSaml(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: SamlTransport,
) {
	const started = await service.request(`${transport.prefix}/sign-in/sso`, {
		host: transport.host,
		body: {
			providerId: runtimeSamlProvider,
			providerType: "saml",
			callbackURL: transport.destination,
		},
	});
	expect(
		started.status,
		started.ok ? undefined : await started.clone().text(),
	).toBe(200);
	const url = await fixtureRedirect(started);
	expect(url.origin).toBe(runtimeSamlOrigin);
	expect(url.searchParams.has("Signature")).toBe(true);
	const flow = runtimeSamlAuthnRequest(url);
	expect(flow.acs).toBe(
		`${transport.baseURL}/sso/saml2/sp/acs/${runtimeSamlProvider}`,
	);
	return { transport, flow };
}

async function finishRuntimeSaml(
	service: Awaited<ReturnType<typeof openProcess>>,
	keys: Awaited<ReturnType<typeof createRuntimeSamlKeys>>,
	{ flow, transport }: Awaited<ReturnType<typeof startRuntimeSaml>>,
) {
	const acs = new URL(flow.acs);
	const authenticated = await service.request(acs.pathname, {
		host: transport.host,
		origin: runtimeSamlOrigin,
		body: runtimeSamlResponse(keys, flow, credentials.project.email),
	});
	expect(authenticated.status).toBe(302);
	expect(authenticated.headers.get("location")).toBe(transport.destination);
	const response = await service.request(`${transport.prefix}/get-session`, {
		host: transport.host,
		cookie: cookie(authenticated),
	});
	expect(await response.json()).toMatchObject({ user: credentials.project });
	return cookie(authenticated);
}

async function fixtureVerificationMail(
	service: Awaited<ReturnType<typeof openProcess>>,
	email: string,
) {
	return vi.waitFor(() => {
		const verification = service.mail.find(
			({ to, subject }) => to === email && subject.startsWith("Verify "),
		);
		expect(verification?.subject).toContain("Verify your");
		const match = verification?.text.match(
			/https:\/\/[^\s<>\]]+\/verify-email\?[^\s<>\]]+/,
		);
		expect(match?.[0]).toBeTruthy();
		return new URL(match![0]);
	});
}

async function startFixtureProvider(
	service: Awaited<ReturnType<typeof openProcess>>,
	provider: "google" | "microsoft",
	transport: {
		prefix: string;
		callback: string;
		destination: string;
		host?: string;
		clientIP?: string;
	},
) {
	const started = await service.request(`${transport.prefix}/sign-in/social`, {
		host: transport.host,
		clientIP: transport.clientIP,
		body: {
			provider,
			callbackURL: transport.destination,
			disableRedirect: true,
		},
	});
	expect(
		started.status,
		started.ok ? undefined : await started.clone().text(),
	).toBe(200);
	const authorization = await fixtureRedirect(started);
	const config =
		provider === "google" ? runtimeFixtureGoogle : runtimeFixtureMicrosoft;
	expect(authorization.origin).toBe(
		provider === "google"
			? "https://accounts.google.com"
			: "https://login.microsoftonline.com",
	);
	expect(authorization.searchParams.get("client_id")).toBe(config.clientId);
	expect(authorization.searchParams.get("redirect_uri")).toBe(
		transport.callback,
	);
	if (provider === "microsoft") {
		expect(authorization.pathname).toBe(
			`/${runtimeFixtureMicrosoft.tenantId}/oauth2/v2.0/authorize`,
		);
		expect(authorization.searchParams.get("nonce")).toBeTruthy();
	}
	const state = authorization.searchParams.get("state");
	expect(state).toBeTruthy();
	const query = new URLSearchParams({
		state: state!,
		code: runtimeProviderFixtureCode(authorization),
	});
	return {
		path: `${transport.prefix}/callback/${provider}?${query}`,
		cookie: cookie(started),
	};
}

async function startFixtureApple(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: {
		prefix: string;
		callback: string;
		destination: string;
		host?: string;
		clientIP?: string;
		cookie?: string;
	},
) {
	const started = await service.request(`${transport.prefix}/sign-in/social`, {
		host: transport.host,
		clientIP: transport.clientIP,
		cookie: transport.cookie,
		body: {
			provider: "apple",
			callbackURL: transport.destination,
			disableRedirect: true,
			additionalParams: { locale: "en_US" },
		},
	});
	expect(
		started.status,
		started.ok ? undefined : await started.clone().text(),
	).toBe(200);
	const authorization = await fixtureRedirect(started);
	expect(authorization.origin).toBe(runtimeFixtureAppleOrigin);
	expect(authorization.pathname).toBe("/auth/authorize");
	for (const [key, value] of Object.entries({
		client_id: runtimeFixtureApple.clientId,
		redirect_uri: transport.callback,
		response_mode: "form_post",
		response_type: "code id_token",
		locale: "en_US",
	}))
		expect(authorization.searchParams.get(key)).toBe(value);
	const state = authorization.searchParams.get("state");
	expect(state).toBeTruthy();
	expect(authorization.searchParams.get("nonce")).toBeTruthy();
	expect(started.headers.getSetCookie()).toEqual(
		expect.arrayContaining([expect.stringMatching(/SameSite=None/i)]),
	);
	return {
		path: `${transport.prefix}/callback/apple`,
		cookie: cookie(started),
		host: transport.host,
		clientIP: transport.clientIP,
		body: new URLSearchParams({
			state: state!,
			code: runtimeProviderFixtureCode(authorization),
			id_token: "synthetic-front-channel-value",
		}),
	};
}

async function finishFixtureApple(
	service: Awaited<ReturnType<typeof openProcess>>,
	attempt: Awaited<ReturnType<typeof startFixtureApple>>,
) {
	const { path, cookie, host, clientIP, body } = attempt;
	const continued = await service.request(path, {
		cookie,
		host,
		clientIP,
		body,
		origin: runtimeFixtureAppleOrigin,
	});
	expect(continued.status).toBe(302);
	const next = await fixtureRedirect(continued);
	expect(next.pathname).toBe(path);
	return service.request(next.pathname + next.search, {
		cookie,
		host,
		clientIP,
	});
}

async function issueFixtureTokens(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: { prefix: string; issuer: string; host?: string; cookie: string },
) {
	const state = randomUUID();
	const query = fixtureAuthorizationQuery(state);
	const authorization = await service.request(
		`${transport.prefix}/oauth2/authorize?${query}`,
		transport,
	);
	const callback = await fixtureRedirect(authorization);
	expect(callback.origin + callback.pathname).toBe(oauthRedirectURI);
	expect(callback.searchParams.get("state")).toBe(state);
	expect(callback.searchParams.get("iss")).toBe(transport.issuer);
	const response = await service.request(`${transport.prefix}/oauth2/token`, {
		host: transport.host,
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: oauthClientId,
			redirect_uri: oauthRedirectURI,
			code: callback.searchParams.get("code") ?? "",
			code_verifier: oauthVerifier,
		}),
	});
	expect(
		response.status,
		response.ok ? undefined : await response.clone().text(),
	).toBe(200);
	const tokens = (await response.json()) as { id_token: string };
	const keyResponse = await service.request(`${transport.prefix}/jwks`, {
		host: transport.host,
	});
	expect(keyResponse.status).toBe(200);
	const keys = (await keyResponse.json()) as JSONWebKeySet;
	await jwtVerify(tokens.id_token, createLocalJWKSet(keys), {
		issuer: transport.issuer,
		audience: oauthClientId,
	});
	return keys;
}

type RuntimePersonalKey = {
	id: string;
	key?: string;
	name: string;
	enabled: boolean;
	referenceId: string;
};

type ApiKeyTransport = { prefix: string; host?: string; cookie: string };

async function runtimeApiKeys(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: ApiKeyTransport,
) {
	const response = await service.request(
		`${transport.prefix}/api-key/list?sortBy=name&sortDirection=asc`,
		transport,
	);
	expect(
		response.status,
		response.ok ? undefined : await response.clone().text(),
	).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	const result = (await response.json()) as {
		apiKeys: RuntimePersonalKey[];
		total: number;
	};
	expect(result.apiKeys.every((key) => !("key" in key))).toBe(true);
	return result;
}

async function runtimeCreateApiKey(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: ApiKeyTransport,
	name: string,
) {
	const response = await service.request(`${transport.prefix}/api-key/create`, {
		...transport,
		body: { name },
	});
	expect(
		response.status,
		response.ok ? undefined : await response.clone().text(),
	).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	const key = (await response.json()) as RuntimePersonalKey;
	expect(key).toMatchObject({
		id: expect.any(String),
		name,
		enabled: true,
		key: expect.stringMatching(/^allauth_[A-Za-z]{64}$/),
		referenceId: credentials.project.id,
	});
	return key;
}

async function runtimeGetApiKey(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: ApiKeyTransport,
	keyId: string,
	status = 200,
) {
	const response = await service.request(
		`${transport.prefix}/api-key/get?id=${encodeURIComponent(keyId)}`,
		transport,
	);
	expect(
		response.status,
		response.ok ? undefined : await response.clone().text(),
	).toBe(status);
	const result = (await response.json()) as RuntimePersonalKey;
	expect(result).not.toHaveProperty("key");
	return result;
}

async function exerciseOwnedApiKeys(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: ApiKeyTransport,
	legacy: RuntimePersonalKey,
	createdName: string,
) {
	expect((await runtimeApiKeys(service, transport)).apiKeys).toEqual(
		expect.arrayContaining([
			expect.objectContaining({ id: legacy.id, name: legacy.name }),
		]),
	);
	expect(await runtimeGetApiKey(service, transport, legacy.id)).toMatchObject({
		id: legacy.id,
		enabled: true,
	});
	const created = await runtimeCreateApiKey(service, transport, createdName);
	const updatedName = `${createdName} renamed`;
	const updated = await service.request(`${transport.prefix}/api-key/update`, {
		...transport,
		body: {
			keyId: created.id,
			name: updatedName,
			enabled: false,
			expiresIn: null,
		},
	});
	expect(
		updated.status,
		updated.ok ? undefined : await updated.clone().text(),
	).toBe(200);
	const changed = (await updated.json()) as RuntimePersonalKey;
	expect(changed).toMatchObject({
		id: created.id,
		name: updatedName,
		enabled: false,
		expiresAt: null,
	});
	expect(changed).not.toHaveProperty("key");
	const removed = await service.request(`${transport.prefix}/api-key/delete`, {
		...transport,
		body: { keyId: legacy.id },
	});
	expect(removed.status).toBe(200);
	expect(await removed.json()).toEqual({ success: true });
	expect(
		await runtimeGetApiKey(service, transport, legacy.id, 404),
	).toMatchObject({ code: "KEY_NOT_FOUND" });
	return changed;
}

async function seed(databaseURL: string) {
	await promisify(execFile)(
		process.execPath,
		["scripts/database.mjs", "migrate"],
		{
			cwd: appRoot,
			env: { ...childEnvironment(), DATABASE_URL: databaseURL },
		},
	);
	const env = { ...childEnvironment(), DATABASE_URL: databaseURL };
	const database = projectRegistryPool(env);
	const cwd = vi.spyOn(process, "cwd").mockReturnValue(appRoot);
	try {
		const hash = await clerkCompatiblePasswords.hash(credentials.password);
		async function insertAccount(
			schema: string,
			account: { id: string; email: string },
		) {
			await database.query(
				`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Fixture User',$2,true,'user')`,
				[account.id, account.email],
			);
			await database.query(
				`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt") VALUES ($1,$1,'credential',$1,$2,now())`,
				[account.id, hash],
			);
			await database.query(
				`INSERT INTO "${schema}"."allauthSecurityPolicy" (id,policy) VALUES ('default',$1::jsonb)`,
				[
					JSON.stringify({
						...defaultSecurityPolicy,
						newDeviceNotifications: false,
					}),
				],
			);
		}
		await insertAccount("public", credentials.platform);
		const owner: ControlPrincipal = {
			user: {
				...credentials.platform,
				name: "Fixture Owner",
				emailVerified: true,
			},
			session: { id: randomUUID(), userId: credentials.platform.id },
		};
		await database.query(
			`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 hour',now())`,
			[owner.session.id, randomUUID(), owner.user.id],
		);
		const { workspace } = await createWorkspace(
			owner,
			{ name: "Project Runtime Fixture", slug: "runtime-fixture" },
			env,
		);
		async function provision(slug: string, origins: string[] = []) {
			const project = await provisionProject(
				{
					name: slug,
					slug,
					primaryOrigin: `https://${slug}.runtime.fixture.example`,
					origins,
					environment: "development",
				},
				{
					clientId: `fixture-${slug}`,
					clientSecret: "disposable-fixture-broker-client-secret",
				},
				owner.user.id,
				env,
				{ workspaceId: workspace.id, principal: owner },
			);
			await insertAccount(project.schemaName, credentials.project);
			await database.query(
				`INSERT INTO "${project.schemaName}"."oauthClient" (id,"clientId","redirectUris","grantTypes",scopes,"tokenEndpointAuthMethod","skipConsent","backchannelLogoutUri","createdAt","updatedAt")
			VALUES ($1,$1,$2::jsonb,'["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]','["openid","profile"]','none',true,$3,now(),now())`,
				[
					oauthClientId,
					JSON.stringify([oauthRedirectURI]),
					"https://rp.runtime.fixture.example/logout",
				],
			);
			return project;
		}
		const alpha = await provision("runtime-owned-fixture", [supportOrigin]);
		const beta = await provision("runtime-control-fixture");
		const samlKeys = await createRuntimeSamlKeys();
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."ssoProvider" (id,"providerId",issuer,domain,"domainVerified","userId","samlConfig")
			 VALUES ($1,$1,$2,'runtime.fixture.example',TRUE,$3,$4)`,
			[
				runtimeSamlProvider,
				runtimeSamlEntity,
				credentials.project.id,
				JSON.stringify(runtimeSamlConfiguration(samlKeys)),
			],
		);
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."account" (id,"accountId","providerId","userId","updatedAt")
			 VALUES ($1,$2,$3,$4,now())`,
			[
				randomUUID(),
				runtimeSamlSubject,
				runtimeSamlProvider,
				credentials.project.id,
			],
		);
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Fixture Support Target',$2,true,'user')`,
			[supportTarget, "support-target@runtime.fixture.example"],
		);
		await authPolicyRepository(database).update(
			alpha.id,
			0,
			{
				...defaultAuthPolicy,
				supportAccess: { enabled: true, callbackUrl: supportCallback },
			},
			owner.user.id,
		);
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."organization" (id,name,slug,"createdAt") VALUES ($1,'Fixture Directory',$1,now())`,
			[directoryOrg],
		);
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."member" (id,"userId","organizationId",role,"createdAt") VALUES ($1,$2,$3,'owner',now())`,
			[randomUUID(), credentials.project.id, directoryOrg],
		);
		await database.query(
			`INSERT INTO "${alpha.schemaName}"."ssoProvider" (id,"providerId",issuer,domain,"domainVerified","organizationId","userId","oidcConfig")
			 VALUES ($1,$1,$2,'directory.fixture.example',TRUE,$3,$4,$5)`,
			[
				directoryProvider,
				directoryIssuer,
				directoryOrg,
				credentials.project.id,
				JSON.stringify({
					issuer: directoryIssuer,
					clientId: "synthetic-directory-client",
					clientSecret: "synthetic-directory-credential",
					authorizationEndpoint: `${directoryIssuer}/authorize`,
					tokenEndpoint: `${directoryIssuer}/token`,
					jwksEndpoint: `${directoryIssuer}/jwks`,
					pkce: true,
				}),
			],
		);
		await googleProviderRepository(database, env).update(
			alpha,
			{
				version: 0,
				google: {
					enabled: true,
					clientId: runtimeFixtureGoogle.clientId,
					clientSecret: runtimeFixtureGoogle.clientSecret,
				},
			},
			owner.user.id,
		);
		return { alpha, beta, samlKeys };
	} finally {
		cwd.mockRestore();
		await database.end();
	}
}

describe.skipIf(!existsSync(fixture))(
	"isolated project service process cutover and rollback",
	() => {
		it("starts old, owned and old writers in sequence while preserving a live project session", async () => {
			const local: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixture, "utf8"),
			);
			const base = new URL(local.DATABASE_URL);
			if (
				local.container !== "allauth-production-test-20261007" ||
				base.hostname !== "127.0.0.1" ||
				base.port !== "55445"
			)
				throw new Error(
					"Project runtime cutover requires the isolated local PostgreSQL fixture.",
				);
			const admin = new Pool({ connectionString: base.href, max: 1 });
			const source = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const restored = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const created: string[] = [];
			const url = (name: string) => new URL(`/${name}`, base).href;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${source}"`);
				created.push(source);
				const { alpha, beta, samlKeys } = await seed(url(source));
				const [appleCredentialKeys, appleIssuerKeys] = await Promise.all([
					generateKeyPair("ES256", { extractable: true }),
					generateKeyPair("RS256", { extractable: true }),
				]);
				const appleFixture = {
					credentialKey: await exportPKCS8(appleCredentialKeys.privateKey),
					issuerKey: await exportPKCS8(appleIssuerKeys.privateKey),
				};
				const open = (
					name: string,
					owned: boolean,
					microsoftProject = alpha.slug,
					appleProject = alpha.slug,
				) =>
					openProcess(url(name), alpha, owned, microsoftProject, {
						...appleFixture,
						project: appleProject,
					});
				const appleDirectEmail =
					"apple-native-unverified@runtime.fixture.example";
				const appleDirectSubject = "fixture-runtime-apple-direct-subject";
				const alphaPath = `/api/projects/${alpha.slug}/auth`;
				const betaPath = `/api/projects/${beta.slug}/auth`;
				const alphaHost = `${alpha.slug}-accounts.allauth.co`;
				const directIssuer = `${platformOrigin}${alphaPath}`;
				const hostedIssuer = `https://${alphaHost}/api/auth`;
				const hostedProvider = {
					prefix: "/api/auth",
					host: alphaHost,
					destination: `https://${alphaHost}/account`,
					clientIP: "192.0.2.57",
				};
				const directProvider = {
					prefix: alphaPath,
					destination: `${alpha.primaryOrigin}/account`,
				};
				const samlTransports: SamlTransport[] = [
					{
						prefix: alphaPath,
						baseURL: directIssuer,
						destination: `${platformOrigin}/account?from=runtime-saml`,
					},
					{
						prefix: "/api/auth",
						baseURL: hostedIssuer,
						host: alphaHost,
						destination: `https://${alphaHost}/account?from=runtime-saml`,
					},
				];
				const betaHost = `${beta.slug}-accounts.allauth.co`;
				const login = {
					email: credentials.project.email,
					password: credentials.password,
				};
				const management = (project: Project) =>
					`/api/admin/organizations?project=${project.slug}`;
				const scimManagement = `/api/organizations/${directoryOrg}/scim`;
				const scimProject = `?project=${alpha.slug}`;
				const hostedScim = "/api/auth/scim/v2/Users";
				const directScim = `${alphaPath}/scim/v2/Users`;
				const scimName = "directory-user@runtime.fixture.example";
				const wallet = privateKeyToAccount(generatePrivateKey());
				const directWallet = {
					prefix: alphaPath,
					origin: alpha.primaryOrigin,
					proxy: alpha,
				};
				const hostedWallet = {
					prefix: "/api/auth",
					origin: `https://${alphaHost}`,
					host: alphaHost,
				};
				async function walletProof(
					writer: Awaited<ReturnType<typeof openProcess>>,
					transport: typeof directWallet | typeof hostedWallet,
					chainId: number,
					alias = "nonce",
					signer = wallet,
				) {
					const challenged = await writer.request(
						`${transport.prefix}/siwe/${alias}`,
						{ ...transport, body: {} },
					);
					expect(
						challenged.status,
						challenged.ok ? undefined : await challenged.clone().text(),
					).toBe(200);
					const { nonce } = (await challenged.json()) as { nonce: string };
					const message = createSiweMessage({
						address: signer.address,
						domain: new URL(transport.origin).host,
						uri: `${transport.origin}/account`,
						chainId,
						nonce,
						version: "1",
					});
					return {
						message,
						signature: await signer.signMessage({ message }),
						email: "wallet@runtime.fixture.example",
					};
				}
				service = await open(source, false);
				expect((await service.request("/api/health")).status).toBe(200);
				const nativeSaml = [];
				for (const transport of samlTransports)
					nativeSaml.push(await startRuntimeSaml(service, transport));
				const rootLogin = await service.request("/api/auth/sign-in/email", {
					body: {
						email: credentials.platform.email,
						password: credentials.password,
					},
				});
				expect(rootLogin.status).toBe(200);
				const rootCookie = cookie(rootLogin);
				const walletSignup = await walletProof(service, directWallet, 1);
				const nativeWallet = await service.request(`${alphaPath}/siwe/verify`, {
					...directWallet,
					body: walletSignup,
				});
				expect(
					nativeWallet.status,
					nativeWallet.ok ? undefined : await nativeWallet.clone().text(),
				).toBe(200);
				const walletId = (
					(await nativeWallet.json()) as { user: { id: string } }
				).user.id;
				const nativeWalletProof = await walletProof(service, directWallet, 137);
				const directory = await service.request(scimManagement + scimProject, {
					cookie: rootCookie,
					body: { providerId: directoryProvider },
				});
				expect(
					directory.status,
					directory.ok ? undefined : await directory.clone().text(),
				).toBe(201);
				const nativeDirectory = (await directory.json()) as {
					connection: { connectionId: string };
					token: string;
				};
				const nativeDirectoryAuth = {
					authorization: `Bearer ${nativeDirectory.token}`,
				};
				expect(nativeDirectory.token).toEqual(expect.any(String));
				expect(
					(
						await service.request(hostedScim, {
							...nativeDirectoryAuth,
							host: alphaHost,
						})
					).status,
				).toBe(200);
				const impersonation = await service.request(
					`${alphaPath}/project-admin/impersonate-user`,
					{
						cookie: rootCookie,
						body: { userId: supportTarget },
					},
				);
				expect(impersonation.status).toBe(200);
				const impersonationId = (
					(await impersonation.json()) as { session: { id: string } }
				).session.id;
				const supportCookies = `${rootCookie}; ${cookie(impersonation)}`;
				const nativeLaunch = await service.request(
					`${alphaPath}/project-admin/support/launch`,
					{
						cookie: supportCookies,
						body: {},
					},
				);
				expect(nativeLaunch.status).toBe(200);
				const nativeLaunchURL = new URL(
					((await nativeLaunch.json()) as { url: string }).url,
				);
				expect(nativeLaunchURL.origin).toBe(supportOrigin);
				const directLogin = await service.request(
					`${alphaPath}/sign-in/email`,
					{ body: login },
				);
				expect(directLogin.status).toBe(200);
				const legacyCookie = cookie(directLogin);
				const hostedLogin = await service.request("/api/auth/sign-in/email", {
					host: alphaHost,
					body: login,
				});
				expect(hostedLogin.status).toBe(200);
				const legacyHostedCookie = cookie(hostedLogin);
				const avatar = {
					contentType: "image/jpeg",
					data: Buffer.from([255, 216, 255, 0, 255, 217]).toString("base64"),
				};
				const avatarBase = `${runtimeFixtureAssetOrigin}/branding/${alpha.workspaceId}/${alpha.applicationId}/`;
				const legacyAvatar = await service.request("/api/auth/sdk/avatar", {
					host: alphaHost,
					cookie: legacyHostedCookie,
					body: avatar,
				});
				expect(legacyAvatar.status).toBe(200);
				expect(
					((await legacyAvatar.json()) as { url: string }).url.startsWith(
						avatarBase,
					),
				).toBe(true);
				const nativeDirectKey = await runtimeCreateApiKey(
					service,
					{ prefix: alphaPath, cookie: legacyCookie },
					"Native direct",
				);
				const nativeHostedKey = await runtimeCreateApiKey(
					service,
					{ prefix: "/api/auth", host: alphaHost, cookie: legacyHostedCookie },
					"Native hosted",
				);

				const nativeGoogle = await startFixtureProvider(service, "google", {
					...hostedProvider,
					callback: `${hostedIssuer}/callback/google`,
				});
				const nativeGuest = await service.request(
					`${alphaPath}/sign-in/anonymous`,
					{ body: {} },
				);
				expect(nativeGuest.status).toBe(200);
				const nativeGuestData = (await nativeGuest.json()) as {
					user: { id: string };
				};
				const hostedGuest = await service.request(
					"/api/auth/sign-in/anonymous",
					{
						host: alphaHost,
						clientIP: "192.0.2.64",
						body: {},
					},
				);
				expect(hostedGuest.status).toBe(200);
				const nativeApple = await startFixtureApple(service, {
					...hostedProvider,
					clientIP: "192.0.2.64",
					callback: `${hostedIssuer}/callback/apple`,
					cookie: cookie(hostedGuest),
				});
				const legacyContinuation = await fixtureRedirect(
					await service.request(
						`/api/auth/oauth2/authorize?${fixtureAuthorizationQuery()}`,
						{ host: alphaHost },
					),
				);
				expect(legacyContinuation.pathname).toBe("/sign-in");
				expect(legacyContinuation.searchParams.has("sig")).toBe(true);
				const oauthCallback = new URL(
					`/oauth2/continue${legacyContinuation.search}`,
					`https://${alphaHost}`,
				);
				expect(
					(await service.request(management(alpha), { cookie: rootCookie }))
						.status,
				).toBe(200);
				await service.stop();
				service = undefined;
				await admin.query(`CREATE DATABASE "${restored}" TEMPLATE "${source}"`);
				created.push(restored);

				service = await open(restored, true);
				expect((await service.request("/api/health")).status).toBe(200);
				const ownedSaml = [];
				for (const started of nativeSaml) {
					const { transport } = started;
					const metadata = await service.request(
						`${transport.prefix}/sso/saml2/sp/metadata?providerId=${runtimeSamlProvider}`,
						{ host: transport.host },
					);
					expect(metadata.status).toBe(200);
					expect(await metadata.text()).toContain(
						`Location="${started.flow.acs}"`,
					);
					const samlCookie = await finishRuntimeSaml(
						service,
						samlKeys,
						started,
					);
					const customMetadata = await service.request(
						`${transport.prefix}/sso/update-provider`,
						{
							host: transport.host,
							cookie: samlCookie,
							body: {
								providerId: runtimeSamlProvider,
								samlConfig: {
									spMetadata: {
										metadata: runtimeSamlSPMetadata(started.flow.acs),
									},
								},
							},
						},
					);
					expect(
						customMetadata.status,
						customMetadata.ok ? undefined : await customMetadata.clone().text(),
					).toBe(400);
					expect(await customMetadata.json()).toMatchObject({
						code: "SSO_CONFIGURATION_UNSUPPORTED",
					});
					ownedSaml.push(await startRuntimeSaml(service, transport));
				}
				const compatibleWallet = await service.request(
					`${alphaPath}/siwe/verify`,
					{ ...directWallet, body: nativeWalletProof },
				);
				expect(
					compatibleWallet.status,
					compatibleWallet.ok
						? undefined
						: await compatibleWallet.clone().text(),
				).toBe(200);
				expect(await compatibleWallet.json()).toMatchObject({
					success: true,
					user: { id: walletId, walletAddress: wallet.address, chainId: 137 },
				});
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: cookie(compatibleWallet),
						})
					).json(),
				).toMatchObject({
					user: {
						id: walletId,
						email: walletSignup.email,
						emailVerified: false,
					},
				});
				const replay = await service.request(`${alphaPath}/siwe/verify`, {
					...directWallet,
					body: nativeWalletProof,
				});
				expect(replay.status).toBe(401);
				expect(await replay.json()).toMatchObject({
					code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
				});
				const newWallet = privateKeyToAccount(generatePrivateKey());
				const hostedWalletSignup = await walletProof(
					service,
					hostedWallet,
					1,
					"nonce",
					newWallet,
				);
				const ownedWalletSignup = await service.request(
					"/api/auth/siwe/verify",
					{
						...hostedWallet,
						body: { ...hostedWalletSignup, email: credentials.project.email },
					},
				);
				expect(
					ownedWalletSignup.status,
					ownedWalletSignup.ok
						? undefined
						: await ownedWalletSignup.clone().text(),
				).toBe(200);
				const ownedWalletId = (
					(await ownedWalletSignup.json()) as { user: { id: string } }
				).user.id;
				expect(ownedWalletId).not.toBe(credentials.project.id);
				const wrongOriginProof = await walletProof(service, directWallet, 1);
				const wrongMessage = wrongOriginProof.message.replace(
					`URI: ${directWallet.origin}/account`,
					"URI: https://other.runtime.fixture.example/account",
				);
				const wrongOrigin = await service.request(`${alphaPath}/siwe/verify`, {
					...directWallet,
					body: {
						...wrongOriginProof,
						message: wrongMessage,
						signature: await wallet.signMessage({ message: wrongMessage }),
					},
				});
				expect(wrongOrigin.status).toBe(401);
				expect(await wrongOrigin.json()).toMatchObject({
					code: "UNAUTHORIZED_INVALID_SIGNATURE",
				});
				const burned = await service.request(`${alphaPath}/siwe/verify`, {
					...directWallet,
					body: wrongOriginProof,
				});
				expect(await burned.json()).toMatchObject({
					code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
				});
				const ownedWalletProof = await walletProof(
					service,
					hostedWallet,
					10,
					"get-nonce",
				);
				const guestCookies = cookie(nativeGuest);
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: guestCookies,
						})
					).json(),
				).toMatchObject({
					user: {
						id: nativeGuestData.user.id,
						isAnonymous: true,
						emailVerified: false,
						role: "guest",
					},
				});
				const upgraded = await service.request(`${alphaPath}/sign-in/email`, {
					cookie: guestCookies,
					body: login,
				});
				expect(
					upgraded.status,
					upgraded.ok ? undefined : await upgraded.clone().text(),
				).toBe(200);
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: guestCookies,
						})
					).json(),
				).toBeNull();
				const deleteGuest = await service.request(
					`${alphaPath}/sign-in/anonymous`,
					{ body: {} },
				);
				expect(deleteGuest.status).toBe(200);
				const repeatedGuest = await service.request(
					`${alphaPath}/sign-in/anonymous`,
					{ cookie: cookie(deleteGuest), body: {} },
				);
				expect(repeatedGuest.status).toBe(400);
				expect(await repeatedGuest.json()).toMatchObject({
					code: "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
				});
				const deletedGuest = await service.request(
					`${alphaPath}/delete-anonymous-user`,
					{ cookie: cookie(deleteGuest), body: {} },
				);
				expect(deletedGuest.status).toBe(200);
				expect(await deletedGuest.json()).toEqual({ success: true });
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: cookie(deleteGuest),
						})
					).json(),
				).toBeNull();
				const candidateGuest = await service.request(
					"/api/auth/sign-in/anonymous",
					{ host: alphaHost, body: {} },
				);
				expect(
					candidateGuest.status,
					candidateGuest.ok ? undefined : await candidateGuest.clone().text(),
				).toBe(200);
				const candidateGuestData = (await candidateGuest.json()) as {
					user: { id: string };
				};
				for (const [path, host, issuer] of [
					[`${alphaPath}/sign-in/sso`, undefined, directIssuer],
					["/api/auth/sign-in/sso", alphaHost, hostedIssuer],
				] as const) {
					const started = await service.request(path, {
						host,
						body: {
							providerId: directoryProvider,
							callbackURL: `${host ? `https://${host}` : platformOrigin}/account`,
						},
					});
					expect(
						started.status,
						started.ok ? undefined : await started.clone().text(),
					).toBe(200);
					const authorization = await fixtureRedirect(started);
					expect(`${authorization.origin}${authorization.pathname}`).toBe(
						`${directoryIssuer}/authorize`,
					);
					expect(authorization.searchParams.get("redirect_uri")).toBe(
						`${issuer}/sso/callback/${directoryProvider}`,
					);
				}
				const directoryList = await service.request(
					scimManagement + scimProject,
					{ cookie: rootCookie },
				);
				expect(directoryList.status).toBe(200);
				expect(await directoryList.json()).toMatchObject({
					connections: [
						{
							connection: {
								connectionId: nativeDirectory.connection.connectionId,
							},
							providerId: directoryProvider,
						},
					],
				});
				expect(
					(
						await service.request(hostedScim, {
							...nativeDirectoryAuth,
							host: betaHost,
						})
					).status,
				).toBe(401);
				const added = await service.request(hostedScim, {
					...nativeDirectoryAuth,
					host: alphaHost,
					body: {
						schemas: [scimUser],
						userName: scimName,
						emails: [{ value: scimName, primary: true }],
						active: true,
					},
				});
				expect(
					added.status,
					added.ok ? undefined : await added.clone().text(),
				).toBe(201);
				const directoryUserId = ((await added.json()) as { id: string }).id;
				const patched = await service.request(
					`${directScim}/${encodeURIComponent(directoryUserId)}`,
					{
						...nativeDirectoryAuth,
						method: "PATCH",
						body: {
							schemas: [scimPatch],
							Operations: [{ op: "replace", path: "active", value: false }],
						},
					},
				);
				expect(
					patched.status,
					patched.ok ? undefined : await patched.clone().text(),
				).toBe(200);
				expect(await patched.json()).toMatchObject({
					id: directoryUserId,
					active: false,
				});
				const rotatedDirectory = await service.request(
					`${scimManagement}/${nativeDirectory.connection.connectionId}/rotate${scimProject}`,
					{ cookie: rootCookie, body: {} },
				);
				expect(
					rotatedDirectory.status,
					rotatedDirectory.ok
						? undefined
						: await rotatedDirectory.clone().text(),
				).toBe(200);
				const ownedDirectoryToken = (
					(await rotatedDirectory.json()) as { token: string }
				).token;
				expect(ownedDirectoryToken).toEqual(expect.any(String));
				expect(ownedDirectoryToken).not.toBe(nativeDirectory.token);
				const supportStatus = await service.request(
					`${alphaPath}/project-admin/support/status`,
					{ cookie: supportCookies },
				);
				expect(await supportStatus.json()).toEqual({
					enabled: true,
					callbackUrl: supportCallback,
					launchAvailable: true,
				});
				const supportSession = await service.request(
					`${alphaPath}/get-session`,
					{ cookie: supportCookies },
				);
				expect(await supportSession.json()).toMatchObject({
					session: {
						id: impersonationId,
						impersonatedBy: credentials.platform.id,
					},
					user: { id: supportTarget },
				});
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: cookie(impersonation),
						})
					).json(),
				).toBeNull();
				const state = randomBytes(32).toString("base64url");
				const codeVerifier = randomBytes(32).toString("base64url");
				const supportQuery = new URLSearchParams({
					launch: nativeLaunchURL.searchParams.get("launch")!,
					state,
					codeChallenge: createHash("sha256")
						.update(codeVerifier)
						.digest("base64url"),
				});
				const supported = await fixtureRedirect(
					await service.request(
						`${alphaPath}/project-admin/support/authorize?${supportQuery}`,
						{ cookie: supportCookies },
					),
				);
				expect(supported.href.split("?", 1)[0]).toBe(supportCallback);
				expect(supported.searchParams.get("state")).toBe(state);
				const signedSupport = { origin: supportOrigin, proxy: alpha };
				const exchangedSupport = await service.request(
					`${alphaPath}/sdk/support/exchange`,
					{
						...signedSupport,
						body: {
							code: supported.searchParams.get("code"),
							state,
							codeVerifier,
							callbackUrl: supportCallback,
						},
					},
				);
				expect(
					exchangedSupport.status,
					exchangedSupport.ok
						? undefined
						: await exchangedSupport.clone().text(),
				).toBe(200);
				expect(await exchangedSupport.json()).toMatchObject({
					session: { id: impersonationId },
					user: { id: supportTarget },
					actor: { id: credentials.platform.id },
				});
				const connectedSupport = {
					...signedSupport,
					cookie: cookie(exchangedSupport),
				};
				const switchedApple = await finishFixtureApple(service, nativeApple);
				expect(switchedApple.headers.get("location")).toBe(
					hostedProvider.destination,
				);
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: cookie(hostedGuest),
						})
					).json(),
				).toBeNull();
				const appleBrowserSession = await service.request(
					"/api/auth/get-session",
					{ host: alphaHost, cookie: cookie(switchedApple) },
				);
				const appleBrowserUser = (
					(await appleBrowserSession.json()) as {
						user: { id: string; email: string; emailVerified: boolean };
					}
				).user;
				expect(appleBrowserUser).toMatchObject({
					id: expect.any(String),
					email: runtimeFixtureApple.email,
					emailVerified: true,
				});
				const ownedAppleGuest = await service.request(
					`${alphaPath}/sign-in/anonymous`,
					{ body: {} },
				);
				expect(ownedAppleGuest.status).toBe(200);
				const ownedApple = await startFixtureApple(service, {
					...directProvider,
					callback: `${alpha.primaryOrigin}/api/allauth/callback/apple`,
					cookie: cookie(ownedAppleGuest),
				});
				const reservedApple = await service.request(
					`${alphaPath}/sign-in/social`,
					{
						body: {
							provider: "apple",
							additionalParams: {
								redirect_uri: "https://unregistered.fixture.example/callback",
							},
						},
					},
				);
				expect(reservedApple.status).toBe(400);
				const nativeAppleToken = await new SignJWT({
					email: appleDirectEmail,
					email_verified: false,
				})
					.setProtectedHeader({
						alg: "RS256",
						kid: "runtime-provider-fixture-key",
					})
					.setIssuer(runtimeFixtureAppleOrigin)
					.setAudience(runtimeFixtureApple.appBundleIdentifier)
					.setSubject(appleDirectSubject)
					.setIssuedAt()
					.setExpirationTime("5m")
					.sign(appleIssuerKeys.privateKey);
				const appleVerificationCallback = `https://${alphaHost}/account/security?from=apple`;
				const appleSignUp = await service.request("/api/auth/sign-in/social", {
					host: alphaHost,
					clientIP: "192.0.2.65",
					body: {
						provider: "apple",
						callbackURL: appleVerificationCallback,
						idToken: { token: nativeAppleToken },
					},
				});
				expect(
					appleSignUp.status,
					appleSignUp.ok ? undefined : await appleSignUp.clone().text(),
				).toBe(200);
				expect(await appleSignUp.json()).toMatchObject({
					redirect: false,
					user: { email: appleDirectEmail, emailVerified: false },
				});
				const appleVerification = await fixtureVerificationMail(
					service,
					appleDirectEmail,
				);
				expect(appleVerification.origin).toBe(`https://${alphaHost}`);
				expect(appleVerification.searchParams.get("callbackURL")).toBe(
					appleVerificationCallback,
				);
				const verifiedApple = await service.request(
					appleVerification.pathname + appleVerification.search,
					{
						host: alphaHost,
						cookie: cookie(appleSignUp),
						clientIP: "192.0.2.65",
					},
				);
				expect(verifiedApple.headers.get("location")).toBe(
					appleVerificationCallback,
				);
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: cookie(appleSignUp),
						})
					).json(),
				).toMatchObject({
					user: { email: appleDirectEmail, emailVerified: true },
				});
				const switchedGoogle = await service.request(nativeGoogle.path, {
					host: alphaHost,
					cookie: nativeGoogle.cookie,
					clientIP: "192.0.2.57",
				});
				expect(switchedGoogle.headers.get("location")).toBe(
					hostedProvider.destination,
				);
				const googleSession = await service.request("/api/auth/get-session", {
					host: alphaHost,
					cookie: cookie(switchedGoogle),
				});
				expect(await googleSession.json()).toMatchObject({
					user: { email: runtimeFixtureGoogle.email, emailVerified: true },
				});
				await startFixtureProvider(service, "google", {
					...directProvider,
					callback: `${alpha.primaryOrigin}/api/allauth/callback/google`,
				});
				await startFixtureProvider(service, "microsoft", {
					...hostedProvider,
					clientIP: "192.0.2.58",
					callback: `${hostedIssuer}/callback/microsoft`,
				});
				const ownedMicrosoft = await startFixtureProvider(
					service,
					"microsoft",
					{
						...directProvider,
						callback: `${alpha.primaryOrigin}/api/allauth/callback/microsoft`,
					},
				);
				expect(
					await (await service.request(`${alphaPath}/sdk/config`)).json(),
				).toMatchObject({
					apiKeys: true,
					googleProvider: "google",
					microsoftProvider: "microsoft",
					apple: true,
					appleProvider: "apple",
					profileImageUpload: true,
					profileImageOwnershipAndDeletion: false,
				});
				const directAvatar = await service.request(`${alphaPath}/sdk/avatar`, {
					cookie: legacyCookie,
					body: avatar,
				});
				expect(directAvatar.status).toBe(200);
				expect(
					((await directAvatar.json()) as { url: string }).url.startsWith(
						avatarBase,
					),
				).toBe(true);
				const hostedAvatar = await service.request("/api/auth/sdk/avatar", {
					host: alphaHost,
					cookie: legacyHostedCookie,
					body: avatar,
				});
				expect(hostedAvatar.status).toBe(200);
				const { url: savedImage } = (await hostedAvatar.json()) as {
					url: string;
				};
				expect(savedImage.startsWith(avatarBase)).toBe(true);
				expect(
					(
						await service.request("/api/auth/update-user", {
							host: alphaHost,
							cookie: legacyHostedCookie,
							body: { image: savedImage },
						})
					).status,
				).toBe(200);
				const directDiscovery = await service.request(
					`${alphaPath}/.well-known/openid-configuration`,
				);
				expect(await directDiscovery.json()).toMatchObject({
					issuer: directIssuer,
					token_endpoint: `${directIssuer}/oauth2/token`,
				});
				const hostedDiscovery = await service.request(
					"/.well-known/openid-configuration",
					{ host: alphaHost },
				);
				expect(await hostedDiscovery.json()).toMatchObject({
					issuer: hostedIssuer,
					authorization_endpoint: `${hostedIssuer}/oauth2/authorize`,
					end_session_endpoint: `${hostedIssuer}/oauth2/end-session`,
					device_authorization_endpoint: `${hostedIssuer}/device/code`,
				});
				const device = await service.request("/api/auth/device/code", {
					host: alphaHost,
					body: new URLSearchParams({
						client_id: oauthClientId,
						scope: "openid",
					}),
				});
				expect(
					device.status,
					device.ok ? undefined : await device.clone().text(),
				).toBe(200);
				expect(await device.json()).toMatchObject({
					verification_uri: `${platformOrigin}/device?project=${alpha.slug}`,
				});
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: legacyCookie,
						})
					).json(),
				).toMatchObject({
					user: { id: credentials.project.id, image: savedImage },
				});
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: legacyHostedCookie,
						})
					).json(),
				).toMatchObject({ user: { id: credentials.project.id } });
				const ownedOnly = await service.request(`${alphaPath}/not-installed`);
				expect(ownedOnly.status).toBe(501);
				expect(await ownedOnly.json()).toMatchObject({
					code: "ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
				});
				expect(
					(await service.request(`${betaPath}/not-installed?engine=owned`))
						.status,
				).toBe(404);
				expect(
					(
						await service.request("/api/auth/not-installed", {
							host: alphaHost,
						})
					).status,
				).toBe(501);
				expect(
					(await service.request("/api/auth/not-installed", { host: betaHost }))
						.status,
				).toBe(404);
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: betaHost,
							cookie: legacyHostedCookie,
						})
					).json(),
				).toBeNull();
				const organization = {
					name: "Fixture Organization",
					slug: "fixture-organization",
					ownerId: credentials.project.id,
				};
				expect(
					(
						await service.request(management(alpha), {
							cookie: rootCookie,
							body: organization,
						})
					).status,
				).toBe(503);
				expect(
					(
						await service.request(management(beta), {
							cookie: rootCookie,
							body: organization,
						})
					).status,
				).toBe(201);
				const ownedConfig = await service.request("/api/config", {
					host: alphaHost,
				});
				expect(ownedConfig.status).toBe(200);
				expect(await ownedConfig.json()).toMatchObject({
					apiKeys: true,
					enterpriseSSO: true,
					scim: true,
					signUpEnabled: true,
					googleProvider: "google",
					microsoftProvider: "microsoft",
					apple: true,
					appleProvider: "apple",
				});
				const legacyConfig = await service.request("/api/config", {
					host: betaHost,
				});
				expect(legacyConfig.status).toBe(200);
				expect(await legacyConfig.json()).toMatchObject({
					apiKeys: true,
					enterpriseSSO: true,
					scim: true,
					google: false,
					microsoft: false,
					apple: false,
				});
				const ownedDirectKey = await exerciseOwnedApiKeys(
					service,
					{ prefix: alphaPath, cookie: legacyCookie },
					nativeDirectKey,
					"Owned direct",
				);
				const ownedHostedKey = await exerciseOwnedApiKeys(
					service,
					{ prefix: "/api/auth", host: alphaHost, cookie: legacyHostedCookie },
					nativeHostedKey,
					"Owned hosted",
				);
				expect(
					(await service.request("/api/auth/api-key/list", { host: alphaHost }))
						.status,
				).toBe(401);
				expect(
					(
						await service.request("/api/auth/api-key/verify", {
							host: alphaHost,
							body: { key: nativeHostedKey.key },
						})
					).status,
				).toBe(404);
				const betaLogin = await service.request("/api/auth/sign-in/email", {
					host: betaHost,
					body: login,
				});
				expect(betaLogin.status).toBe(200);
				expect(
					await runtimeApiKeys(service, {
						prefix: "/api/auth",
						host: betaHost,
						cookie: cookie(betaLogin),
					}),
				).toEqual({ apiKeys: [], total: 0 });
				expect(
					await runtimeApiKeys(service, {
						prefix: "/api/auth",
						cookie: rootCookie,
					}),
				).toEqual({ apiKeys: [], total: 0 });

				expect(
					(await service.request("/oauth/login", { host: alphaHost })).status,
				).toBe(503);
				expect(
					(await service.request("/oauth/login", { host: betaHost })).status,
				).toBe(400);
				const directKeys = await issueFixtureTokens(service, {
					prefix: alphaPath,
					issuer: directIssuer,
					cookie: legacyCookie,
				});
				const signupEmail = "new-registered@runtime.fixture.example";
				const registration = await service.request("/api/auth/sign-up/email", {
					host: alphaHost,
					body: {
						email: signupEmail,
						name: "Runtime Registration",
						password: credentials.updated,
						callbackURL: `https://${alphaHost}/console`,
					},
				});
				expect(
					registration.status,
					registration.ok ? undefined : await registration.clone().text(),
				).toBe(200);
				const verificationURL = await fixtureVerificationMail(
					service,
					signupEmail,
				);
				expect(verificationURL.origin).toBe(`https://${alphaHost}`);
				const verified = await service.request(
					verificationURL.pathname + verificationURL.search,
					{ host: alphaHost },
				);
				expect(verified.status).toBe(302);
				expect(verified.headers.get("location")).toBe(
					`https://${alphaHost}/console`,
				);
				const verifiedCookie = cookie(verified);
				expect(verifiedCookie).toContain("session_token=");
				const hostedKeys = await issueFixtureTokens(service, {
					prefix: "/api/auth",
					issuer: hostedIssuer,
					host: alphaHost,
					cookie: verifiedCookie,
				});
				expect(hostedKeys).toEqual(directKeys);
				expect(
					(
						await service.request("/api/auth/sign-out", {
							host: alphaHost,
							cookie: verifiedCookie,
							body: {},
						})
					).status,
				).toBe(200);
				const hostedLogout = await vi.waitFor(() => {
					expect(service!.logout).toHaveLength(1);
					return service!.logout[0]!;
				});
				await jwtVerify(hostedLogout, createLocalJWKSet(hostedKeys), {
					issuer: hostedIssuer,
					audience: oauthClientId,
				});
				const oauthEmail = "verified-oauth@runtime.fixture.example";
				const oauthRegistration = await service.request(
					"/api/auth/sign-up/email",
					{
						host: alphaHost,
						body: {
							email: oauthEmail,
							name: "OAuth Registration",
							password: credentials.updated,
							callbackURL: oauthCallback.href,
						},
					},
				);
				expect(
					oauthRegistration.status,
					oauthRegistration.ok
						? undefined
						: await oauthRegistration.clone().text(),
				).toBe(200);
				const oauthMail = await fixtureVerificationMail(service, oauthEmail);
				const forged = new URL(oauthCallback);
				forged.searchParams.set("state", "changed-by-caller");
				const tamperedMail = new URL(oauthMail);
				tamperedMail.searchParams.set("callbackURL", forged.href);
				expect(
					(
						await service.request(tamperedMail.pathname + tamperedMail.search, {
							host: alphaHost,
						})
					).status,
				).toBe(403);
				const verifiedOAuth = await service.request(
					oauthMail.pathname + oauthMail.search,
					{ host: alphaHost },
				);
				expect(verifiedOAuth.status).toBe(302);
				expect(verifiedOAuth.headers.get("location")).toBe(oauthCallback.href);
				const continuation = await fixtureRedirect(
					await service.request("/api/auth/oauth2/continue", {
						host: alphaHost,
						cookie: cookie(verifiedOAuth),
						body: {
							selected: true,
							oauth_query: oauthCallback.searchParams.toString(),
						},
					}),
				);
				expect(continuation.origin + continuation.pathname).toBe(
					oauthRedirectURI,
				);
				expect(continuation.searchParams.get("state")).toBe(
					oauthCallback.searchParams.get("state"),
				);
				expect(continuation.searchParams.has("code")).toBe(true);
				const oldClock = vi
					.spyOn(Date, "now")
					.mockReturnValue(Date.now() - 120_000);
				let expiredOAuth: URLSearchParams;
				try {
					expiredOAuth = signProjectIssuerQuery(
						fixtureAuthorizationQuery(),
						versionedSigningSecret,
					);
				} finally {
					oldClock.mockRestore();
				}
				const expiredMail = new URL(oauthMail);
				expiredMail.searchParams.set(
					"callbackURL",
					`https://${alphaHost}/oauth2/continue?${expiredOAuth}`,
				);
				const invalidToken = new URL(expiredMail);
				invalidToken.searchParams.set("token", "invalid-email-token");
				expect(
					(
						await service.request(invalidToken.pathname + invalidToken.search, {
							host: alphaHost,
						})
					).status,
				).toBe(401);
				const expiredFallback = await service.request(
					expiredMail.pathname + expiredMail.search,
					{ host: alphaHost },
				);
				expect(expiredFallback.status).toBe(302);
				expect(expiredFallback.headers.get("location")).toBe(
					`https://${alphaHost}/account`,
				);
				expect(
					(
						await service.request("/api/auth/oauth2/continue", {
							host: alphaHost,
							cookie: cookie(verifiedOAuth),
							body: { selected: true, oauth_query: expiredOAuth.toString() },
						})
					).status,
				).toBe(400);
				const resetURL = new URL(`https://${alphaHost}/reset-password`);
				resetURL.searchParams.set("returnTo", "/account/security?from=reset");
				const resetRequest = await service.request(
					"/api/auth/request-password-reset",
					{
						host: alphaHost,
						body: { email: oauthEmail, redirectTo: resetURL.href },
					},
				);
				expect(resetRequest.status).toBe(200);
				const resetMail = await vi.waitFor(() => {
					const mail = service!.mail.find(
						({ to, subject }) =>
							to === oauthEmail && subject.startsWith("Reset your"),
					);
					const match = mail?.text.match(
						/https:\/\/[^\s<>\]]+\/reset-password\/[^\s<>\]]+/,
					);
					expect(match?.[0]).toBeTruthy();
					return new URL(match![0]);
				});
				const resetRedirect = await fixtureRedirect(
					await service.request(resetMail.pathname + resetMail.search, {
						host: alphaHost,
					}),
				);
				expect(resetRedirect.pathname).toBe("/reset-password");
				expect(resetRedirect.searchParams.get("returnTo")).toBe(
					"/account/security?from=reset",
				);
				expect(resetRedirect.searchParams.has("token")).toBe(true);
				const rotated = await service.request(`${alphaPath}/change-password`, {
					cookie: legacyCookie,
					body: {
						currentPassword: credentials.password,
						newPassword: credentials.updated,
						revokeOtherSessions: true,
					},
				});
				expect(rotated.status).toBe(200);
				const ownedCookie = cookie(rotated);
				expect(ownedCookie).toContain("session_token=");
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: legacyHostedCookie,
						})
					).json(),
				).toBeNull();
				const ownedHostedLogin = await service.request(
					"/api/auth/sign-in/email",
					{
						host: alphaHost,
						body: { ...login, password: credentials.updated },
					},
				);
				expect(ownedHostedLogin.status).toBe(200);
				const ownedHostedCookie = cookie(ownedHostedLogin);
				await service.stop();
				service = undefined;

				service = await open(restored, false);
				expect((await service.request("/api/health")).status).toBe(200);
				for (const started of ownedSaml)
					await finishRuntimeSaml(service, samlKeys, started);
				const rolledBackWallet = await service.request(
					"/api/auth/siwe/verify",
					{ ...hostedWallet, body: ownedWalletProof },
				);
				expect(
					rolledBackWallet.status,
					rolledBackWallet.ok
						? undefined
						: await rolledBackWallet.clone().text(),
				).toBe(200);
				expect(await rolledBackWallet.json()).toMatchObject({
					success: true,
					user: { id: walletId, walletAddress: wallet.address, chainId: 10 },
				});
				const ownedWalletSession = await service.request(
					"/api/auth/get-session",
					{
						host: alphaHost,
						cookie: cookie(ownedWalletSignup),
					},
				);
				expect(await ownedWalletSession.json()).toMatchObject({
					user: {
						id: ownedWalletId,
						email: `${newWallet.address.toLowerCase()}@siwe.placeholder.invalid`,
						emailVerified: false,
					},
				});
				const restoredGuest = await service.request("/api/auth/get-session", {
					host: alphaHost,
					cookie: cookie(candidateGuest),
				});
				expect(await restoredGuest.json()).toMatchObject({
					user: {
						id: candidateGuestData.user.id,
						isAnonymous: true,
						emailVerified: false,
						role: "guest",
					},
				});
				const restoredDirectory = await service.request(
					`${hostedScim}/${encodeURIComponent(directoryUserId)}`,
					{
						authorization: `Bearer ${ownedDirectoryToken}`,
						host: alphaHost,
					},
				);
				expect(
					restoredDirectory.status,
					restoredDirectory.ok
						? undefined
						: await restoredDirectory.clone().text(),
				).toBe(200);
				expect(await restoredDirectory.json()).toMatchObject({
					id: directoryUserId,
					userName: scimName,
					active: false,
				});
				const restoredSupport = await service.request(
					`${alphaPath}/sdk/support/session`,
					connectedSupport,
				);
				expect(await restoredSupport.json()).toMatchObject({
					session: { id: impersonationId },
					user: { id: supportTarget },
				});
				expect(
					(
						await service.request(`${alphaPath}/sdk/support/stop`, {
							...connectedSupport,
							body: {},
						})
					).status,
				).toBe(200);
				expect(
					await (
						await service.request(
							`${alphaPath}/sdk/support/session`,
							connectedSupport,
						)
					).json(),
				).toBeNull();
				const rolledBackApple = await finishFixtureApple(service, ownedApple);
				expect(rolledBackApple.headers.get("location")).toBe(
					directProvider.destination,
				);
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: cookie(ownedAppleGuest),
						})
					).json(),
				).toBeNull();
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: cookie(rolledBackApple),
						})
					).json(),
				).toMatchObject({
					user: { id: appleBrowserUser.id, email: runtimeFixtureApple.email },
				});
				const rolledBackMicrosoft = await service.request(ownedMicrosoft.path, {
					cookie: ownedMicrosoft.cookie,
				});
				expect(rolledBackMicrosoft.headers.get("location")).toBe(
					directProvider.destination,
				);
				const microsoftSession = await service.request(
					`${alphaPath}/get-session`,
					{ cookie: cookie(rolledBackMicrosoft) },
				);
				expect(await microsoftSession.json()).toMatchObject({
					user: { email: runtimeFixtureMicrosoft.email, emailVerified: false },
				});
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: cookie(switchedGoogle),
						})
					).json(),
				).toMatchObject({ user: { email: runtimeFixtureGoogle.email } });
				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: ownedCookie,
						})
					).json(),
				).toMatchObject({ user: { id: credentials.project.id } });
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: ownedHostedCookie,
						})
					).json(),
				).toMatchObject({
					user: { id: credentials.project.id, image: savedImage },
				});
				const rolledBackDirectKeys = { prefix: alphaPath, cookie: ownedCookie };
				const rolledBackHostedKeys = {
					prefix: "/api/auth",
					host: alphaHost,
					cookie: ownedHostedCookie,
				};
				expect(
					await runtimeGetApiKey(
						service,
						rolledBackDirectKeys,
						ownedDirectKey.id,
					),
				).toEqual(ownedDirectKey);
				expect(
					await runtimeGetApiKey(
						service,
						rolledBackHostedKeys,
						ownedHostedKey.id,
					),
				).toEqual(ownedHostedKey);
				expect(
					await runtimeGetApiKey(
						service,
						rolledBackDirectKeys,
						nativeDirectKey.id,
						404,
					),
				).toMatchObject({ code: "KEY_NOT_FOUND" });
				expect(
					await runtimeGetApiKey(
						service,
						rolledBackHostedKeys,
						nativeHostedKey.id,
						404,
					),
				).toMatchObject({ code: "KEY_NOT_FOUND" });

				expect(
					await (
						await service.request(`${alphaPath}/get-session`, {
							cookie: legacyCookie,
						})
					).json(),
				).toBeNull();
				expect(
					(await service.request(`${alphaPath}/sign-in/email`, { body: login }))
						.status,
				).toBe(401);
				expect(
					(
						await service.request("/api/auth/sign-in/email", {
							host: alphaHost,
							clientIP: "192.0.2.56",
							body: { ...login, password: credentials.updated },
						})
					).status,
				).toBe(200);
				const catalog = await service.request(management(alpha), {
					cookie: rootCookie,
				});
				expect(catalog.status).toBe(200);
				expect(await catalog.json()).toMatchObject({
					organizations: [{ id: directoryOrg }],
				});
				const control = await service.request(management(beta), {
					cookie: rootCookie,
				});
				expect(await control.json()).toMatchObject({
					organizations: [
						expect.objectContaining({ slug: "fixture-organization" }),
					],
				});
				await service.stop();
				service = undefined;
				await expect(open(restored, true, beta.slug)).rejects.toThrow(
					"stored features outside the candidate scope",
				);
				await expect(
					open(restored, true, alpha.slug, beta.slug),
				).rejects.toThrow("stored features outside the candidate scope");
				const changed = new Pool({ connectionString: url(restored), max: 1 });
				try {
					const stored = await changed.query(
						`SELECT "providerId", "accountId" FROM "${alpha.schemaName}"."account" WHERE "providerId" IN ('apple','google','microsoft') ORDER BY "providerId", "accountId"`,
					);
					expect(stored.rows).toEqual([
						{ providerId: "apple", accountId: appleDirectSubject },
						{ providerId: "apple", accountId: runtimeFixtureApple.subject },
						{ providerId: "google", accountId: runtimeFixtureGoogle.subject },
						{
							providerId: "microsoft",
							accountId: runtimeFixtureMicrosoft.subject,
						},
					]);
					expect(
						(
							await changed.query(
								`SELECT 1 FROM "${beta.schemaName}"."account" WHERE "providerId" IN ('apple','google','microsoft')`,
							)
						).rowCount,
					).toBe(0);
					service = await open(restored, true);
					const removedApple = await service.request(
						`${alphaPath}/project-admin/remove-user`,
						{
							cookie: rootCookie,
							body: { userId: appleBrowserUser.id },
						},
					);
					expect(
						removedApple.status,
						removedApple.ok ? undefined : await removedApple.clone().text(),
					).toBe(200);
					expect(await removedApple.json()).toEqual({ success: true });
					expect(
						await (
							await service.request(`${alphaPath}/get-session`, {
								cookie: cookie(rolledBackApple),
							})
						).json(),
					).toBeNull();
					await service.stop();
					service = undefined;
					await changed.query(
						`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"='{}' WHERE "providerId"=$1`,
						[directoryProvider],
					);
					await expect(open(restored, true)).rejects.toThrow(
						"This development project has a configured SAML provider outside the candidate scope.",
					);
					await changed.query(
						`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"=NULL WHERE "providerId"=$1`,
						[directoryProvider],
					);
					const supportedSaml = runtimeSamlConfiguration(samlKeys);
					for (const spMetadata of [
						{ metadata: runtimeSamlSPMetadata(nativeSaml[0].flow.acs) },
						{ isAssertionEncrypted: true },
					]) {
						await changed.query(
							`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"=$1 WHERE "providerId"=$2`,
							[
								JSON.stringify({ ...supportedSaml, spMetadata }),
								runtimeSamlProvider,
							],
						);
						await expect(open(restored, true)).rejects.toThrow(
							"This development project has a configured SAML provider outside the candidate scope.",
						);
					}
					await changed.query(
						`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"=$1 WHERE "providerId"=$2`,
						[JSON.stringify(supportedSaml), runtimeSamlProvider],
					);
					await changed.query(
						`UPDATE "${alpha.schemaName}"."apikey" SET "rateLimitMax"=101 WHERE id=$1`,
						[ownedDirectKey.id],
					);
					await expect(open(restored, true)).rejects.toThrow(
						"stored features outside the candidate scope",
					);
					await changed.query(
						`UPDATE "${alpha.schemaName}"."apikey" SET "rateLimitMax"=100 WHERE id=$1`,
						[ownedDirectKey.id],
					);

					await changed.query(
						`UPDATE "${alpha.schemaName}"."oauthClient" SET "grantTypes" = '["client_credentials"]' WHERE "clientId" = $1`,
						[oauthClientId],
					);
				} finally {
					await changed.end();
				}
				await expect(open(restored, true)).rejects.toThrow(
					"stored features outside the candidate scope",
				);
			} finally {
				try {
					try {
						await service?.stop();
					} finally {
						for (const name of created.reverse())
							await dropClosedFixtureDatabase(admin, name);
					}
				} finally {
					await admin.end();
				}
			}
		}, 90_000);
	},
);
