import { execFile, fork, spawn } from "node:child_process";
import {
	createHash,
	createHmac,
	createPrivateKey,
	randomBytes,
	randomUUID,
} from "node:crypto";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { symmetricEncrypt } from "better-auth/crypto";
import type { JSONWebKeySet } from "jose";
import {
	createLocalJWKSet,
	exportJWK,
	exportPKCS8,
	generateKeyPair,
	jwtVerify,
	SignJWT,
} from "jose";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { describe, expect, it, vi } from "vitest";
import {
	agentReplayApprovalSetting,
	agentReplayBridgeIdSetting,
	issueAgentReplayDrainEvidence,
	productionAgentReplayApprovalsSetting,
	productionAgentReplayBridgeIdsSetting,
	verifyAgentReplayDrainEvidence,
} from "../../scripts/project-agent-replay-evidence.mjs";
import { productionProjectEngineRevisionsSetting } from "../../scripts/project-engine-rollout-selection.mjs";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { lockProjectSettings } from "../auth-policy/serialization";
import { authPolicyRepository } from "../auth-policy/storage";
import { clerkCompatiblePasswords } from "../clerk-password";
import { defaultSecurityPolicy } from "../control/security-policy";
import type { SecurityRule } from "../control/security-management";
import type { ControlPrincipal } from "../control/types";
import {
	newWebhookSigningSecret,
	webhookSignature,
} from "../control/webhook-contract";
import { deliverPendingWebhooks } from "../control/webhooks";
import { signEdgeRequest } from "../domains/edge";
import { googleProviderRepository } from "../project-providers/repository";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { platformWorkspaceId } from "../workspaces/types";
import { openLegacyMfaRecord } from "./legacy-mfa-record";
import { readLegacyProjectKeyring } from "./legacy-project-keyring";
import { signProjectIssuerQuery } from "./owned-project-issuer-authorization-query";
import { projectOpenApiPath } from "./owned-project-openapi";
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
	renewRuntimeSamlCertificate,
	runtimeSamlAuthnRequest,
	runtimeSamlConfiguration,
	runtimeSamlEntity,
	runtimeSamlIssuer,
	runtimeSamlOrigin,
	runtimeSamlProvider,
	runtimeSamlResponse,
	runtimeSamlSPMetadata,
	runtimeSamlSubject,
} from "./owned-project-runtime-saml-fixture";
import { encryptedSamlConfigurationFingerprint } from "./owned-project-sso-saml-approval";
import type { ProjectEncryptedSamlFixtureAdmission } from "./owned-project-sso-saml-fixture-admission";
import { encryptedSamlFixtureConfigurationDigest } from "./owned-project-sso-saml-fixture-admission";
import {
	createProjectEngineWriterLease,
	projectEngineWriterConnectionOptions,
} from "./project-engine-writer-lease";
import { projectProxySecret } from "./proxy";
import type { Project } from "./registry";
import { projectSecret } from "./runtime";

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
const catalogPrivateMetadata = "synthetic-catalog-private-metadata";
const catalogClientSecret = "synthetic-catalog-private-client-secret";
const supportOrigin = "https://support.runtime.fixture.example";
const supportCallback = `${supportOrigin}/api/allauth/support/callback`;
const supportTarget = "fixture-support-target";
const analyticsAccount = {
	id: "fixture-analytics-account",
	email: "analytics@runtime.fixture.example",
};
const analyticsOrganizations = [
	"fixture-analytics-active-organization",
	"fixture-analytics-requested-organization",
] as const;
const rejectedInvitationEmail =
	"reject-console-invitation@runtime.fixture.example";
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
	realmAdmin: {
		id: "fixture-project-administrator",
		email: "project-administrator@runtime.fixture.example",
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
		CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32),
		CLOUDFLARE_SAAS_API_TOKEN: "fixture-only-domain-readiness-token",
		CLOUDFLARE_SAAS_CNAME_TARGET: "domains.allauth.co",
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

function applicationCatalog(project: Project, clientId?: string) {
	const detail = clientId ? `/${encodeURIComponent(clientId)}` : "";
	return `/api/admin/applications${detail}?project=${project.slug}`;
}

async function runtimeApplicationCatalog(
	service: Awaited<ReturnType<typeof openProcess>>,
	project: Project,
	rootCookie: string,
) {
	const response = await service.request(applicationCatalog(project), {
		cookie: rootCookie,
	});
	expect(response.status, await response.clone().text()).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	const body = await response.text();
	expect(body).not.toContain(catalogPrivateMetadata);
	expect(body).not.toContain(catalogClientSecret);
	const { applications } = JSON.parse(body) as {
		applications: { client_id: string }[];
	};
	return applications.sort((first, second) =>
		first.client_id.localeCompare(second.client_id),
	);
}

async function expectProjectApplicationWriteDirections(
	service: Awaited<ReturnType<typeof openProcess>>,
	project: Project,
	rootCookie: string,
) {
	const client = applicationCatalog(project, `${project.slug}+client`);
	const registration = await service.request(applicationCatalog(project), {
		cookie: rootCookie,
		body: {},
	});
	expect(registration.status).toBe(400);
	expect(await registration.json()).toEqual({
		error:
			"Use the project's own verified administrator session to register native OAuth clients. App integration settings are managed in Projects.",
	});
	for (const method of ["PATCH", "DELETE"] as const) {
		const result = await service.request(client, {
			cookie: rootCookie,
			method,
		});
		expect(result.status).toBe(400);
		expect(await result.json()).toEqual({
			error:
				"Use the project's own verified administrator session to manage native OAuth clients.",
		});
	}
}

async function runtimeSecurity(
	service: Awaited<ReturnType<typeof openProcess>>,
	path: string,
	options: Parameters<Awaited<ReturnType<typeof openProcess>>["request"]>[1],
	status = 200,
): Promise<unknown> {
	const response = await service.request(path, options);
	expect(response.status, await response.clone().text()).toBe(status);
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(response.headers.get("pragma")).toBe("no-cache");
	return response.json();
}

async function analyticsResponse(
	service: Awaited<ReturnType<typeof openProcess>>,
	path: string,
	options: Parameters<Awaited<ReturnType<typeof openProcess>>["request"]>[1],
	status = 200,
): Promise<unknown> {
	const response = await service.request(path, options);
	expect(response.status, await response.clone().text()).toBe(status);
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(response.headers.get("pragma")).toBe("no-cache");
	return response.json();
}

async function projectSignInMetadata(
	databaseURL: string,
	project: Project,
	userId: string,
) {
	const database = new Pool({ connectionString: databaseURL, max: 1 });
	try {
		const result = await database.query<{ metadata: Record<string, unknown> }>(
			`SELECT metadata FROM "${project.schemaName}"."allauthEvent"
			 WHERE type='auth.sign-in' AND outcome='success' AND "userId"=$1 ORDER BY "createdAt",id`,
			[userId],
		);
		return result.rows.map(({ metadata }) => metadata);
	} finally {
		await database.end();
	}
}

async function analyticsActivity(database: Pool, project: Project) {
	const result = await database.query(
		`SELECT "entityType","entityId",sources FROM "${project.schemaName}"."allauthAnalyticsActivity"
		 WHERE "entityId"=ANY($1::text[]) ORDER BY "entityType","entityId"`,
		[[analyticsAccount.id, ...analyticsOrganizations]],
	);
	return result.rows;
}

async function openProcess(
	databaseURL: string,
	project: Project,
	owned:
		| boolean
		| { agentReplayApproval?: string; agentBridgeId?: string; legacyAgentBridgeOnly?: boolean },
	microsoftProject = project.slug,
	apple?: AppleFixture,
	encryptedSamlFixture?: ProjectEncryptedSamlFixtureAdmission,
	rolloutEnvironment: Partial<NodeJS.ProcessEnv> = {},
) {
	const internal = typeof owned === "object" ? owned : undefined;
	const child = fork(worker, [], {
		cwd: appRoot,
		env: {
			...childEnvironment(microsoftProject, apple),
			...(internal
				? {
						...(!internal.legacyAgentBridgeOnly ? { ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: project.id } : {}),
						EMAIL_PROVIDER: "cloudflare",
						EMAIL_FROM: "agent-restart@runtime.fixture.example",
						CLOUDFLARE_ACCOUNT_ID: "a".repeat(32),
						CLOUDFLARE_EMAIL_API_TOKEN: "synthetic-agent-restart-mail-token",
						...(internal.agentReplayApproval
							? { [agentReplayApprovalSetting]: internal.agentReplayApproval }
							: {}),
						...(internal.agentBridgeId ? { [agentReplayBridgeIdSetting]: internal.agentBridgeId } : {}),
					}
				: {}),
			...rolloutEnvironment,
		},
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
		owned: owned === true,
		appleIssuerKey: apple?.issuerKey,
		encryptedSamlFixture,
		rejectInvitationMailTo: rejectedInvitationEmail,
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
					method?: "PATCH" | "DELETE";
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
								options.clientIP ?? "",
								createHash("sha256")
									.update(body ?? "")
									.digest("hex"),
							].join("\n"),
						)
						.digest("hex");
					headers.set("allauth-proxy-signature", signature);
					headers.set("allauth-proxy-origin", proxyOrigin);
					headers.set("allauth-proxy-timestamp", timestamp);
					if (options.clientIP)
						headers.set("allauth-proxy-ip", options.clientIP);
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
	clientIP?: string;
	proxy?: Project;
	origin?: string;
};

async function startRuntimeSaml(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: SamlTransport,
	acs = `${transport.baseURL}/sso/saml2/sp/acs/${runtimeSamlProvider}`,
) {
	const started = await service.request(`${transport.prefix}/sign-in/sso`, {
		host: transport.host,
		proxy: transport.proxy,
		origin: transport.origin,
		clientIP: transport.clientIP,
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
	expect(flow.acs).toBe(acs);
	return { transport, flow };
}

async function finishRuntimeSaml(
	service: Awaited<ReturnType<typeof openProcess>>,
	keys: Awaited<ReturnType<typeof createRuntimeSamlKeys>>,
	{ flow, transport }: Awaited<ReturnType<typeof startRuntimeSaml>>,
	encryption?: { certificate: string; dataAlgorithm?: string },
) {
	const acs = new URL(flow.acs);
	const authenticated = await service.request(acs.pathname, {
		host: transport.host,
		origin: runtimeSamlOrigin,
		body: await runtimeSamlResponse(
			keys,
			flow,
			credentials.project.email,
			encryption,
		),
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

async function seedRuntimeMembershipGrant(
	database: Pool,
	schema: string,
	client: string,
	userId: string,
	organizationId: string,
) {
	const id = randomUUID();
	const code = createHash("sha256").update(randomUUID()).digest("base64url");
	const params = [id, client, userId, organizationId];
	await database.query(
		`INSERT INTO "${schema}"."oauthRefreshToken"(id,token,"clientId","userId","referenceId","expiresAt","createdAt",scopes,"rotationReplayResponse","rotationReplayExpiresAt")
		 VALUES ($1,$1,$2,$3,$4,now()+interval '1 hour',now(),'["organization:read"]','synthetic-member-replay',now()+interval '1 minute')`,
		params,
	);
	await database.query(
		`INSERT INTO "${schema}"."oauthAccessToken"(id,token,"clientId","userId","referenceId","refreshId","expiresAt","createdAt",scopes)
		 VALUES ($1,$1,$2,$3,$4,$1,now()+interval '1 hour',now(),'["organization:read"]')`,
		params,
	);
	await database.query(
		`INSERT INTO "${schema}"."oauthConsent"(id,"clientId","userId","referenceId","createdAt","updatedAt",scopes)
		 VALUES ($1,$2,$3,$4,now(),now(),'["organization:read"]')`,
		params,
	);
	await database.query(
		`INSERT INTO "${schema}"."verification"(id,identifier,value,"expiresAt") VALUES ($1,$1,$2,now()+interval '1 hour')`,
		[
			code,
			JSON.stringify({
				type: "authorization_code",
				referenceId: organizationId,
				userId,
			}),
		],
	);
	return { id, code };
}

async function runtimeMembershipGrantState(
	database: Pool,
	schema: string,
	grant: { id: string; code: string },
) {
	const { rows } = await database.query(
		`SELECT EXISTS(SELECT 1 FROM "${schema}"."oauthAccessToken" WHERE id=$1) AS access,
		 EXISTS(SELECT 1 FROM "${schema}"."oauthRefreshToken" WHERE id=$1) AS refresh,
		 EXISTS(SELECT 1 FROM "${schema}"."oauthConsent" WHERE id=$1) AS consent,
		 EXISTS(SELECT 1 FROM "${schema}"."verification" WHERE id=$2) AS code`,
		[grant.id, grant.code],
	);
	return rows[0];
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

async function seed(databaseURL: string, protectedAgentRealm = false) {
	await promisify(execFile)(
		process.execPath,
		["scripts/database.mjs", "migrate"],
		{
			cwd: appRoot,
			env: { ...childEnvironment(), DATABASE_URL: databaseURL },
		},
	);
	const env = { ...childEnvironment(), DATABASE_URL: databaseURL };
	// The production registry owns one pool per process. Each isolated test seeds its own database.
	vi.resetModules();
	const [{ projectRegistryPool, provisionProject }, { createWorkspace }] =
		await Promise.all([
			import("./registry"),
			import("../workspaces/repository"),
		]);
	const database = projectRegistryPool(env);
	const cwd = vi.spyOn(process, "cwd").mockReturnValue(appRoot);
	try {
		const hash = await clerkCompatiblePasswords.hash(credentials.password);
		async function insertAccount(
			schema: string,
			account: { id: string; email: string },
			role = "user",
		) {
			await database.query(
				`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role) VALUES ($1,'Fixture User',$2,true,$3)`,
				[account.id, account.email, role],
			);
			await database.query(
				`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt") VALUES ($1,$1,'credential',$1,$2,now())`,
				[account.id, hash],
			);
			await database.query(
				`INSERT INTO "${schema}"."allauthSecurityPolicy" (id,policy) VALUES ('default',$1::jsonb) ON CONFLICT (id) DO NOTHING`,
				[
					JSON.stringify({
						...defaultSecurityPolicy,
						newDeviceNotifications: false,
					}),
				],
			);
		}
		await insertAccount(
			"public",
			credentials.platform,
			protectedAgentRealm ? "admin" : "user",
		);
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
		async function provision(
			slug: string,
			origins: string[] = [],
			workspaceId = workspace.id,
		) {
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
				{ workspaceId, principal: owner },
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
			await database.query(
				`INSERT INTO "${project.schemaName}"."oauthClient"
				  (id,"clientId",name,"clientSecret","redirectUris","grantTypes",disabled,metadata)
				 VALUES ($1,$1,$2,$3,$4::jsonb,'["authorization_code"]',TRUE,$5::jsonb)`,
				[
					`${project.slug}+client`,
					`${project.name} catalog application`,
					catalogClientSecret,
					JSON.stringify([oauthRedirectURI]),
					JSON.stringify({
						allauthOrganizationIds: ["catalog-fixture-organization", null],
						allauthResourceURI: "https://rp.runtime.fixture.example",
						allauthAllowLocalhost: true,
						internal: catalogPrivateMetadata,
					}),
				],
			);
			return project;
		}
		const alpha = await provision(
			"runtime-owned-fixture",
			[supportOrigin],
			protectedAgentRealm ? platformWorkspaceId : workspace.id,
		);
		const beta = await provision("runtime-control-fixture", [], protectedAgentRealm ? platformWorkspaceId : workspace.id);
		await insertAccount(alpha.schemaName, credentials.realmAdmin, "admin");
		for (const project of [alpha, beta])
			await insertAccount(project.schemaName, analyticsAccount);
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
		it("restarts with approved MFA and API-key webhooks and existing unverified and guest sessions", async () => {
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
					"Project webhook cutover requires the isolated local PostgreSQL fixture.",
				);
			const admin = new Pool({ connectionString: base.href, max: 1 });
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			let created = false;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			let database: Pool | undefined;
			let workerDatabase:
				| Kysely<Record<string, Record<string, unknown>>>
				| undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const { alpha } = await seed(databaseURL);
				const schema = `"${alpha.schemaName}"`;
				const settingsDatabase = new Pool({
					connectionString: databaseURL,
					max: 2,
				});
				database = settingsDatabase;
				workerDatabase = new Kysely({
					dialect: new PostgresDialect({
						pool: new Pool({
							connectionString: databaseURL,
							max: 1,
							options: `-c search_path=${alpha.schemaName}`,
						}),
					}),
				});
				const repository = authPolicyRepository(database);
				const current = await repository.read(alpha.id);
				const eligiblePolicy = {
					...current.policy,
					requireEmailVerification: false,
				};
				await repository.update(
					alpha.id,
					current.version,
					eligiblePolicy,
					credentials.platform.id,
				);
				await database.query(
					`UPDATE ${schema}."user" SET "emailVerified"=FALSE WHERE id=$1`,
					[credentials.project.id],
				);
				const projectKey = projectSecret(childEnvironment(), alpha.id);
				const endpointId = randomUUID();
				const destination = "https://webhook.runtime.fixture.example/mfa";
				const oldSigningKey = newWebhookSigningSecret();
				await database.query(
					`INSERT INTO ${schema}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["mfa.*","api-key.*"]',$3)`,
					[
						endpointId,
						destination,
						await symmetricEncrypt({ key: projectKey, data: oldSigningKey }),
					],
				);
				const direct = `/api/projects/${alpha.slug}/auth`;
				const webhooks = `${direct}/control/webhooks`;
				const host = `${alpha.slug}-accounts.allauth.co`;
				const hosted = "/api/auth";
				service = await openProcess(databaseURL, alpha, false);
				const platformSignIn = await service.request(
					"/api/auth/sign-in/email",
					{
						body: {
							email: credentials.platform.email,
							password: credentials.password,
						},
					},
				);
				expect(platformSignIn.status).toBe(200);
				const adminCookie = cookie(platformSignIn);
				const existing = await service.request(`${hosted}/sign-in/email`, {
					host,
					body: {
						email: credentials.project.email,
						password: credentials.password,
					},
				});
				expect(existing.status).toBe(200);
				expect(await existing.json()).toMatchObject({
					user: { id: credentials.project.id, emailVerified: false },
				});
				const guest = await service.request(`${hosted}/sign-in/anonymous`, {
					host,
					body: {},
				});
				expect(guest.status).toBe(200);
				const { user: guestUser } = (await guest.json()) as {
					user: { id: string };
				};
				const users = [
					{
						id: credentials.project.id,
						cookie: cookie(existing),
						password: credentials.password,
						role: "user",
						ip: "192.0.2.81",
					},
					{
						id: guestUser.id,
						cookie: cookie(guest),
						password: undefined,
						role: "guest",
						ip: "192.0.2.82",
					},
				];
				const accountKey = { prefix: hosted, host, cookie: users[0]!.cookie };
				const nativeKey = await runtimeCreateApiKey(
					service,
					accountKey,
					"Original subscribed key",
				);
				const supportLogin = await service.request(`${hosted}/sign-in/email`, {
					host,
					body: {
						email: credentials.project.email,
						password: credentials.password,
					},
				});
				expect(supportLogin.status).toBe(200);
				const supportCookie = cookie(supportLogin);
				const session = await service.request(`${hosted}/get-session`, {
					host,
					cookie: supportCookie,
				});
				const { session: support } = (await session.json()) as {
					session: { id: string };
				};
				await database.query(
					`UPDATE ${schema}."session" SET "impersonatedBy"=$1 WHERE id=$2`,
					[credentials.platform.id, support.id],
				);
				async function rejectSupportKey(
					writer: Awaited<ReturnType<typeof openProcess>>,
				) {
					const attempt = await writer.request(`${hosted}/api-key/create`, {
						host,
						cookie: supportCookie,
						body: { name: "Support forbidden key" },
					});
					expect(attempt.status, await attempt.clone().text()).toBe(403);
					expect(await attempt.json()).toMatchObject({
						message:
							"Authentication changes and account deletion are unavailable during impersonation.",
					});
				}
				await rejectSupportKey(service);
				for (const user of users) {
					const setup = await service.request(`${hosted}/two-factor/enable`, {
						host,
						clientIP: user.ip,
						cookie: user.cookie,
						body: { password: user.password },
					});
					expect(setup.status, await setup.clone().text()).toBe(200);
				}
				await service.stop();
				service = undefined;

				service = await openProcess(databaseURL, alpha, true);
				const list = await service.request(webhooks, { cookie: adminCookie });
				expect(list.status).toBe(200);
				expect(await list.json()).toMatchObject({
					endpoints: [{ id: endpointId, eventTypes: ["mfa.*", "api-key.*"] }],
					supportedEventTypes: [
						"mfa.*",
						"api-key.*",
						"session.created",
						"passkey.*",
					],
				});
				const hostedManagement = await service.request(
					`${hosted}/control/webhooks`,
					{ host, cookie: adminCookie },
				);
				expect(hostedManagement.status).toBe(403);
				const unproved = await service.request(`${webhooks}/create`, {
					cookie: adminCookie,
					body: { url: destination, eventTypes: ["mfa.*", "session.*"] },
				});
				expect(unproved.status).toBe(400);
				expect(await unproved.json()).toMatchObject({
					message: expect.stringMatching(/subscription|event/i),
				});
				const rotate = await service.request(`${webhooks}/rotate`, {
					cookie: adminCookie,
					body: { id: endpointId },
				});
				expect(rotate.status).toBe(200);
				const { secret: newSigningKey } = (await rotate.json()) as {
					secret: string;
				};
				expect(newSigningKey).not.toBe(oldSigningKey);
				await rejectSupportKey(service);
				const renamed = await service.request(`${hosted}/api-key/update`, {
					...accountKey,
					body: { keyId: nativeKey.id, name: "Owned subscribed key" },
				});
				expect(renamed.status, await renamed.clone().text()).toBe(200);
				expect(await renamed.json()).toMatchObject({
					id: nativeKey.id,
					name: "Owned subscribed key",
				});
				const { encryptionKeys } = readLegacyProjectKeyring(
					projectKey,
					versionedEncryption,
				);
				for (const user of users) {
					const stored = await database.query<{ secret: string }>(
						`SELECT secret FROM ${schema}."twoFactor" WHERE "userId"=$1`,
						[user.id],
					);
					const factor = openLegacyMfaRecord(
						stored.rows[0]!.secret,
						encryptionKeys,
					);
					const counter = new Uint8Array(8);
					new DataView(counter.buffer).setBigUint64(
						0,
						BigInt(Math.floor(Date.now() / 30_000)),
					);
					const digest = createHmac("sha1", factor).update(counter).digest();
					const code = String(
						(digest.readUInt32BE(digest[digest.length - 1]! & 15) &
							0x7fff_ffff) %
							1_000_000,
					).padStart(6, "0");
					const verified = await service.request(
						`${hosted}/two-factor/verify-totp`,
						{ host, clientIP: user.ip, cookie: user.cookie, body: { code } },
					);
					expect(verified.status, await verified.clone().text()).toBe(200);
					user.cookie = cookie(verified);
					expect(user.cookie).toBeTruthy();
				}
				const createInput = {
					cookie: adminCookie,
					body: {
						url: "https://webhook.runtime.fixture.example/new-mfa",
						eventTypes: ["api-key.*", "mfa.*", "session.created", "passkey.*"],
					},
				};
				const settings = await database.connect();
				let settingsCommitted = false;
				try {
					await settings.query("BEGIN");
					await lockProjectSettings(settings, alpha.id);
					const inFlight = service.request(`${webhooks}/create`, createInput);
					await expect
						.poll(
							async () => {
								const { rows } = await settingsDatabase.query<{
									waiting: boolean;
								}>(
									`SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
								AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
								AND objsubid=1 AND objid=(hashtext($1)::bigint & 4294967295)::oid) AS waiting`,
									[`allauth:project-auth-configuration:${alpha.id}`],
								);
								return rows[0]?.waiting;
							},
							{ timeout: 4_000 },
						)
						.toBe(true);
					const lockedPolicy = authPolicyRepository(settings);
					const revision = await lockedPolicy.read(alpha.id);
					const changed = await lockedPolicy.update(
						alpha.id,
						revision.version,
						{ ...eligiblePolicy, requireEmailVerification: true },
						credentials.platform.id,
					);
					await settings.query("COMMIT");
					settingsCommitted = true;
					const refused = await inFlight;
					expect(refused.status).toBe(400);
					expect(await refused.json()).toMatchObject({
						message: expect.stringMatching(/subscription/i),
					});
					await repository.update(
						alpha.id,
						changed.version,
						eligiblePolicy,
						credentials.platform.id,
					);
				} finally {
					if (!settingsCommitted) await settings.query("ROLLBACK");
					settings.release();
				}
				const subscribed = await service.request(
					`${webhooks}/create`,
					createInput,
				);
				expect(subscribed.status, await subscribed.clone().text()).toBe(200);
				const { endpoint: newEndpoint } = (await subscribed.json()) as {
					endpoint: { id: string };
				};
				await service.stop();
				service = undefined;

				await database.query(
					`UPDATE ${schema}."allauthWebhookEndpoint" SET "eventTypes"='["mfa.*","*"]' WHERE id=$1`,
					[endpointId],
				);
				await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
					/webhook/i,
				);
				await database.query(
					`UPDATE ${schema}."allauthWebhookEndpoint" SET "eventTypes"='["mfa.*","api-key.*"]' WHERE id=$1`,
					[endpointId],
				);
				const revision = await repository.read(alpha.id);
				const required = await repository.update(
					alpha.id,
					revision.version,
					{
						...eligiblePolicy,
						mfaMode: "required",
						requireEmailVerification: true,
						signUpEnabled: false,
					},
					credentials.platform.id,
				);
				await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
					/webhook/i,
				);
				await repository.update(
					alpha.id,
					required.version,
					eligiblePolicy,
					credentials.platform.id,
				);
				service = await openProcess(databaseURL, alpha, false);
				const rollbackList = await service.request(webhooks, {
					cookie: adminCookie,
				});
				expect(await rollbackList.json()).toMatchObject({
					endpoints: expect.arrayContaining([
						{
							id: newEndpoint.id,
							eventTypes: [
								"api-key.*",
								"mfa.*",
								"session.created",
								"passkey.*",
							],
							url: "https://webhook.runtime.fixture.example/new-mfa",
							enabled: true,
							description: "",
							createdAt: expect.any(String),
							updatedAt: expect.any(String),
						},
					]),
				});
				expect(
					(
						await service.request(`${webhooks}/delete`, {
							cookie: adminCookie,
							body: { id: newEndpoint.id },
						})
					).status,
				).toBe(200);
				const rollbackKeyTransport = {
					...accountKey,
					cookie: users[0]!.cookie,
				};
				expect(
					await runtimeGetApiKey(service, rollbackKeyTransport, nativeKey.id),
				).toMatchObject({ name: "Owned subscribed key" });
				const removed = await service.request(`${hosted}/api-key/delete`, {
					...rollbackKeyTransport,
					body: { keyId: nativeKey.id },
				});
				expect(removed.status, await removed.clone().text()).toBe(200);
				for (const user of users) {
					const active = await service.request(`${hosted}/get-session`, {
						host,
						clientIP: user.ip,
						cookie: user.cookie,
					});
					expect(await active.json()).toMatchObject({
						user: {
							id: user.id,
							emailVerified: false,
							role: user.role,
							twoFactorEnabled: true,
						},
					});
					const disabled = await service.request(
						`${hosted}/two-factor/disable`,
						{
							host,
							clientIP: user.ip,
							cookie: user.cookie,
							body: { password: user.password },
						},
					);
					expect(disabled.status, await disabled.clone().text()).toBe(200);
				}
				const deliveries: Array<{
					body: string;
					headers: Record<string, string>;
				}> = [];
				expect(
					await deliverPendingWebhooks({
						database: workerDatabase,
						secret: projectKey,
						resolver: async () => [{ address: "93.184.216.34", family: 4 }],
						now: () => new Date(Date.now() + 1_000),
						maxDeliveries: 20,
						transport: async ({ destination: target, body, headers }) => {
							if (target.url.href === destination)
								deliveries.push({ body, headers });
							return 204;
						},
					}),
				).toEqual({ claimed: 9, delivered: 9, failed: 0, retried: 0 });
				const subjects = new Set(users.map((user) => user.id));
				const types = [];
				for (const { body, headers } of deliveries) {
					expect(headers["webhook-signature"]).toBe(
						await webhookSignature(
							newSigningKey,
							headers["webhook-id"],
							headers["webhook-timestamp"],
							body,
						),
					);
					const event = JSON.parse(body).data.event as {
						type: string;
						actorId: string;
						userId: string;
						outcome: string;
					};
					expect(subjects.has(event.userId)).toBe(true);
					expect(event).toMatchObject({
						actorId: event.userId,
						outcome: "success",
					});
					expect(body).not.toContain(credentials.password);
					expect(body).not.toContain(nativeKey.key!);
					types.push(event.type);
				}
				expect(types.sort()).toEqual([
					"api-key.create",
					"api-key.delete",
					"api-key.update",
					"mfa.disabled",
					"mfa.disabled",
					"mfa.enrollment-started",
					"mfa.enrollment-started",
					"mfa.verified",
					"mfa.verified",
				]);

				const keyEndpoint = randomUUID();
				await database.query(
					`INSERT INTO ${schema}."allauthWebhookEndpoint" (id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["api-key.*"]',$3)`,
					[
						keyEndpoint,
						"https://webhook.runtime.fixture.example/keys-only",
						await symmetricEncrypt({ key: projectKey, data: newSigningKey }),
					],
				);
				expect(
					(
						await service.request(`${webhooks}/delete`, {
							cookie: adminCookie,
							body: { id: endpointId },
						})
					).status,
				).toBe(200);
				const liveBeforePolicy = await service.request(
					`${hosted}/sign-in/email`,
					{
						host,
						clientIP: "192.0.2.89",
						body: {
							email: credentials.project.email,
							password: credentials.password,
						},
					},
				);
				expect(
					liveBeforePolicy.status,
					await liveBeforePolicy.clone().text(),
				).toBe(200);
				const priorCookie = cookie(liveBeforePolicy);
				expect(priorCookie).toBeTruthy();
				await service.stop();
				service = undefined;
				const optional = await repository.read(alpha.id);
				await repository.update(
					alpha.id,
					optional.version,
					{
						...eligiblePolicy,
						mfaMode: "required",
						requireEmailVerification: true,
						signUpEnabled: false,
					},
					credentials.platform.id,
				);
				service = await openProcess(databaseURL, alpha, true);
				const restricted = await service.request(webhooks, {
					cookie: adminCookie,
				});
				expect(restricted.status).toBe(200);
				expect(await restricted.json()).toMatchObject({
					endpoints: [{ id: keyEndpoint, eventTypes: ["api-key.*"] }],
					supportedEventTypes: ["api-key.*", "session.created"],
				});
				const staleKey = await service.request(`${hosted}/api-key/create`, {
					host,
					cookie: priorCookie,
					body: { name: "Blocked by new MFA policy" },
				});
				expect(staleKey.status, await staleKey.clone().text()).toBe(403);
				expect(await staleKey.json()).toMatchObject({
					message:
						"This application requires an already verified account enrolled in MFA.",
				});
			} finally {
				try {
					await service?.stop();
				} finally {
					await Promise.all([database?.end(), workerDatabase?.destroy()]);
					try {
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 60_000);

		it("preserves the signed SDK browser-session list across project writers", async () => {
			const local: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixture, "utf8"),
			);
			const base = new URL(local.DATABASE_URL);
			if (
				local.container !== "allauth-production-test-20261007" ||
				base.hostname !== "127.0.0.1" ||
				base.port !== "55445"
			)
				throw new Error("SDK session parity requires the isolated PostgreSQL fixture.");
			const admin = new Pool({ connectionString: base.href, max: 1 });
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			let created = false;
			let database: Pool | undefined;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const { alpha, beta } = await seed(databaseURL);
				database = new Pool({ connectionString: databaseURL, max: 1 });
				const basePath = `/api/projects/${alpha.slug}/auth`;
				const listPath = `${basePath}/sdk/sessions`;
				const proxy = { proxy: alpha, origin: alpha.primaryOrigin };
				service = await openProcess(databaseURL, alpha, false);
				const login = await service.request(`${basePath}/sign-in/email`, {
					...proxy,
					body: { email: credentials.project.email, password: credentials.password },
				});
				expect(login.status).toBe(200);
				const browser = { ...proxy, cookie: cookie(login) };
				const userId = credentials.project.id;
				const { rows: [current] } = await database.query<{ id: string }>(
					`UPDATE "${alpha.schemaName}"."session" SET "ipAddress"='', "userAgent"=NULL
					 WHERE "userId"=$1 RETURNING id`,
					[userId],
				);
				expect(current?.id).toBeTruthy();
				await database.query(
					`WITH generated AS (INSERT INTO "${alpha.schemaName}"."session"
					 (id,token,"userId","createdAt","updatedAt","expiresAt","ipAddress","userAgent")
					 SELECT 'sdk-list-' || i, 'fixture-hidden-token-' || i, $1,
					  now()-i*interval '1 minute',now(),now()+interval '1 hour','192.0.2.40','Fixture browser'
					 FROM generate_series(1,100) AS i)
					 INSERT INTO "${alpha.schemaName}"."session" (id,token,"userId","createdAt","updatedAt","expiresAt")
					 VALUES ('sdk-expired','fixture-expired-token',$1,now(),now(),now()-interval '1 minute'),
					        ('sdk-foreign-user','fixture-foreign-token',$2,now(),now(),now()+interval '1 hour')`,
					[userId, credentials.realmAdmin.id],
				);
				await database.query(
					`INSERT INTO "${beta.schemaName}"."session" (id,token,"userId","updatedAt","expiresAt")
					 VALUES ('sdk-other-realm','fixture-other-realm-token',$1,now(),now()+interval '1 hour')`,
					[userId],
				);
				async function expectList(writer: NonNullable<typeof service>) {
					const unauthorized = await writer.request(listPath, proxy);
					expect(unauthorized.status).toBe(401);
					expect(unauthorized.headers.get("cache-control")).toBe("no-store");
					expect(unauthorized.headers.get("pragma")).toBe("no-cache");
					expect(await unauthorized.text()).toBe("");
					const response = await writer.request(listPath, browser);
					expect(response.status).toBe(200);
					expect(response.headers.get("cache-control")).toBe("no-store");
					expect(response.headers.get("pragma")).toBe("no-cache");
					expect(response.headers.get("set-auth-token")).toBeNull();
					const data = (await response.json()) as {
						currentSessionId: string;
						sessions: { id: string; createdAt: string; expiresAt: string }[];
					};
					expect(data.currentSessionId).toBe(current!.id);
					expect(data.sessions.map(({ id }) => id)).toEqual([
						current!.id,
						...Array.from({ length: 99 }, (_, index) => `sdk-list-${index + 1}`),
					]);
					expect(data.sessions[0]).toEqual({
						id: current!.id,
						createdAt: expect.any(String),
						expiresAt: expect.any(String),
					});
					expect(data.sessions[1]).toEqual({
						id: "sdk-list-1",
						createdAt: expect.any(String),
						expiresAt: expect.any(String),
						ipAddress: "192.0.2.40",
						userAgent: "Fixture browser",
					});
					const bearer = await writer.request(listPath, {
						...browser,
						authorization: "Bearer fixture-not-a-browser-session",
					});
					expect(bearer.status).toBe(403);
					expect(await bearer.json()).toEqual({
						message: "Use your signed-in browser session for this action.",
					});
					for (const [emailVerified, banned] of [[false, false], [true, true]]) {
						await database!.query(
							`UPDATE "${alpha.schemaName}"."user" SET "emailVerified"=$2,banned=$3 WHERE id=$1`,
							[userId, emailVerified, banned],
						);
						const ineligible = await writer.request(listPath, browser);
						expect(ineligible.status).toBe(403);
						expect(await ineligible.json()).toEqual({
							message: "A verified, active project account is required.",
						});
					}
					await database!.query(
						`UPDATE "${alpha.schemaName}"."user" SET "emailVerified"=true,banned=false WHERE id=$1`,
						[userId],
					);
					await database!.query(
						`UPDATE "${alpha.schemaName}"."session" SET "expiresAt"=now()+interval '1 minute' WHERE id=$1`,
						[current!.id],
					);
					const renewed = await writer.request(listPath, browser);
					expect(renewed.status).toBe(200);
					expect(renewed.headers.get("set-auth-token")).toBeNull();
					expect(renewed.headers.getSetCookie().some((value) => value.includes(".session_token="))).toBe(true);
					const renewedList = await renewed.json() as typeof data;
					expect(renewedList.currentSessionId).toBe(data.currentSessionId);
					expect(Date.parse(renewedList.sessions[0]!.expiresAt)).toBeGreaterThan(Date.now() + 60_000);
					await database!.query(
						`UPDATE "${alpha.schemaName}"."session" SET "expiresAt"=$2 WHERE id=$1`,
						[current!.id, data.sessions[0]!.expiresAt],
					);
					return data;
				}
				const native = await expectList(service);
				await service.stop();
				service = undefined;
				service = await openProcess(databaseURL, alpha, true);
				expect(await expectList(service)).toEqual(native);
			} finally {
				try {
					await service?.stop();
				} finally {
					try {
						await database?.end();
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 60_000);

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
				const organizationDetail = (project: Project, id: string) =>
					`/api/admin/organizations/${encodeURIComponent(id)}?project=${project.slug}`;
				const organizationMembers = (project: Project, id: string) =>
					`/api/admin/organizations/${encodeURIComponent(id)}/members?project=${project.slug}`;
				const organizationTeams = (project: Project, id: string) =>
					`/api/admin/organizations/${encodeURIComponent(id)}/teams?project=${project.slug}`;
				const organizationRoles = (project: Project, id: string) =>
					`/api/admin/organizations/${encodeURIComponent(id)}/roles?project=${project.slug}`;
				const organizationInvitations = (project: Project, id: string) =>
					`/api/admin/organizations/${encodeURIComponent(id)}/invitations?project=${project.slug}`;
				const usersPath = (project: Project) =>
					`/api/admin/users?project=${project.slug}&search=${credentials.project.id}&limit=1`;
				const userPath = (project: Project, metadata = false) =>
					`/api/admin/users/${credentials.project.id}${metadata ? "/metadata" : ""}?project=${project.slug}`;
				const nativePublicMetadata = { consoleLabel: "legacy writer" };
				const ownedPublicMetadata = { consoleLabel: "AllAuth writer" };
				const ownedPrivateMetadata = {
					fixtureInternal: "visible only to the database",
				};
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
				const analyticsPath = `${alphaPath}/control/analytics`;
				const analyticsSummaryPath = `${analyticsPath}?range=7d`;
				const analyticsEntitiesPath = `${analyticsPath}/entities?cohort=active&q=${analyticsAccount.id}`;
				const analyticsOrganizationPath = `${analyticsPath}/entities?entity=organizations&cohort=active&q=fixture-analytics-`;
				const analyticsLogin = await service.request(
					"/api/auth/sign-in/email",
					{
						host: alphaHost,
						clientIP: "192.0.2.121",
						body: {
							email: analyticsAccount.email,
							password: credentials.password,
						},
					},
				);
				expect(analyticsLogin.status).toBe(200);
				const analyticsCookie = cookie(analyticsLogin);
				const analyticsSession = {
					cookie: analyticsCookie,
					host: alphaHost,
					clientIP: "192.0.2.121",
				};
				const securityPath = `${alphaPath}/control/security`;
				const workspaceSession = { cookie: rootCookie };
				const nativePolicy = {
					...defaultSecurityPolicy,
					maxFailuresPerIp: 25,
					newDeviceNotifications: false,
				};
				expect(
					await runtimeSecurity(service, `${securityPath}/update`, {
						...workspaceSession,
						body: { policy: nativePolicy },
					}),
				).toEqual({ policy: nativePolicy });
				const { rule: nativeRule } = (await runtimeSecurity(
					service,
					`${securityPath}/rules/add`,
					{
						...workspaceSession,
						body: {
							type: "email-domain",
							value: "Fixture-Restricted.Example",
							reason: "Temporary fixture rule",
						},
					},
				)) as { rule: SecurityRule };
				expect(nativeRule).toMatchObject({
					id: expect.any(String),
					value: "fixture-restricted.example",
					type: "email-domain",
				});
				const nativeSecurityDenied = await runtimeSecurity(
					service,
					securityPath,
					{},
					403,
				);
				const nativeSecurityValidation = await runtimeSecurity(
					service,
					`${securityPath}/update`,
					{ ...workspaceSession, body: {} },
					400,
				);
				const invalidRule = {
					type: "ip",
					value: "invalid-ip",
					reason: "Invalid fixture input",
				};
				const nativeRuleValidation = await runtimeSecurity(
					service,
					`${securityPath}/rules/add`,
					{ ...workspaceSession, body: invalidRule },
					400,
				);
				const nativeSecurityOrigin = await runtimeSecurity(
					service,
					`${securityPath}/rules/add`,
					{
						...workspaceSession,
						origin: alpha.primaryOrigin,
						body: invalidRule,
					},
					403,
				);
				const nativeApplications = await runtimeApplicationCatalog(
					service,
					alpha,
					rootCookie,
				);
				expect(nativeApplications).toEqual(
					expect.arrayContaining([
						expect.objectContaining({
							client_id: `${alpha.slug}+client`,
							client_name: `${alpha.name} catalog application`,
							grant_types: ["authorization_code"],
							redirect_uris: [oauthRedirectURI],
							organizationIds: ["catalog-fixture-organization"],
							resourceURI: "https://rp.runtime.fixture.example",
							allowLocalhost: true,
							disabled: true,
						}),
					]),
				);
				await expectProjectApplicationWriteDirections(
					service,
					alpha,
					rootCookie,
				);
				const realmAdminLogin = await service.request(
					"/api/auth/sign-in/email",
					{
						host: alphaHost,
						clientIP: "192.0.2.78",
						body: {
							email: credentials.realmAdmin.email,
							password: credentials.password,
						},
					},
				);
				expect(realmAdminLogin.status).toBe(200);
				const realmAdminCookie = cookie(realmAdminLogin);
				const hostedSchemaPath = `/api/auth${projectOpenApiPath}`;
				const directSchemaPath = `${alphaPath}${projectOpenApiPath}`;
				const nativeSchema = await service.request(hostedSchemaPath, {
					host: alphaHost,
					cookie: realmAdminCookie,
				});
				expect(nativeSchema.status).toBe(200);
				expect(nativeSchema.headers.get("cache-control")).toBe("no-store");
				expect(await nativeSchema.json()).toMatchObject({
					openapi: "3.1.1",
					servers: [{ url: hostedIssuer }],
					paths: { "/get-session": expect.any(Object) },
				});
				const mixedSchemaCredentials = {
					host: alphaHost,
					cookie: realmAdminCookie,
					authorization: "Bearer fixture-other-credential",
				};
				expect(
					(await service.request(hostedSchemaPath, mixedSchemaCredentials))
						.status,
				).toBe(403);
				expect(
					(await service.request("/api/auth/reference", { host: alphaHost }))
						.status,
				).toBe(404);
				const nativeRealmSupport = await service.request(
					"/api/auth/admin/impersonate-user",
					{
						host: alphaHost,
						cookie: cookie(realmAdminLogin),
						body: { userId: supportTarget },
					},
				);
				expect(
					nativeRealmSupport.status,
					nativeRealmSupport.ok
						? undefined
						: await nativeRealmSupport.clone().text(),
				).toBe(200);
				const realmSupportCookie = cookie(nativeRealmSupport);
				expect(realmSupportCookie).toContain(".admin_session=");
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
				const legacySupportList = await service.request(`${alphaPath}/sdk/sessions`, {
					cookie: supportCookies,
				});
				expect(legacySupportList.status).toBe(200);
				const legacySupportSessions = (await legacySupportList.json()) as {
					currentSessionId: string;
					sessions: { id: string }[];
				};
				expect(legacySupportSessions.currentSessionId).toBe(impersonationId);
				const legacySupportSession = legacySupportSessions.sessions.find(({ id }) => id === impersonationId);
				expect(legacySupportSession).toBeDefined();
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
				expect(
					(
						await service.request(userPath(alpha, true), {
							cookie: rootCookie,
							method: "PATCH",
							body: { publicMetadata: nativePublicMetadata },
						})
					).status,
				).toBe(200);
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
				const nativeAnalytics = await analyticsResponse(
					service,
					analyticsSummaryPath,
					workspaceSession,
				);
				const nativeAnalyticsEntity = await analyticsResponse(
					service,
					analyticsEntitiesPath,
					workspaceSession,
				);
				const nativeAnalyticsInvalid = await analyticsResponse(
					service,
					`${analyticsPath}?from=2026-01-01`,
					workspaceSession,
					400,
				);
				const nativeAnalyticsInvalidSpan = await analyticsResponse(
					service,
					`${analyticsPath}?from=2026-01-02&to=2026-01-01`,
					workspaceSession,
					400,
				);
				const nativeAnalyticsDenied = await analyticsResponse(
					service,
					analyticsSummaryPath,
					{},
					403,
				);
				await service.stop();
				service = undefined;
				await admin.query(`CREATE DATABASE "${restored}" TEMPLATE "${source}"`);
				created.push(restored);

				service = await open(restored, true);
				expect(
					await analyticsResponse(
						service,
						analyticsSummaryPath,
						workspaceSession,
					),
				).toEqual(nativeAnalytics);
				expect(
					await analyticsResponse(
						service,
						analyticsEntitiesPath,
						workspaceSession,
					),
				).toEqual(nativeAnalyticsEntity);
				expect(
					await analyticsResponse(
						service,
						`${analyticsPath}?from=2026-01-01`,
						workspaceSession,
						400,
					),
				).toEqual(nativeAnalyticsInvalid);
				expect(
					await analyticsResponse(
						service,
						`${analyticsPath}?from=2026-01-02&to=2026-01-01`,
						workspaceSession,
						400,
					),
				).toEqual(nativeAnalyticsInvalidSpan);
				for (const path of [analyticsSummaryPath, analyticsEntitiesPath])
					expect(
						await analyticsResponse(
							service,
							path,
							{ cookie: realmAdminCookie },
							403,
						),
					).toEqual(nativeAnalyticsDenied);
				expect(
					await analyticsResponse(
						service,
						"/api/auth/control/analytics",
						{ ...workspaceSession, host: alphaHost },
						403,
					),
				).toEqual(nativeAnalyticsDenied);
				const activityDB = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				try {
					const schema = `"${alpha.schemaName}"`;
					const activity = (sources: number) => ({
						entityType: "users",
						entityId: analyticsAccount.id,
						sources,
					});
					expect(await analyticsActivity(activityDB, alpha)).toEqual([
						activity(1),
					]);
					for (let read = 0; read < 2; read++) {
						const session = await service.request(
							"/api/auth/get-session",
							analyticsSession,
						);
						expect(session.status).toBe(200);
						expect(await session.json()).toMatchObject({
							user: analyticsAccount,
						});
					}
					expect(await analyticsActivity(activityDB, alpha)).toEqual([
						activity(3),
					]);
					const reset = await service.request(
						"/api/auth/request-password-reset",
						{
							...analyticsSession,
							body: {
								email: "missing-analytics-account@runtime.fixture.example",
								redirectTo: `https://${alphaHost}/reset-password`,
							},
						},
					);
					expect(reset.status).toBe(200);
					expect(await analyticsActivity(activityDB, alpha)).toEqual([
						activity(3),
					]);
					const profile = await service.request("/api/auth/update-user", {
						...analyticsSession,
						body: { name: "Runtime Analytics Account" },
					});
					expect(profile.status, await profile.clone().text()).toBe(200);
					expect(await analyticsActivity(activityDB, alpha)).toEqual([
						activity(7),
					]);
					for (const id of analyticsOrganizations) {
						await activityDB.query(
							`INSERT INTO ${schema}.organization (id,name,slug,"createdAt") VALUES ($1,$1,$1,now())`,
							[id],
						);
						await activityDB.query(
							`INSERT INTO ${schema}.member (id,"organizationId","userId",role,"createdAt") VALUES ($1,$2,$3,'owner',now())`,
							[randomUUID(), id, analyticsAccount.id],
						);
					}
					const [active, requested] = analyticsOrganizations;
					const selection = await service.request(
						"/api/auth/organization/set-active",
						{
							...analyticsSession,
							body: { organizationId: active },
						},
					);
					expect(selection.status, await selection.clone().text()).toBe(200);
					const session = await service.request(
						"/api/auth/get-session",
						analyticsSession,
					);
					expect(await session.json()).toMatchObject({
						session: { activeOrganizationId: active },
					});
					const update = await service.request(
						"/api/auth/organization/update",
						{
							...analyticsSession,
							body: {
								organizationId: requested,
								data: { name: "Explicitly requested analytics organization" },
							},
						},
					);
					expect(update.status, await update.clone().text()).toBe(200);
					expect(await analyticsActivity(activityDB, alpha)).toEqual([
						{ entityType: "organizations", entityId: active, sources: 6 },
						{ entityType: "organizations", entityId: requested, sources: 4 },
						activity(7),
					]);
					const wrongRealm = await service.request("/api/auth/get-session", {
						...analyticsSession,
						host: betaHost,
					});
					expect(await wrongRealm.json()).toBeNull();
					expect(await analyticsActivity(activityDB, beta)).toEqual([]);
				} finally {
					await activityDB
						.query(
							`DELETE FROM "${alpha.schemaName}".organization WHERE id=ANY($1::text[])`,
							[analyticsOrganizations],
						)
						.finally(() => activityDB.end());
				}
				const ownedAnalyticsEntity = await analyticsResponse(
					service,
					analyticsEntitiesPath,
					workspaceSession,
				);
				expect(ownedAnalyticsEntity).toMatchObject({
					total: 1,
					entities: [
						{
							id: analyticsAccount.id,
							name: "Runtime Analytics Account",
							activeDays: 1,
						},
					],
				});
				const ownedAnalyticsOrganizations = await analyticsResponse(
					service,
					analyticsOrganizationPath,
					workspaceSession,
				);
				expect(ownedAnalyticsOrganizations).toMatchObject({
					total: 2,
					entities: expect.arrayContaining(
						analyticsOrganizations.map((id) =>
							expect.objectContaining({
								id,
								deleted: true,
								name: null,
								activeDays: 1,
							}),
						),
					),
				});
				expect(
					await runtimeSecurity(service, securityPath, workspaceSession),
				).toMatchObject({
					policy: nativePolicy,
					rules: [nativeRule],
					stats: { activeRules: 1 },
					capabilities: {
						credentialStuffing: true,
						velocity: true,
						blockRules: true,
						botChallenge: false,
						impossibleTravel: false,
						breachedPasswords: false,
					},
				});
				expect(await runtimeSecurity(service, securityPath, {}, 403)).toEqual(
					nativeSecurityDenied,
				);
				expect(
					await runtimeSecurity(
						service,
						securityPath,
						{ cookie: realmAdminCookie },
						403,
					),
				).toEqual(nativeSecurityDenied);
				expect(
					await runtimeSecurity(
						service,
						`${securityPath}/update`,
						{
							cookie: realmAdminCookie,
							body: { policy: { ...nativePolicy, maxFailuresPerIp: 12 } },
						},
						403,
					),
				).toEqual(nativeSecurityDenied);
				expect(
					await runtimeSecurity(
						service,
						securityPath,
						{ ...workspaceSession, authorization: "Bearer fixture" },
						403,
					),
				).toEqual(nativeSecurityDenied);
				expect(
					await runtimeSecurity(
						service,
						"/api/auth/control/security",
						{ ...workspaceSession, host: alphaHost },
						403,
					),
				).toEqual(nativeSecurityDenied);
				expect(
					await runtimeSecurity(
						service,
						`${securityPath}/update`,
						{ ...workspaceSession, body: {} },
						400,
					),
				).toEqual(nativeSecurityValidation);
				expect(
					await runtimeSecurity(
						service,
						`${securityPath}/rules/add`,
						{ ...workspaceSession, body: invalidRule },
						400,
					),
				).toEqual(nativeRuleValidation);
				expect(
					await runtimeSecurity(
						service,
						`${securityPath}/rules/add`,
						{
							...workspaceSession,
							origin: alpha.primaryOrigin,
							body: invalidRule,
						},
						403,
					),
				).toEqual(nativeSecurityOrigin);
				const securityDB = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				const securityHook = randomUUID();
				const retainedSecurityPolicy = {
					...nativePolicy,
					maxFailuresPerIp: 33,
					blockedEmailDomains: ["fixture-denied.example"],
				};
				let retainedSecurityRule: SecurityRule | undefined;
				try {
					const schema = `"${alpha.schemaName}"`;
					await securityDB.query(
						`INSERT INTO ${schema}."allauthWebhookEndpoint"
						 (id,url,"eventTypes","encryptedSecret") VALUES ($1,'https://delivery.invalid','["security.*"]','synthetic-fixture-secret')`,
						[securityHook],
					);
					expect(
						await runtimeSecurity(service, `${securityPath}/update`, {
							...workspaceSession,
							body: {
								policy: {
									...retainedSecurityPolicy,
									blockedEmailDomains: [
										"Fixture-Denied.Example",
										"fixture-denied.example",
									],
								},
							},
						}),
					).toEqual({ policy: retainedSecurityPolicy });
					const ownedRuleInput = {
						type: "ip",
						value: "2001:0DB8::0040",
						reason: "  Fixture IPv6 rule  ",
					};
					const { rule } = (await runtimeSecurity(
						service,
						`${securityPath}/rules/add`,
						{
							...workspaceSession,
							body: ownedRuleInput,
						},
					)) as { rule: SecurityRule };
					expect(rule).toMatchObject({
						id: expect.any(String),
						value: "2001:db8::40",
						reason: "Fixture IPv6 rule",
						type: "ip",
					});
					const { rule: updatedRule } = (await runtimeSecurity(
						service,
						`${securityPath}/rules/add`,
						{
							...workspaceSession,
							body: {
								...ownedRuleInput,
								value: "2001:db8::40",
								reason: "Updated fixture IPv6 rule",
							},
						},
					)) as { rule: SecurityRule };
					retainedSecurityRule = updatedRule;
					expect(updatedRule).toEqual({
						...rule,
						reason: "Updated fixture IPv6 rule",
					});
					expect(
						await runtimeSecurity(service, `${securityPath}/rules/remove`, {
							...workspaceSession,
							body: { id: nativeRule.id },
						}),
					).toEqual({ success: true });
					const blocked = await service.request(`${alphaPath}/sign-in/email`, {
						body: {
							email: "account@fixture-denied.example",
							password: credentials.password,
						},
					});
					expect(blocked.status).toBe(429);
					expect(await blocked.json()).toMatchObject({
						code: "ALLAUTH_SECURITY_BLOCKED",
					});
					expect(
						await runtimeSecurity(service, securityPath, workspaceSession),
					).toMatchObject({
						policy: retainedSecurityPolicy,
						rules: [updatedRule],
						stats: { activeRules: 1, blockedRequests: 1 },
					});
					expect(
						await runtimeSecurity(
							service,
							`${betaPath}/control/security`,
							workspaceSession,
						),
					).toMatchObject({
						policy: {
							maxFailuresPerIp: defaultSecurityPolicy.maxFailuresPerIp,
						},
						rules: [],
					});
					const events = await securityDB.query(
						`SELECT type,outcome,"actorId","targetId",metadata FROM ${schema}."allauthEvent"
						 WHERE type IN ('security.policy.updated','security.rule.added','security.rule.removed','security.blocked')
						 ORDER BY "createdAt",id`,
					);
					const nativeUpdate = events.rows.find(
						(row) => row.type === "security.policy.updated",
					);
					expect(nativeUpdate).toMatchObject({
						actorId: credentials.platform.id,
						metadata: {
							fields: expect.arrayContaining([
								"maxFailuresPerIp",
								"logRetentionDays",
							]),
						},
					});
					const { rows: deliveries } = await securityDB.query(
						`SELECT "eventType",status,payload FROM ${schema}."allauthWebhookDelivery" WHERE "endpointId"=$1`,
						[securityHook],
					);
					expect(deliveries).toHaveLength(5);
					expect(deliveries).toEqual(
						expect.arrayContaining([
							expect.objectContaining({
								eventType: "security.policy.updated",
								status: "pending",
								payload: expect.objectContaining({
									data: {
										event: expect.objectContaining({
											actorId: credentials.platform.id,
											metadata: nativeUpdate?.metadata,
										}),
									},
								}),
							}),
							expect.objectContaining({
								eventType: "security.rule.added",
								payload: expect.objectContaining({
									data: {
										event: expect.objectContaining({
											targetId: rule.id,
											metadata: { ruleType: "ip" },
										}),
									},
								}),
							}),
							expect.objectContaining({
								eventType: "security.rule.removed",
								payload: expect.objectContaining({
									data: {
										event: expect.objectContaining({
											targetId: nativeRule.id,
											metadata: {},
										}),
									},
								}),
							}),
							expect.objectContaining({
								eventType: "security.blocked",
								payload: expect.objectContaining({
									data: {
										event: expect.objectContaining({
											outcome: "blocked",
											metadata: {
												signal: "email-domain-policy",
												monitor: false,
											},
										}),
									},
								}),
							}),
						]),
					);
					expect(JSON.stringify(deliveries)).not.toContain(
						"fixture-denied.example",
					);
				} finally {
					await securityDB
						.query(
							`DELETE FROM "${alpha.schemaName}"."allauthWebhookEndpoint" WHERE id=$1`,
							[securityHook],
						)
						.finally(() => securityDB.end());
				}
				expect(
					await runtimeApplicationCatalog(service, alpha, rootCookie),
				).toEqual(nativeApplications);
				expect(
					await runtimeApplicationCatalog(service, beta, rootCookie),
				).toEqual(
					expect.arrayContaining([
						expect.objectContaining({ client_id: `${beta.slug}+client` }),
					]),
				);
				expect(
					(
						await service.request(applicationCatalog(alpha), {
							cookie: realmAdminCookie,
						})
					).status,
				).toBe(403);
				expect(
					(
						await service.request(applicationCatalog(alpha), {
							cookie: rootCookie,
							authorization: "Bearer fixture",
						})
					).status,
				).toBe(403);
				expect(
					(
						await service.request(applicationCatalog(alpha), {
							cookie: rootCookie,
							origin: alpha.primaryOrigin,
							body: {},
						})
					).status,
				).toBe(403);
				await expectProjectApplicationWriteDirections(
					service,
					alpha,
					rootCookie,
				);
				expect((await service.request("/api/health")).status).toBe(200);
				const userDirectory = await service.request(usersPath(alpha), {
					cookie: rootCookie,
				});
				expect(userDirectory.status, await userDirectory.clone().text()).toBe(
					200,
				);
				expect(await userDirectory.json()).toMatchObject({
					users: [
						{
							id: credentials.project.id,
							publicMetadata: nativePublicMetadata,
						},
					],
					total: 1,
					limit: 1,
					offset: 0,
				});
				expect(
					(await service.request(usersPath(alpha), { cookie: legacyCookie }))
						.status,
				).toBe(401);
				expect(
					(
						await service.request(userPath(alpha, true), {
							cookie: rootCookie,
							origin: alpha.primaryOrigin,
							method: "PATCH",
							body: { publicMetadata: ownedPublicMetadata },
						})
					).status,
				).toBe(403);
				expect(
					(
						await service.request(userPath(alpha, true), {
							cookie: rootCookie,
							method: "PATCH",
							body: {
								publicMetadata: ownedPublicMetadata,
								privateMetadata: ownedPrivateMetadata,
							},
						})
					).status,
				).toBe(200);
				const userDetail = await service.request(userPath(alpha), {
					cookie: rootCookie,
				});
				expect(userDetail.status).toBe(200);
				const ownedDetail = await userDetail.json();
				expect(ownedDetail).toMatchObject({
					user: {
						id: credentials.project.id,
						publicMetadata: ownedPublicMetadata,
					},
					accounts: expect.arrayContaining([
						expect.objectContaining({ providerId: "credential" }),
					]),
				});
				expect(JSON.stringify(ownedDetail)).not.toContain("fixtureInternal");
				expect(JSON.stringify(ownedDetail)).not.toContain('"password"');
				expect(JSON.stringify(ownedDetail)).not.toContain('"token"');
				const siblingDetail = await service.request(userPath(beta), {
					cookie: rootCookie,
				});
				expect(siblingDetail.status).toBe(200);
				expect(await siblingDetail.text()).not.toContain("consoleLabel");
				for (const [path, host, issuer] of [
					[hostedSchemaPath, alphaHost, hostedIssuer],
					[directSchemaPath, undefined, directIssuer],
				] as const) {
					const schema = await service.request(path, {
						host,
						cookie: realmAdminCookie,
					});
					expect(schema.status).toBe(200);
					expect(schema.headers.get("cache-control")).toBe("no-store");
					expect(schema.headers.getSetCookie()).toEqual([]);
					const document = await schema.json();
					expect(document).toMatchObject({
						openapi: "3.1.1",
						servers: [{ url: issuer }],
						components: {
							securitySchemes: {
								sessionCookie: {
									name: `__Secure-allauth_project_${alpha.slug}.session_token`,
								},
							},
						},
						paths: {
							"/get-session": { get: expect.any(Object) },
							"/sign-in/email": { post: expect.any(Object) },
						},
					});
					const serialized = JSON.stringify(document);
					for (const privateValue of [
						platformSecret,
						credentials.realmAdmin.email,
						alpha.schemaName,
						realmAdminCookie,
					])
						expect(serialized).not.toContain(privateValue);
					for (const refused of [undefined, rootCookie, realmSupportCookie])
						expect(
							(await service.request(path, { host, cookie: refused })).status,
						).toBe(403);
				}
				expect(
					(await service.request(hostedSchemaPath, mixedSchemaCredentials))
						.status,
				).toBe(403);
				expect(
					(
						await service.request(directSchemaPath, {
							...mixedSchemaCredentials,
							host: undefined,
						})
					).status,
				).toBe(403);
				expect(
					(
						await service.request(`${betaPath}${projectOpenApiPath}`, {
							cookie: realmAdminCookie,
						})
					).status,
				).toBe(403);
				expect(
					(await service.request("/api/auth/reference", { host: alphaHost }))
						.status,
				).toBe(404);
				const schemaAuthority = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				try {
					for (const [role, verified, banned] of [
						["user", true, false],
						["admin", false, false],
						["admin", true, true],
					]) {
						await schemaAuthority.query(
							`UPDATE "${alpha.schemaName}"."user" SET role=$2,"emailVerified"=$3,banned=$4 WHERE id=$1`,
							[credentials.realmAdmin.id, role, verified, banned],
						);
						expect(
							(
								await service.request(directSchemaPath, {
									cookie: realmAdminCookie,
								})
							).status,
						).toBe(403);
					}
					await schemaAuthority.query(
						`UPDATE "${alpha.schemaName}"."user" SET role='admin',"emailVerified"=true,banned=false WHERE id=$1`,
						[credentials.realmAdmin.id],
					);
				} finally {
					await schemaAuthority.end();
				}
				const [ownedSchemaCookie, revokedSchemaCookie] = await Promise.all(
					["192.0.2.74", "192.0.2.75"].map(async (clientIP) => {
						const login = await service!.request(`${alphaPath}/sign-in/email`, {
							clientIP,
							body: {
								email: credentials.realmAdmin.email,
								password: credentials.password,
							},
						});
						expect(login.status).toBe(200);
						return cookie(login);
					}),
				);
				for (const browserCookie of [ownedSchemaCookie, revokedSchemaCookie])
					expect(
						(await service.request(directSchemaPath, { cookie: browserCookie }))
							.status,
					).toBe(200);
				expect(
					(
						await service.request(`${alphaPath}/sign-out`, {
							cookie: revokedSchemaCookie,
							body: {},
						})
					).status,
				).toBe(200);
				expect(
					(
						await service.request(directSchemaPath, {
							cookie: revokedSchemaCookie,
						})
					).status,
				).toBe(403);
				const realmSupport = await service.request("/api/auth/get-session", {
					host: alphaHost,
					cookie: realmSupportCookie,
				});
				const realmIdentity = (await realmSupport.json()) as {
					session: { id: string; impersonatedBy: string };
					user: { id: string };
				};
				expect(realmIdentity).toMatchObject({
					session: { impersonatedBy: credentials.realmAdmin.id },
					user: { id: supportTarget },
				});
				const stripped = realmSupportCookie
					.split("; ")
					.filter((part) => !part.includes(".admin_session="))
					.join("; ");
				const realmSupportList = await service.request(`${alphaPath}/sdk/sessions`, {
					cookie: realmSupportCookie,
				});
				expect(realmSupportList.status).toBe(200);
				expect(await realmSupportList.json()).toMatchObject({
					currentSessionId: realmIdentity.session.id,
					sessions: expect.arrayContaining([expect.objectContaining({ id: realmIdentity.session.id })]),
				});
				const missingRealmProof = await service.request(`${alphaPath}/sdk/sessions`, {
					cookie: stripped,
				});
				expect(missingRealmProof.status).toBe(401);
				expect(await missingRealmProof.text()).toBe("");
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: stripped,
						})
					).json(),
				).toBeNull();
				const realmStop = await service.request(
					"/api/auth/admin/stop-impersonating",
					{
						host: alphaHost,
						cookie: realmSupportCookie,
						body: {},
					},
				);
				expect(
					realmStop.status,
					realmStop.ok ? undefined : await realmStop.clone().text(),
				).toBe(200);
				expect(await realmStop.json()).toMatchObject({
					session: { impersonatedBy: null },
					user: { id: credentials.realmAdmin.id },
				});
				const ownedRealmSupport = await service.request(
					"/api/auth/admin/impersonate-user",
					{
						host: alphaHost,
						cookie: cookie(realmStop),
						body: { userId: supportTarget },
					},
				);
				expect(
					ownedRealmSupport.status,
					ownedRealmSupport.ok
						? undefined
						: await ownedRealmSupport.clone().text(),
				).toBe(200);
				const newRealmSupport = cookie(ownedRealmSupport);
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
					).toBe(409);
					expect(await customMetadata.json()).toMatchObject({
						code: "CONFLICT",
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
				const consoleSupportList = await service.request(`${alphaPath}/sdk/sessions`, {
					cookie: supportCookies,
				});
				expect(consoleSupportList.status).toBe(200);
				expect(consoleSupportList.headers.get("cache-control")).toBe("no-store");
				expect(consoleSupportList.headers.getSetCookie()).toEqual([]);
				const consoleSupportSessions = (await consoleSupportList.json()) as typeof legacySupportSessions;
				expect(consoleSupportSessions.currentSessionId).toBe(impersonationId);
				expect(consoleSupportSessions.sessions.find(({ id }) => id === impersonationId)).toEqual(legacySupportSession);
				const unboundSupportList = await service.request(`${alphaPath}/sdk/sessions`, {
					cookie: cookie(impersonation),
				});
				expect(unboundSupportList.status).toBe(401);
				expect(unboundSupportList.headers.get("cache-control")).toBe("no-store");
				expect(await unboundSupportList.text()).toBe("");
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
				const wrongSupportList = await service.request(`${alphaPath}/sdk/sessions`, {
					...connectedSupport,
					origin: alpha.primaryOrigin,
				});
				expect(wrongSupportList.status).toBe(401);
				expect(wrongSupportList.headers.get("cache-control")).toBe("no-store");
				expect(await wrongSupportList.text()).toBe("");
				const boundSupportList = await service.request(`${alphaPath}/sdk/sessions`, connectedSupport);
				expect(boundSupportList.status).toBe(200);
				expect(boundSupportList.headers.getSetCookie()).toEqual([]);
				expect(await boundSupportList.json()).toEqual(consoleSupportSessions);
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
				const appleDirectSignUp = (await appleSignUp.json()) as {
					redirect: boolean;
					user: { id: string; email: string; emailVerified: boolean };
				};
				expect(appleDirectSignUp).toMatchObject({
					redirect: false,
					user: { email: appleDirectEmail, emailVerified: false },
				});
				expect(
					await projectSignInMetadata(
						url(restored),
						alpha,
						appleDirectSignUp.user.id,
					),
				).toEqual([]);
				const appleOwnedLoginEvents = await projectSignInMetadata(
					url(restored),
					alpha,
					appleBrowserUser.id,
				);
				expect(appleOwnedLoginEvents).toHaveLength(1);
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
				const initialCatalog = await service.request(management(alpha), {
					cookie: rootCookie,
				});
				expect(initialCatalog.status).toBe(200);
				expect(await initialCatalog.json()).toMatchObject({
					organizations: [{ id: directoryOrg }],
					total: 1,
					limit: 25,
					offset: 0,
				});
				const projectPrincipal = await service.request(management(alpha), {
					cookie: legacyCookie,
					body: organization,
				});
				expect(projectPrincipal.status).toBe(401);
				const foreignOrigin = await service.request(management(alpha), {
					cookie: rootCookie,
					origin: alpha.primaryOrigin,
					body: organization,
				});
				expect(foreignOrigin.status).toBe(403);
				const foreignOwner = await service.request(management(alpha), {
					cookie: rootCookie,
					body: { ...organization, ownerId: credentials.platform.id },
				});
				expect(foreignOwner.status).toBe(404);
				const consoleCreated = await service.request(management(alpha), {
					cookie: rootCookie,
					body: organization,
				});
				expect(consoleCreated.status, await consoleCreated.clone().text()).toBe(
					201,
				);
				expect(consoleCreated.headers.get("cache-control")).toBe("no-store");
				const { organization: ownedOrganization } =
					(await consoleCreated.json()) as { organization: { id: string } };
				expect(ownedOrganization).toMatchObject({
					id: expect.any(String),
					name: organization.name,
					slug: organization.slug,
					createdAt: expect.any(String),
					memberCount: 1,
					teamCount: 0,
					logo: null,
				});
				const ownedCatalog = await service.request(
					`${management(alpha)}&search=${ownedOrganization.id}&limit=1`,
					{ cookie: rootCookie },
				);
				expect(await ownedCatalog.json()).toEqual({
					organizations: [ownedOrganization],
					total: 1,
					limit: 1,
					offset: 0,
				});
				expect(
					(
						await service.request(management(alpha), {
							cookie: rootCookie,
							body: organization,
						})
					).status,
				).toBe(409);
				const consoleAuthority = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				const otherOwner = randomUUID();
				try {
					const membership = [alpha.workspaceId, credentials.platform.id];
					await consoleAuthority.query(
						`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,'Synthetic Backup Owner',$2,TRUE)`,
						[otherOwner, `${otherOwner}@runtime.fixture.example`],
					);
					await consoleAuthority.query(
						`INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,'owner')`,
						[randomUUID(), alpha.workspaceId, otherOwner],
					);
					await consoleAuthority.query(
						`UPDATE public."allauthWorkspaceMember" SET role='member' WHERE "workspaceId"=$1 AND "userId"=$2`,
						membership,
					);
					try {
						expect(
							(
								await service.request(management(alpha), {
									cookie: rootCookie,
									body: {
										...organization,
										slug: "denied-fixture-organization",
									},
								})
							).status,
						).toBe(401);
					} finally {
						await consoleAuthority.query(
							`UPDATE public."allauthWorkspaceMember" SET role='owner' WHERE "workspaceId"=$1 AND "userId"=$2`,
							membership,
						);
					}
					const audit = await consoleAuthority.query(
						`SELECT e.type,e."actorId",e."userId",m.role FROM "${alpha.schemaName}"."allauthEvent" e
						 JOIN "${alpha.schemaName}"."member" m ON m."organizationId"=e."organizationId" AND m."userId"=e."userId"
						 WHERE e."targetId"=$1`,
						[ownedOrganization.id],
					);
					expect(audit.rows).toEqual([
						{
							type: "organization.created",
							actorId: credentials.platform.id,
							userId: credentials.project.id,
							role: "owner",
						},
					]);
				} finally {
					try {
						await consoleAuthority.query(
							'DELETE FROM public."user" WHERE id=$1',
							[otherOwner],
						);
					} finally {
						await consoleAuthority.end();
					}
				}
				const controlCreated = await service.request(management(beta), {
					cookie: rootCookie,
					body: organization,
				});
				expect(controlCreated.status).toBe(201);
				expect(await controlCreated.json()).toMatchObject({
					organization: {
						id: expect.not.stringMatching(ownedOrganization.id),
						slug: organization.slug,
					},
				});
				const controlIsolation = await service.request(
					`${management(beta)}&search=${ownedOrganization.id}`,
					{ cookie: rootCookie },
				);
				expect(await controlIsolation.json()).toMatchObject({
					organizations: [],
					total: 0,
				});
				const detail = organizationDetail(alpha, ownedOrganization.id);
				const foreignDetail = organizationDetail(beta, ownedOrganization.id);
				expect(
					(await service.request(detail, { cookie: legacyCookie })).status,
				).toBe(401);
				expect(
					(await service.request(foreignDetail, { cookie: rootCookie })).status,
				).toBe(404);
				const initialDetail = await service.request(detail, {
					cookie: rootCookie,
				});
				expect(initialDetail.status).toBe(200);
				expect(await initialDetail.json()).toMatchObject({
					organization: ownedOrganization,
					members: [
						expect.objectContaining({
							userId: credentials.project.id,
							role: "owner",
						}),
					],
					teams: [],
					providers: [],
				});
				const patch = {
					name: "Renamed Fixture Organization",
					logo: "https://fixtures.example/organization-logo.png",
				};
				const updateDetail = await service.request(detail, {
					cookie: rootCookie,
					method: "PATCH",
					body: patch,
				});
				expect(updateDetail.status, await updateDetail.clone().text()).toBe(
					200,
				);
				const patchedOrganization = { ...ownedOrganization, ...patch };
				expect(await updateDetail.json()).toMatchObject({
					organization: { id: ownedOrganization.id, ...patch },
				});
				expect(
					(
						await service.request(detail, {
							cookie: rootCookie,
							origin: alpha.primaryOrigin,
							method: "PATCH",
							body: { name: "Untrusted Change" },
						})
					).status,
				).toBe(403);

				const removable = await service.request(management(alpha), {
					cookie: rootCookie,
					body: { ...organization, slug: "removable-fixture-organization" },
				});
				expect(removable.status).toBe(201);
				const { organization: removableOrganization } =
					(await removable.json()) as { organization: { id: string } };
				const removableId = removableOrganization.id;
				const removableDetail = organizationDetail(alpha, removableId);
				const remove = (path: string, confirmOrganizationId: string) =>
					service!.request(path, {
						cookie: rootCookie,
						method: "DELETE",
						body: { confirmOrganizationId },
					});
				expect(
					(await remove(removableDetail, ownedOrganization.id)).status,
				).toBe(400);
				expect(
					(await remove(organizationDetail(beta, removableId), removableId))
						.status,
				).toBe(404);
				const enterpriseDenied = await remove(
					organizationDetail(alpha, directoryOrg),
					directoryOrg,
				);
				expect(enterpriseDenied.status).toBe(409);
				expect(await enterpriseDenied.json()).toMatchObject({
					error:
						"Remove enterprise SSO and SCIM connections before deleting this organization.",
				});
				const relations = new Pool({ connectionString: url(restored), max: 1 });
				try {
					const realm = `"${alpha.schemaName}"`;
					const team = randomUUID();
					const session = randomUUID();
					const preservedSession = randomUUID();
					const client = randomUUID();
					const grant = randomUUID();
					const preservedGrant = randomUUID();
					const authCode = createHash("sha256")
						.update(randomUUID())
						.digest("base64url");
					const preservedCode = createHash("sha256")
						.update(randomUUID())
						.digest("base64url");
					await relations.query(
						`INSERT INTO ${realm}."team"(id,name,"organizationId","memberCount","createdAt") VALUES ($1,'Synthetic Team',$2,0,now())`,
						[team, removableId],
					);
					await relations.query(
						`INSERT INTO ${realm}."session"(id,token,"userId","expiresAt","updatedAt","activeOrganizationId","activeTeamId")
						 VALUES ($1,$1,$3,now()+interval '1 hour',now(),$4,$6),($2,$2,$3,now()+interval '1 hour',now(),$5,$6)`,
						[
							session,
							preservedSession,
							credentials.project.id,
							removableId,
							directoryOrg,
							team,
						],
					);
					await relations.query(
						`INSERT INTO ${realm}."oauthClient"(id,"clientId","redirectUris",metadata) VALUES ($1,$1,'[]',$2::jsonb)`,
						[client, JSON.stringify({ allauthOrganizationIds: [removableId] })],
					);
					for (const [id, referenceId, code] of [
						[grant, removableId, authCode],
						[preservedGrant, directoryOrg, preservedCode],
					]) {
						const params = [id, client, credentials.project.id, referenceId];
						await relations.query(
							`INSERT INTO ${realm}."oauthRefreshToken"(id,token,"clientId","userId","referenceId","expiresAt","createdAt",scopes,"rotationReplayResponse","rotationReplayExpiresAt")
							 VALUES ($1,$1,$2,$3,$4,now()+interval '1 hour',now(),'["organization:read"]','synthetic-encrypted-replay',now()+interval '1 minute')`,
							params,
						);
						await relations.query(
							`INSERT INTO ${realm}."oauthAccessToken"(id,token,"clientId","userId","referenceId","refreshId","expiresAt","createdAt",scopes)
							 VALUES ($1,$1,$2,$3,$4,$1,now()+interval '1 hour',now(),'["organization:read"]')`,
							params,
						);
						await relations.query(
							`INSERT INTO ${realm}."oauthConsent"(id,"clientId","userId","referenceId","createdAt","updatedAt",scopes)
							 VALUES ($1,$2,$3,$4,now(),now(),'["organization:read"]')`,
							params,
						);
						await relations.query(
							`INSERT INTO ${realm}."verification"(id,identifier,value,"expiresAt") VALUES ($1,$1,$2,now()+interval '1 hour')`,
							[
								code,
								JSON.stringify({
									type: "authorization_code",
									referenceId,
									userId: credentials.project.id,
								}),
							],
						);
					}
					const appDenied = await remove(removableDetail, removableId);
					expect(appDenied.status).toBe(409);
					expect(await appDenied.json()).toMatchObject({
						error:
							"Remove this organization's application bindings before deleting it.",
					});
					await relations.query(
						`UPDATE ${realm}."oauthClient" SET metadata=NULL WHERE id=$1`,
						[client],
					);
					const deleted = await remove(removableDetail, removableId);
					expect(deleted.status, await deleted.clone().text()).toBe(200);
					expect(await deleted.json()).toEqual({ success: true });
					expect(
						(await service.request(removableDetail, { cookie: rootCookie }))
							.status,
					).toBe(404);
					for (const table of [
						"oauthAccessToken",
						"oauthRefreshToken",
						"oauthConsent",
					]) {
						const rows = await relations.query(
							`SELECT id FROM ${realm}."${table}" WHERE id=ANY($1::text[])`,
							[[grant, preservedGrant]],
						);
						expect(rows.rows).toEqual([{ id: preservedGrant }]);
					}
					const codes = await relations.query(
						`SELECT id FROM ${realm}."verification" WHERE id=ANY($1::text[])`,
						[[authCode, preservedCode]],
					);
					expect(codes.rows).toEqual([{ id: preservedCode }]);
					const sessions = await relations.query(
						`SELECT id,"activeOrganizationId","activeTeamId" FROM ${realm}."session" WHERE id=ANY($1::text[])`,
						[[session, preservedSession]],
					);
					expect(sessions.rows).toEqual(
						expect.arrayContaining([
							{ id: session, activeOrganizationId: null, activeTeamId: null },
							{
								id: preservedSession,
								activeOrganizationId: directoryOrg,
								activeTeamId: null,
							},
						]),
					);
					expect(
						(
							await relations.query(
								`SELECT id FROM ${realm}."team" WHERE id=$1`,
								[team],
							)
						).rowCount,
					).toBe(0);
					expect(
						(
							await relations.query(
								`SELECT id FROM ${realm}."member" WHERE "organizationId"=$1`,
								[removableId],
							)
						).rowCount,
					).toBe(0);
					const audit = await relations.query(
						`SELECT action,"actorId","organizationId" FROM ${realm}."allauthAudit" WHERE action IN ('organization.updated','organization.deleted') AND "organizationId"=ANY($1::text[])`,
						[[ownedOrganization.id, removableId]],
					);
					expect(audit.rows).toEqual(
						expect.arrayContaining([
							{
								action: "organization.updated",
								actorId: credentials.platform.id,
								organizationId: ownedOrganization.id,
							},
							{
								action: "organization.deleted",
								actorId: credentials.platform.id,
								organizationId: removableId,
							},
						]),
					);
					await relations.query(
						`DELETE FROM ${realm}."session" WHERE id=ANY($1::text[])`,
						[[session, preservedSession]],
					);
					await relations.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[client],
					);
					await relations.query(
						`DELETE FROM ${realm}."verification" WHERE id=$1`,
						[preservedCode],
					);
				} finally {
					await relations.end();
				}
				const memberRoute = organizationMembers(alpha, ownedOrganization.id);
				const readMembers = (suffix = "") =>
					service!.request(`${memberRoute}${suffix}`, { cookie: rootCookie });
				const changeMember = (body: Record<string, unknown>) =>
					service!.request(memberRoute, { cookie: rootCookie, body });
				const legacyOwnerList = await service.request(
					organizationMembers(alpha, directoryOrg),
					{ cookie: rootCookie },
				);
				expect(legacyOwnerList.status).toBe(200);
				expect(await legacyOwnerList.json()).toMatchObject({
					members: expect.arrayContaining([
						expect.objectContaining({
							userId: credentials.project.id,
							role: "owner",
						}),
					]),
				});
				expect(
					(
						await service.request(
							organizationMembers(beta, ownedOrganization.id),
							{ cookie: rootCookie },
						)
					).status,
				).toBe(404);
				expect(
					(await service.request(memberRoute, { cookie: legacyCookie })).status,
				).toBe(401);
				expect(
					(
						await service.request(memberRoute, {
							cookie: rootCookie,
							origin: alpha.primaryOrigin,
							body: { action: "add", userId: supportTarget },
						})
					).status,
				).toBe(403);
				const { members: initialMembers } = (await (
					await readMembers()
				).json()) as { members: { id: string }[] };
				expect(initialMembers).toHaveLength(1);
				expect(
					(
						await changeMember({
							action: "update",
							memberId: initialMembers[0].id,
							role: "member",
						})
					).status,
				).toBe(409);
				expect(
					(
						await changeMember({
							action: "add",
							userId: credentials.platform.id,
						})
					).status,
				).toBe(404);
				expect(
					(
						await changeMember({
							action: "add",
							userId: candidateGuestData.user.id,
						})
					).status,
				).toBe(400);
				expect(
					(
						await changeMember({
							action: "add",
							userId: supportTarget,
							role: "missing-role",
						})
					).status,
				).toBe(400);
				const addedMember = await changeMember({
					action: "add",
					userId: supportTarget,
				});
				expect(addedMember.status, await addedMember.clone().text()).toBe(200);
				const { member: selectedMember } = (await addedMember.json()) as {
					member: { id: string };
				};
				expect(selectedMember).toMatchObject({
					userId: supportTarget,
					role: "member",
				});
				expect(
					(await changeMember({ action: "add", userId: supportTarget })).status,
				).toBe(409);
				const membership = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				const customRole = "fixture-reviewer";
				let persistedMember: { id: string } | undefined;
				try {
					const realm = `"${alpha.schemaName}"`;
					const organizationId = ownedOrganization.id;
					const team = randomUUID();
					const session = randomUUID();
					const staleSession = randomUUID();
					const client = randomUUID();
					const directoryLink = randomUUID();
					await membership.query(
						`INSERT INTO ${realm}."organizationRole"(id,"organizationId",role,permission) VALUES ($1,$2,$3,'{"member":["update"]}')`,
						[randomUUID(), organizationId, customRole],
					);
					await membership.query(
						`INSERT INTO ${realm}."team"(id,name,"organizationId","memberCount","createdAt") VALUES ($1,'Synthetic Membership Team',$2,1,now())`,
						[team, organizationId],
					);
					await membership.query(
						`INSERT INTO ${realm}."teamMember"(id,"teamId","userId","createdAt") VALUES ($1,$2,$3,now())`,
						[randomUUID(), team, supportTarget],
					);
					expect(
						await (await readMembers(`&teamId=${team}&limit=1`)).json(),
					).toMatchObject({
						members: [
							expect.objectContaining({
								id: selectedMember.id,
								userId: supportTarget,
								role: "member",
								directoryManaged: false,
							}),
						],
						total: 1,
						limit: 1,
						offset: 0,
					});
					expect(
						await (
							await readMembers(`&teamId=${team}&excludeTeam=true`)
						).json(),
					).toMatchObject({
						members: [
							expect.objectContaining({ userId: credentials.project.id }),
						],
						total: 1,
					});
					expect((await readMembers(`&teamId=${randomUUID()}`)).status).toBe(
						404,
					);
					await membership.query(
						`INSERT INTO ${realm}."allauthDirectoryMembership"(id,"organizationId","userId","memberId","createdAt") VALUES ($1,$2,$3,$4,now())`,
						[directoryLink, organizationId, supportTarget, selectedMember.id],
					);
					expect(
						await (await readMembers(`&search=${supportTarget}`)).json(),
					).toMatchObject({
						members: [
							expect.objectContaining({
								id: selectedMember.id,
								directoryManaged: true,
							}),
						],
						total: 1,
					});
					for (const change of [
						{ action: "update", memberId: selectedMember.id, role: customRole },
						{ action: "remove", memberId: selectedMember.id },
					]) {
						const response = await changeMember(change);
						expect(response.status).toBe(409);
						expect(await response.json()).toMatchObject({
							error: "Manage this membership through its SCIM directory.",
						});
					}
					await membership.query(
						`DELETE FROM ${realm}."allauthDirectoryMembership" WHERE id=$1`,
						[directoryLink],
					);
					await membership.query(
						`INSERT INTO ${realm}."session"(id,token,"userId","expiresAt","updatedAt","activeOrganizationId","activeTeamId")
						 VALUES ($1,$1,$3,now()+interval '1 hour',now(),$4,$6),($2,$2,$3,now()+interval '1 hour',now(),$5,$6)`,
						[
							session,
							staleSession,
							supportTarget,
							organizationId,
							directoryOrg,
							team,
						],
					);
					await membership.query(
						`INSERT INTO ${realm}."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[client],
					);
					const preservedGrant = await seedRuntimeMembershipGrant(
						membership,
						alpha.schemaName,
						client,
						credentials.project.id,
						organizationId,
					);
					const changingGrant = await seedRuntimeMembershipGrant(
						membership,
						alpha.schemaName,
						client,
						supportTarget,
						organizationId,
					);
					const expectedRevocation = {
						access: false,
						refresh: false,
						consent: true,
						code: false,
					};
					const updated = await changeMember({
						action: "update",
						memberId: selectedMember.id,
						role: customRole,
					});
					expect(updated.status, await updated.clone().text()).toBe(200);
					expect(await updated.json()).toEqual({ success: true });
					expect(
						await runtimeMembershipGrantState(
							membership,
							alpha.schemaName,
							changingGrant,
						),
					).toEqual(expectedRevocation);
					const removingGrant = await seedRuntimeMembershipGrant(
						membership,
						alpha.schemaName,
						client,
						supportTarget,
						organizationId,
					);
					const removed = await changeMember({
						action: "remove",
						memberId: selectedMember.id,
					});
					expect(removed.status, await removed.clone().text()).toBe(200);
					expect(await removed.json()).toEqual({ success: true });
					expect(
						await runtimeMembershipGrantState(
							membership,
							alpha.schemaName,
							removingGrant,
						),
					).toEqual(expectedRevocation);
					expect(
						await runtimeMembershipGrantState(
							membership,
							alpha.schemaName,
							preservedGrant,
						),
					).toEqual({
						access: true,
						refresh: true,
						consent: true,
						code: true,
					});
					expect(
						await (await readMembers(`&teamId=${team}`)).json(),
					).toMatchObject({ members: [], total: 0 });
					expect(
						(
							await membership.query(
								`SELECT "memberCount" FROM ${realm}."team" WHERE id=$1`,
								[team],
							)
						).rows,
					).toEqual([{ memberCount: 0 }]);
					const selections = await membership.query(
						`SELECT id,"activeOrganizationId","activeTeamId" FROM ${realm}."session" WHERE id=ANY($1::text[])`,
						[[session, staleSession]],
					);
					expect(selections.rows).toEqual(
						expect.arrayContaining([
							{ id: session, activeOrganizationId: null, activeTeamId: null },
							{
								id: staleSession,
								activeOrganizationId: directoryOrg,
								activeTeamId: null,
							},
						]),
					);
					const audit = await membership.query(
						`SELECT type,"actorId","userId","organizationId" FROM ${realm}."allauthEvent" WHERE "targetId"=$1 ORDER BY type`,
						[selectedMember.id],
					);
					expect(audit.rows).toEqual(
						["added", "removed", "role-updated"].map((type) => ({
							type: `organization.member.${type}`,
							actorId: credentials.platform.id,
							userId: supportTarget,
							organizationId,
						})),
					);
					await membership.query(
						`DELETE FROM ${realm}."session" WHERE id=ANY($1::text[])`,
						[[session, staleSession]],
					);
					await membership.query(`DELETE FROM ${realm}."team" WHERE id=$1`, [
						team,
					]);
					await membership.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[client],
					);
					await membership.query(
						`DELETE FROM ${realm}."verification" WHERE id=$1`,
						[preservedGrant.code],
					);
					const retained = await changeMember({
						action: "add",
						userId: supportTarget,
						role: customRole,
					});
					expect(retained.status).toBe(200);
					persistedMember = (
						(await retained.json()) as { member: { id: string } }
					).member;
				} finally {
					await membership.end();
				}
				const teamsRoute = organizationTeams(alpha, ownedOrganization.id);
				const readTeams = (suffix = "") =>
					service!.request(`${teamsRoute}${suffix}`, { cookie: rootCookie });
				const changeTeam = (body: Record<string, unknown>) =>
					service!.request(teamsRoute, { cookie: rootCookie, body });
				expect(await (await readTeams()).json()).toEqual({
					teams: [],
					total: 0,
					limit: 25,
					offset: 0,
				});
				expect(
					(
						await service.request(
							organizationTeams(beta, ownedOrganization.id),
							{ cookie: rootCookie },
						)
					).status,
				).toBe(404);
				expect(
					(await service.request(teamsRoute, { cookie: legacyCookie })).status,
				).toBe(401);
				expect(
					(
						await service.request(teamsRoute, {
							cookie: rootCookie,
							origin: alpha.primaryOrigin,
							body: { action: "create", name: "Untrusted Team" },
						})
					).status,
				).toBe(403);
				async function createTeam(name: string) {
					const created = await changeTeam({ action: "create", name });
					expect(created.status, await created.clone().text()).toBe(200);
					const result = (await created.json()) as {
						success: boolean;
						teamId: string;
					};
					expect(result).toEqual({ success: true, teamId: expect.any(String) });
					return result.teamId;
				}
				const deletedTeam = await createTeam("Temporary Fixture Team");
				const retainedTeam = await createTeam("Surviving Fixture Team");
				const teamName = "Renamed Surviving Fixture Team";
				const teamUpdate = await changeTeam({
					action: "update",
					teamId: retainedTeam,
					name: teamName,
				});
				expect(await teamUpdate.json()).toEqual({
					success: true,
					teamId: retainedTeam,
				});
				expect(
					(
						await changeTeam({
							action: "add-member",
							teamId: retainedTeam,
							userId: credentials.platform.id,
						})
					).status,
				).toBe(400);
				expect(
					(
						await changeTeam({
							action: "add-member",
							teamId: retainedTeam,
							userId: credentials.project.id,
						})
					).status,
				).toBe(200);
				expect(
					await (await readTeams("&search=Surviving&limit=1")).json(),
				).toMatchObject({
					teams: [{ id: retainedTeam, name: teamName, memberCount: 1 }],
					total: 1,
					limit: 1,
					offset: 0,
				});
				const teamDatabase = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				try {
					const realm = `"${alpha.schemaName}"`;
					const session = randomUUID();
					const nativeSeat = randomUUID();
					await teamDatabase.query(
						`INSERT INTO ${realm}."teamMember"(id,"teamId","userId","createdAt") VALUES ($1,$2,$3,now())`,
						[nativeSeat, deletedTeam, supportTarget],
					);
					expect(
						(
							await changeTeam({
								action: "add-member",
								teamId: deletedTeam,
								userId: supportTarget,
							})
						).status,
					).toBe(200);
					const seats = await teamDatabase.query(
						`SELECT id FROM ${realm}."teamMember" WHERE "teamId"=$1`,
						[deletedTeam],
					);
					expect(seats.rows).toEqual([{ id: nativeSeat }]);
					await teamDatabase.query(
						`INSERT INTO ${realm}."session"(id,token,"userId","expiresAt","updatedAt","activeOrganizationId","activeTeamId")
						 VALUES ($1,$1,$2,now()+interval '1 hour',now(),$3,$4)`,
						[session, supportTarget, ownedOrganization.id, deletedTeam],
					);
					const removedSeat = await changeTeam({
						action: "remove-member",
						teamId: deletedTeam,
						userId: supportTarget,
					});
					expect(await removedSeat.json()).toEqual({
						success: true,
						teamId: deletedTeam,
					});
					const cleared = await teamDatabase.query(
						`SELECT "activeOrganizationId","activeTeamId" FROM ${realm}."session" WHERE id=$1`,
						[session],
					);
					expect(cleared.rows).toEqual([
						{ activeOrganizationId: ownedOrganization.id, activeTeamId: null },
					]);
					await teamDatabase.query(
						`UPDATE ${realm}."session" SET "activeTeamId"=$1 WHERE id=$2`,
						[deletedTeam, session],
					);
					const invites = [
						{
							id: randomUUID(),
							teams: `${deletedTeam},${retainedTeam}`,
							expected: retainedTeam,
							status: "pending",
							hours: 1,
						},
						{
							id: randomUUID(),
							teams: deletedTeam,
							expected: null,
							status: "pending",
							hours: 1,
						},
						{
							id: randomUUID(),
							teams: deletedTeam,
							expected: deletedTeam,
							status: "accepted",
							hours: 1,
						},
						{
							id: randomUUID(),
							teams: deletedTeam,
							expected: deletedTeam,
							status: "pending",
							hours: -1,
						},
					];
					for (const invite of invites) {
						await teamDatabase.query(
							`INSERT INTO ${realm}."invitation"(id,"organizationId",email,role,"teamId",status,"expiresAt","inviterId")
							 VALUES ($1,$2,$3,'member',$4,$5,now()+$6::int*interval '1 hour',$7)`,
							[
								invite.id,
								ownedOrganization.id,
								`${invite.id}@runtime.fixture.example`,
								invite.teams,
								invite.status,
								invite.hours,
								credentials.project.id,
							],
						);
					}
					const deleted = await changeTeam({
						action: "delete",
						teamId: deletedTeam,
					});
					expect(deleted.status, await deleted.clone().text()).toBe(200);
					expect(await deleted.json()).toEqual({
						success: true,
						teamId: deletedTeam,
					});
					const survivingInvites = await teamDatabase.query(
						`SELECT id,"teamId",status FROM ${realm}."invitation" WHERE id=ANY($1::text[])`,
						[invites.map((invite) => invite.id)],
					);
					expect(survivingInvites.rows).toEqual(
						expect.arrayContaining(
							invites.map((invite) => ({
								id: invite.id,
								teamId: invite.expected,
								status: invite.status,
							})),
						),
					);
					expect(
						(
							await teamDatabase.query(
								`SELECT "activeTeamId" FROM ${realm}."session" WHERE id=$1`,
								[session],
							)
						).rows,
					).toEqual([{ activeTeamId: null }]);
					const audit = await teamDatabase.query(
						`SELECT type,"actorId","organizationId" FROM ${realm}."allauthEvent" WHERE "targetId"=$1 ORDER BY type`,
						[deletedTeam],
					);
					expect(audit.rows).toEqual(
						["add-member", "create", "delete", "remove-member"].map((type) => ({
							type: `organization.team.${type}`,
							actorId: credentials.platform.id,
							organizationId: ownedOrganization.id,
						})),
					);
					await teamDatabase.query(
						`DELETE FROM ${realm}."session" WHERE id=$1`,
						[session],
					);
					await teamDatabase.query(
						`DELETE FROM ${realm}."invitation" WHERE id=ANY($1::text[])`,
						[invites.map((invite) => invite.id)],
					);
				} finally {
					await teamDatabase.end();
				}
				const rolesRoute = organizationRoles(alpha, ownedOrganization.id);
				const invitationsRoute = organizationInvitations(
					alpha,
					ownedOrganization.id,
				);
				const root = { cookie: rootCookie };
				const retainedRole = "fixture-retained-billing";
				const invitedRole = "fixture-invited-billing";
				const permission = { member: ["update"] };
				const updatedPermission = { member: ["delete"] };
				const changeRole = (body: Record<string, unknown>) =>
					service!.request(rolesRoute, { ...root, body });
				const changeInvitation = (body: Record<string, unknown>) =>
					service!.request(invitationsRoute, { ...root, body });
				for (const path of [rolesRoute, invitationsRoute]) {
					expect(
						(await service.request(path, { cookie: legacyCookie })).status,
					).toBe(401);
					expect(
						(
							await service.request(path, {
								...root,
								origin: alpha.primaryOrigin,
								body: {},
							})
						).status,
					).toBe(403);
				}
				for (const path of [
					organizationRoles(beta, ownedOrganization.id),
					organizationInvitations(beta, ownedOrganization.id),
				])
					expect((await service.request(path, root)).status).toBe(404);
				expect(
					(await changeRole({ action: "delete", role: "owner" })).status,
				).toBe(400);
				expect(
					(await changeRole({ action: "delete", role: customRole })).status,
				).toBe(409);
				for (const role of [retainedRole, invitedRole]) {
					const created = await changeRole({
						action: "create",
						role,
						permission,
					});
					expect(created.status, await created.clone().text()).toBe(200);
					expect(await created.json()).toEqual({ success: true });
				}
				const rolesDatabase = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				try {
					const realm = `"${alpha.schemaName}"`;
					const client = randomUUID();
					await rolesDatabase.query(
						`INSERT INTO ${realm}."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[client],
					);
					const selectedGrant = await seedRuntimeMembershipGrant(
						rolesDatabase,
						alpha.schemaName,
						client,
						credentials.project.id,
						ownedOrganization.id,
					);
					const preservedGrant = await seedRuntimeMembershipGrant(
						rolesDatabase,
						alpha.schemaName,
						client,
						credentials.project.id,
						directoryOrg,
					);
					const updated = await changeRole({
						action: "update",
						role: retainedRole,
						permission: updatedPermission,
					});
					expect(updated.status, await updated.clone().text()).toBe(200);
					expect(
						await runtimeMembershipGrantState(
							rolesDatabase,
							alpha.schemaName,
							selectedGrant,
						),
					).toEqual({
						access: false,
						refresh: false,
						consent: true,
						code: false,
					});
					expect(
						await runtimeMembershipGrantState(
							rolesDatabase,
							alpha.schemaName,
							preservedGrant,
						),
					).toEqual({
						access: true,
						refresh: true,
						consent: true,
						code: true,
					});
					const audit = await rolesDatabase.query(
						`SELECT type,"actorId","organizationId" FROM ${realm}."allauthEvent" WHERE "targetId"=$1 ORDER BY type`,
						[retainedRole],
					);
					expect(audit.rows).toEqual(
						["create", "update"].map((action) => ({
							type: `organization.role.${action}`,
							actorId: credentials.platform.id,
							organizationId: ownedOrganization.id,
						})),
					);
					await rolesDatabase.query(
						`DELETE FROM ${realm}."oauthClient" WHERE id=$1`,
						[client],
					);
					await rolesDatabase.query(
						`DELETE FROM ${realm}."verification" WHERE id=$1`,
						[preservedGrant.code],
					);
				} finally {
					await rolesDatabase.end();
				}
				expect(
					await (
						await service.request(
							`${rolesRoute}&search=fixture-retained&limit=1`,
							root,
						)
					).json(),
				).toMatchObject({
					roles: [
						{
							role: retainedRole,
							permission: updatedPermission,
							builtIn: false,
						},
					],
					total: 1,
					limit: 1,
					offset: 0,
				});
				const inviteEmail = "fixture-console-invite@runtime.fixture.example";
				expect(
					(
						await changeInvitation({
							action: "send",
							email: inviteEmail,
							inviterId: supportTarget,
						})
					).status,
				).toBe(400);
				expect(
					(
						await changeInvitation({
							action: "send",
							email: inviteEmail,
							teamId: deletedTeam,
						})
					).status,
				).toBe(404);
				expect(
					(
						await changeInvitation({
							action: "send",
							email: credentials.project.email,
						})
					).status,
				).toBe(409);
				const sent = await changeInvitation({
					action: "send",
					email: inviteEmail.toUpperCase(),
					role: invitedRole,
					teamId: retainedTeam,
				});
				expect(sent.status, await sent.clone().text()).toBe(201);
				const sentResult = (await sent.json()) as {
					invitation: { id: string };
					emailAccepted: boolean;
				};
				expect(sentResult).toEqual({
					invitation: {
						id: expect.any(String),
						email: inviteEmail,
						role: invitedRole,
						expiresAt: expect.any(String),
					},
					emailAccepted: true,
				});
				const invitationId = sentResult.invitation.id;
				await vi.waitFor(() => {
					const mail = service!.mail.find((item) => item.to === inviteEmail);
					expect(mail?.subject).toContain(patchedOrganization.name);
					expect(mail?.text).toContain(
						`${alpha.primaryOrigin}/account?invitation=${invitationId}`,
					);
				});
				expect(
					(await changeInvitation({ action: "send", email: inviteEmail }))
						.status,
				).toBe(409);
				expect(
					(await changeRole({ action: "delete", role: invitedRole })).status,
				).toBe(409);
				expect(
					(await changeInvitation({ action: "cancel", invitationId })).status,
				).toBe(200);
				expect(
					(await changeRole({ action: "delete", role: invitedRole })).status,
				).toBe(200);
				const failedMail = await changeInvitation({
					action: "send",
					email: rejectedInvitationEmail,
					teamId: retainedTeam,
				});
				expect(failedMail.status, await failedMail.clone().text()).toBe(502);
				const failedResult = (await failedMail.json()) as {
					invitation: { id: string };
					emailAccepted: boolean;
				};
				expect(failedResult).toMatchObject({
					invitation: { email: rejectedInvitationEmail, role: "member" },
					emailAccepted: false,
				});
				const persistedInvitationId = failedResult.invitation.id;
				expect(
					await (
						await service.request(
							`${invitationsRoute}&search=${persistedInvitationId}&limit=1`,
							root,
						)
					).json(),
				).toMatchObject({
					invitations: [
						{
							id: persistedInvitationId,
							email: rejectedInvitationEmail,
							status: "pending",
							teamId: retainedTeam,
							inviterId: credentials.project.id,
						},
					],
					total: 1,
					limit: 1,
					offset: 0,
				});
				const invitationAudit = new Pool({
					connectionString: url(restored),
					max: 1,
				});
				try {
					const events = await invitationAudit.query(
						`SELECT type,"actorId","organizationId","targetId" FROM "${alpha.schemaName}"."allauthEvent" WHERE "targetId"=ANY($1::text[])`,
						[[invitationId, persistedInvitationId]],
					);
					expect(events.rows).toHaveLength(3);
					expect(events.rows).toEqual(
						expect.arrayContaining(
							[
								{
									targetId: invitationId,
									type: "organization.invitation.created",
								},
								{
									targetId: invitationId,
									type: "organization.invitation.cancelled",
								},
								{
									targetId: persistedInvitationId,
									type: "organization.invitation.created",
								},
							].map((event) => ({
								...event,
								actorId: credentials.platform.id,
								organizationId: ownedOrganization.id,
							})),
						),
					);
				} finally {
					await invitationAudit.end();
				}
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
				).toBe(400);
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
				expect(
					await analyticsResponse(
						service,
						analyticsEntitiesPath,
						workspaceSession,
					),
				).toEqual(ownedAnalyticsEntity);
				expect(
					await analyticsResponse(
						service,
						analyticsOrganizationPath,
						workspaceSession,
					),
				).toEqual(ownedAnalyticsOrganizations);
				expect(
					await runtimeSecurity(service, securityPath, workspaceSession),
				).toMatchObject({
					policy: retainedSecurityPolicy,
					rules: [retainedSecurityRule],
				});
				expect(
					await runtimeSecurity(service, `${securityPath}/rules/remove`, {
						...workspaceSession,
						body: { id: retainedSecurityRule?.id },
					}),
				).toEqual({ success: true });
				const nativeBlocked = await service.request("/api/auth/sign-in/email", {
					host: alphaHost,
					clientIP: "192.0.2.119",
					body: {
						email: "account@fixture-denied.example",
						password: credentials.password,
					},
				});
				expect(nativeBlocked.status).toBe(429);
				expect(await nativeBlocked.json()).toMatchObject({
					code: "ALLAUTH_SECURITY_BLOCKED",
				});
				expect(
					await runtimeApplicationCatalog(service, alpha, rootCookie),
				).toEqual(nativeApplications);
				expect(
					(
						await service.request(directSchemaPath, {
							cookie: ownedSchemaCookie,
						})
					).status,
				).toBe(200);
				expect((await service.request("/api/health")).status).toBe(200);
				const rollbackUser = await service.request(userPath(alpha), {
					cookie: rootCookie,
				});
				expect(rollbackUser.status).toBe(200);
				expect(await rollbackUser.json()).toMatchObject({
					user: {
						id: credentials.project.id,
						publicMetadata: ownedPublicMetadata,
					},
				});
				const userAudit = new Pool({ connectionString: url(restored), max: 1 });
				try {
					const metadata = await userAudit.query(
						`SELECT "privateMetadata" FROM "${alpha.schemaName}"."user" WHERE id=$1`,
						[credentials.project.id],
					);
					expect(metadata.rows).toEqual([
						{ privateMetadata: ownedPrivateMetadata },
					]);
					for (const [table, column] of [
						["allauthAudit", "action"],
						["allauthEvent", "type"],
					]) {
						const events = await userAudit.query(
							`SELECT "actorId", "targetId" FROM "${alpha.schemaName}"."${table}" WHERE "${column}"='user.metadata.updated'`,
						);
						expect(events.rows).toEqual(
							Array.from({ length: 2 }, () => ({
								actorId: credentials.platform.id,
								targetId: credentials.project.id,
							})),
						);
					}
				} finally {
					await userAudit.end();
				}
				const nativeRealmStop = await service.request(
					"/api/auth/admin/stop-impersonating",
					{
						host: alphaHost,
						cookie: newRealmSupport,
						body: {},
					},
				);
				expect(
					nativeRealmStop.status,
					nativeRealmStop.ok ? undefined : await nativeRealmStop.clone().text(),
				).toBe(200);
				expect(await nativeRealmStop.json()).toMatchObject({
					session: { impersonatedBy: null },
					user: { id: credentials.realmAdmin.id },
				});
				expect(
					await (
						await service.request("/api/auth/get-session", {
							host: alphaHost,
							cookie: newRealmSupport,
						})
					).json(),
				).toBeNull();
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
				expect(
					await projectSignInMetadata(
						url(restored),
						alpha,
						appleBrowserUser.id,
					),
				).toEqual([appleOwnedLoginEvents[0], appleOwnedLoginEvents[0]]);
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
					organizations: expect.arrayContaining([
						expect.objectContaining({ id: directoryOrg }),
						{ ...patchedOrganization, memberCount: 2, teamCount: 1 },
					]),
					total: 2,
				});
				const rollbackDetail = await service.request(detail, {
					cookie: rootCookie,
				});
				expect(await rollbackDetail.json()).toMatchObject({
					organization: {
						...patchedOrganization,
						memberCount: 2,
						teamCount: 1,
					},
				});
				const rollbackMembers = await service.request(
					`${memberRoute}&search=${supportTarget}&limit=1`,
					{ cookie: rootCookie },
				);
				const rollbackTeams = await service.request(teamsRoute, {
					cookie: rootCookie,
				});
				expect(rollbackTeams.status).toBe(200);
				expect(await rollbackTeams.json()).toMatchObject({
					teams: [{ id: retainedTeam, name: teamName, memberCount: 1 }],
					total: 1,
					limit: 25,
					offset: 0,
				});
				expect(
					await (
						await service.request(
							`${rolesRoute}&search=fixture-retained&limit=1`,
							root,
						)
					).json(),
				).toMatchObject({
					roles: [
						{
							role: retainedRole,
							permission: updatedPermission,
							builtIn: false,
						},
					],
					total: 1,
				});
				expect(
					await (
						await service.request(`${rolesRoute}&search=fixture-invited`, root)
					).json(),
				).toMatchObject({
					roles: [],
					total: 0,
				});
				const rollbackInvitation = `${invitationsRoute}&search=${persistedInvitationId}`;
				expect(
					await (await service.request(rollbackInvitation, root)).json(),
				).toMatchObject({
					invitations: [
						{
							id: persistedInvitationId,
							status: "pending",
							teamId: retainedTeam,
						},
					],
					total: 1,
				});
				const rollbackCancel = await changeInvitation({
					action: "cancel",
					invitationId: persistedInvitationId,
				});
				expect(rollbackCancel.status, await rollbackCancel.clone().text()).toBe(
					200,
				);
				expect(await rollbackCancel.json()).toEqual({ success: true });
				expect(
					await (await service.request(rollbackInvitation, root)).json(),
				).toMatchObject({
					invitations: [{ id: persistedInvitationId, status: "canceled" }],
				});
				const unconfiguredEmail =
					"unconfigured-console-invite@runtime.fixture.example";
				const unconfigured = await changeInvitation({
					action: "send",
					email: unconfiguredEmail,
				});
				expect(unconfigured.status).toBe(409);
				expect(await unconfigured.json()).toEqual({
					error: "Configure Cloudflare email before sending invitations.",
				});
				expect(
					await (
						await service.request(
							`${invitationsRoute}&search=${unconfiguredEmail}`,
							root,
						)
					).json(),
				).toMatchObject({
					invitations: [],
					total: 0,
				});
				expect(rollbackMembers.status).toBe(200);
				expect(await rollbackMembers.json()).toMatchObject({
					members: [
						expect.objectContaining({
							id: persistedMember?.id,
							userId: supportTarget,
							role: customRole,
							directoryManaged: false,
						}),
					],
					total: 1,
					limit: 1,
					offset: 0,
				});
				expect(
					(await service.request(removableDetail, { cookie: rootCookie }))
						.status,
				).toBe(404);
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
						{
							metadata: runtimeSamlSPMetadata(
								nativeSaml[0].flow.acs.replace(alpha.slug, beta.slug),
							),
						},
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
					"stored OAuth client grants are outside the candidate scope",
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

		it("preserves signed custom SAML metadata at its exact verified accounts receiver across process restarts", async () => {
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
					"Custom SAML transport tests require the isolated local PostgreSQL fixture.",
				);
			const admin = new Pool({ connectionString: base.href, max: 1 });
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			let created = false;
			let database: Pool | undefined;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const { alpha, beta, samlKeys } = await seed(databaseURL);
				database = new Pool({ connectionString: databaseURL });
				const directPrefix = `/api/projects/${alpha.slug}/auth`;
				const defaultHost = `${alpha.slug}-accounts.allauth.co`;
				const custom = "runtime-allauth-saml-fixture.net";
				const other = "runtime-allauth-saml-control.net";
				const customHost = `accounts.${custom}`;
				const callbackPath = `/api/auth/sso/saml2/sp/acs/${runtimeSamlProvider}`;
				const canonicalAcs = `https://${customHost}${callbackPath}`;
				const sloPath = `/api/auth/sso/saml2/sp/slo/${runtimeSamlProvider}`;
				const savedReturn = `https://${customHost}/account?from=saved-saml-return`;
				const pair = randomUUID();
				for (const [domain, projectId, id] of [
					[custom, alpha.id, pair],
					[other, beta.id, randomUUID()],
				]) {
					await database.query(
						`INSERT INTO public."allauthDomainPair" (id,"projectId",domain) VALUES ($1,$2,$3)`,
						[id, projectId, domain],
					);
					for (const [kind, label] of [
						["accounts", "accounts"],
						["frontend-api", "api"],
					]) {
						await database.query(
							`INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerStatus","sslStatus","routingVerifiedAt")
							 VALUES ($1,$2,$3,$4,$5,'fixture-domain-proof',now(),'active','active',now())`,
							[randomUUID(), id, projectId, kind, `${label}.${domain}`],
						);
					}
				}
				const setReceiver = async (
					acs: string,
					logout?: string,
					idpInitiatedCallbackUrl?: string,
				) => {
					const metadata = runtimeSamlSPMetadata(acs, undefined, logout);
					const samlConfig = {
						...runtimeSamlConfiguration(samlKeys),
						spMetadata: { metadata },
						idpInitiatedCallbackUrl,
					};
					await database!.query(
						`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"=$1 WHERE "providerId"=$2`,
						[JSON.stringify(samlConfig), runtimeSamlProvider],
					);
					return metadata;
				};
				const unsupported =
					"This development project has a configured SAML provider outside the candidate scope.";
				for (const denied of [
					`https://accounts.${other}${callbackPath}`,
					`https://api.${custom}${callbackPath}`,
					`${canonicalAcs}?variant=unknown`,
				]) {
					await setReceiver(denied);
					await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
						unsupported,
					);
				}
				const metadata = await setReceiver(
					canonicalAcs,
					`https://${customHost}${sloPath}`,
					savedReturn,
				);
				expect(metadata).toContain("SingleLogoutService");
				const direct = {
					prefix: directPrefix,
					baseURL: `${platformOrigin}${directPrefix}`,
					destination: `${platformOrigin}/account?from=custom-saml-direct`,
				};
				const hosted = {
					prefix: "/api/auth",
					baseURL: `https://${defaultHost}/api/auth`,
					host: defaultHost,
					clientIP: "192.0.2.171",
					destination: `https://${defaultHost}/account?from=custom-saml-hosted`,
				};
				const sameHost = {
					prefix: "/api/auth",
					baseURL: `https://${customHost}/api/auth`,
					host: customHost,
					clientIP: "192.0.2.172",
					destination: `https://${customHost}/account?from=custom-saml-hosted`,
				};
				const start = (writer: Awaited<ReturnType<typeof openProcess>>) =>
					Promise.all([
						startRuntimeSaml(writer, direct, canonicalAcs),
						startRuntimeSaml(writer, hosted, canonicalAcs),
						startRuntimeSaml(writer, sameHost, canonicalAcs),
						startRuntimeSaml(
							writer,
							{ ...sameHost, destination: canonicalAcs },
							canonicalAcs,
						),
					]);
				const finish = async (
					writer: Awaited<ReturnType<typeof openProcess>>,
					pending: Awaited<ReturnType<typeof startRuntimeSaml>>,
					checkAlternate = false,
				) => {
					const form = await runtimeSamlResponse(
						samlKeys,
						pending.flow,
						credentials.project.email,
					);
					if (checkAlternate) {
						const alternate = await writer.request(callbackPath, {
							host: defaultHost,
							origin: runtimeSamlOrigin,
							body: form,
						});
						expect(alternate.status).toBe(400);
						expect(alternate.headers.getSetCookie()).toEqual([]);
					}
					const response = await writer.request(callbackPath, {
						host: customHost,
						clientIP: pending.transport.clientIP ?? "192.0.2.170",
						origin: runtimeSamlOrigin,
						body: form,
					});
					expect(response.status, await response.clone().text()).toBe(302);
					expect(response.headers.get("location")).toBe(
						pending.transport.host === defaultHost ||
							pending.transport.destination === canonicalAcs
							? savedReturn
							: pending.transport.destination,
					);
					const signedIn = await writer.request("/api/auth/get-session", {
						host: customHost,
						cookie: cookie(response),
					});
					expect(await signedIn.json()).toMatchObject({
						user: credentials.project,
					});
				};
				const disabledLogout = async (
					writer: Awaited<ReturnType<typeof openProcess>>,
				) => {
					const response = await writer.request(sloPath, { host: customHost });
					expect(response.status).toBe(400);
					expect(await response.json()).toEqual({
						code: "SINGLE_LOGOUT_NOT_ENABLED",
						message: "Single Logout is not enabled",
					});
				};
				const refusedUnsolicited = async (
					writer: Awaited<ReturnType<typeof openProcess>>,
				) => {
					const response = await writer.request(callbackPath, {
						host: customHost,
						origin: runtimeSamlOrigin,
						body: await runtimeSamlResponse(
							samlKeys,
							{ acs: canonicalAcs },
							credentials.project.email,
						),
					});
					expect(response.status).toBe(302);
					expect(response.headers.getSetCookie()).toEqual([]);
					const refused = new URL(savedReturn);
					refused.searchParams.set("error", "unsolicited_response");
					refused.searchParams.set(
						"error_description",
						"IdP-initiated SSO not allowed",
					);
					expect(response.headers.get("location")).toBe(refused.href);
				};
				service = await openProcess(databaseURL, alpha, false);
				await disabledLogout(service);
				await refusedUnsolicited(service);
				const nativePending = await start(service);
				await service.stop();
				service = undefined;

				service = await openProcess(databaseURL, alpha, true);
				await disabledLogout(service);
				await refusedUnsolicited(service);
				for (const [prefix, host] of [
					[directPrefix, undefined],
					["/api/auth", defaultHost],
					["/api/auth", customHost],
				] as const) {
					const document = await service.request(
						`${prefix}/sso/saml2/sp/metadata?providerId=${runtimeSamlProvider}`,
						{ host },
					);
					expect(document.status).toBe(200);
					expect(await document.text()).toBe(metadata);
				}
				for (const pending of nativePending)
					await finish(service, pending, true);
				const ownedPending = await start(service);
				await service.stop();
				service = undefined;

				service = await openProcess(databaseURL, alpha, false);
				await disabledLogout(service);
				await refusedUnsolicited(service);
				for (const pending of ownedPending) await finish(service, pending);
				const directAcs = `${direct.baseURL}/sso/saml2/sp/acs/${runtimeSamlProvider}`;
				await setReceiver(directAcs);
				const directPending = await startRuntimeSaml(
					service,
					direct,
					directAcs,
				);
				await service.stop();
				service = undefined;

				service = await openProcess(databaseURL, alpha, true);
				const directSession = await service.request(
					new URL(directAcs).pathname,
					{
						origin: runtimeSamlOrigin,
						body: await runtimeSamlResponse(
							samlKeys,
							directPending.flow,
							credentials.project.email,
						),
					},
				);
				expect(directSession.status).toBe(302);
				expect(directSession.headers.get("location")).toBe(direct.destination);
				const directPrincipal = await service.request(
					`${directPrefix}/get-session`,
					{ cookie: cookie(directSession) },
				);
				expect(await directPrincipal.json()).toMatchObject({
					user: credentials.project,
				});
				await setReceiver(canonicalAcs);
				await database.query(
					`DELETE FROM public."allauthDomainPair" WHERE id=$1 AND "projectId"=$2`,
					[pair, alpha.id],
				);
				const stopped = await service.request(`${directPrefix}/sign-in/sso`, {
					body: {
						providerId: runtimeSamlProvider,
						providerType: "saml",
						callbackURL: direct.destination,
					},
				});
				expect(stopped.status).toBe(400);
				expect(await stopped.json()).toMatchObject({
					code: "INVALID_SAML_CONFIGURATION",
				});
				expect(
					(
						await service.request(
							`/api/auth/sso/saml2/sp/metadata?providerId=${runtimeSamlProvider}`,
							{ host: customHost },
						)
					).status,
				).toBe(404);
				await service.stop();
				service = undefined;
				await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
					unsupported,
				);
			} finally {
				try {
					await service?.stop();
				} finally {
					try {
						await database?.end();
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 180_000);

		it("pins a synthetic encrypted SAML provider across direct, hosted, and rollback transports", async () => {
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
					"Encrypted SAML runtime checks require isolated local PostgreSQL.",
				);
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			const admin = new Pool({ connectionString: base.href, max: 1 });
			let created = false;
			let database: Pool | undefined;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const { alpha, beta, samlKeys } = await seed(databaseURL);
				const encryptionKeys = await createRuntimeSamlKeys();
				const signing = runtimeSamlConfiguration(samlKeys);
				const samlConfig = {
					...signing,
					idpMetadata: { ...signing.idpMetadata, isAssertionEncrypted: true },
					spMetadata: {
						isAssertionEncrypted: true,
						encPrivateKey: encryptionKeys.privateKey,
					},
				};
				const provider = {
					id: runtimeSamlProvider,
					providerId: runtimeSamlProvider,
					issuer: runtimeSamlEntity,
					domain: "runtime.fixture.example",
					organizationId: null,
					samlConfig,
				};
				const admission = {
					projectId: alpha.id,
					schemaName: alpha.schemaName,
					providerId: provider.providerId,
					recordId: provider.id,
					configurationDigest:
						encryptedSamlFixtureConfigurationDigest(provider),
				};
				const encryption = { certificate: encryptionKeys.certificate };
				database = new Pool({ connectionString: databaseURL, max: 1 });
				const scoped = database;
				async function setSamlConfiguration(config: object) {
					await scoped.query(
						`UPDATE "${alpha.schemaName}"."ssoProvider" SET "samlConfig"=$1 WHERE id=$2`,
						[JSON.stringify(config), provider.id],
					);
				}
				await setSamlConfiguration(samlConfig);
				const unsupported =
					"configured SAML provider outside the candidate scope";
				await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
					unsupported,
				);
				await expect(
					openProcess(databaseURL, alpha, true, alpha.slug, undefined, {
						...admission,
						projectId: beta.id,
					}),
				).rejects.toThrow("invalid encrypted SAML fixture binding");
				await expect(
					openProcess(databaseURL, alpha, true, alpha.slug, undefined, {
						...admission,
						recordId: randomUUID(),
					}),
				).rejects.toThrow(unsupported);

				const prefix = `/api/projects/${alpha.slug}/auth`;
				const host = `${alpha.slug}-accounts.allauth.co`;
				const direct: SamlTransport = {
					prefix,
					baseURL: `${platformOrigin}${prefix}`,
					destination: `${platformOrigin}/account?from=encrypted-saml`,
				};
				const hosted: SamlTransport = {
					prefix: "/api/auth",
					host,
					baseURL: `https://${host}/api/auth`,
					destination: `https://${host}/account?from=encrypted-saml`,
				};
				const metadataPath = (transport: SamlTransport) =>
					`${transport.prefix}/sso/saml2/sp/metadata?providerId=${runtimeSamlProvider}`;
				service = await openProcess(databaseURL, alpha, false);
				const legacyDirect = await startRuntimeSaml(service, direct);
				const legacyHosted = await startRuntimeSaml(service, hosted);
				const legacyMetadata = await service.request(metadataPath(hosted), {
					host,
				});
				expect(legacyMetadata.status).toBe(200);
				const expectedMetadata = await legacyMetadata.text();
				await service.stop();
				service = undefined;

				service = await openProcess(
					databaseURL,
					alpha,
					true,
					alpha.slug,
					undefined,
					admission,
				);
				const observedMetadata = await service.request(metadataPath(hosted), {
					host,
				});
				expect(observedMetadata.status).toBe(200);
				expect(await observedMetadata.text()).toBe(expectedMetadata);
				const directMetadata = await service.request(metadataPath(direct));
				expect(directMetadata.status).toBe(200);
				expect(await directMetadata.text()).toContain(
					`Location="${legacyDirect.flow.acs}"`,
				);
				const wrongTransport = await service.request(
					new URL(legacyDirect.flow.acs).pathname,
					{
						origin: runtimeSamlOrigin,
						body: await runtimeSamlResponse(
							samlKeys,
							legacyHosted.flow,
							credentials.project.email,
							encryption,
						),
					},
				);
				expect(wrongTransport.status).toBe(400);
				expect(cookie(wrongTransport)).toBe("");
				const cbc = await service.request(
					new URL(legacyHosted.flow.acs).pathname,
					{
						host,
						origin: runtimeSamlOrigin,
						body: await runtimeSamlResponse(
							samlKeys,
							legacyHosted.flow,
							credentials.project.email,
							{
								...encryption,
								dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
							},
						),
					},
				);
				expect(cbc.status).toBe(400);
				expect(cookie(cbc)).toBe("");
				await finishRuntimeSaml(service, samlKeys, legacyDirect, encryption);
				await finishRuntimeSaml(service, samlKeys, legacyHosted, encryption);

				const ownedDirect = await startRuntimeSaml(service, direct);
				const ownedHosted = await startRuntimeSaml(service, hosted);
				await scoped.query(
					`UPDATE "${alpha.schemaName}"."ssoProvider" SET "oidcConfig"=(SELECT "oidcConfig" FROM "${alpha.schemaName}"."ssoProvider" WHERE "providerId"=$2) WHERE id=$1`,
					[provider.id, directoryProvider],
				);
				const mixedProtocol = await service.request(
					`${hosted.prefix}/sign-in/sso`,
					{
						host,
						body: {
							providerId: provider.providerId,
							providerType: "oidc",
							callbackURL: hosted.destination,
						},
					},
				);
				expect(mixedProtocol.status).toBe(400);
				expect(await mixedProtocol.json()).toMatchObject({
					code: "INVALID_OIDC_CONFIGURATION",
				});
				await scoped.query(
					`UPDATE "${alpha.schemaName}"."ssoProvider" SET "oidcConfig"=NULL WHERE id=$1`,
					[provider.id],
				);
				await setSamlConfiguration({
					...samlConfig,
					spMetadata: {
						...samlConfig.spMetadata,
						encPrivateKey: samlKeys.privateKey,
					},
				});
				const changedMetadata = await service.request(metadataPath(hosted), {
					host,
				});
				expect(changedMetadata.status).toBe(400);
				const changedKey = await service.request(
					new URL(ownedHosted.flow.acs).pathname,
					{
						host,
						origin: runtimeSamlOrigin,
						body: await runtimeSamlResponse(
							samlKeys,
							ownedHosted.flow,
							credentials.project.email,
							encryption,
						),
					},
				);
				expect(changedKey.status).toBe(400);
				expect(cookie(changedKey)).toBe("");
				await setSamlConfiguration(samlConfig);
				await service.stop();
				service = undefined;

				service = await openProcess(databaseURL, alpha, false);
				await finishRuntimeSaml(service, samlKeys, ownedDirect, encryption);
				await finishRuntimeSaml(service, samlKeys, ownedHosted, encryption);
				await service.stop();
				service = undefined;

				const custom = {
					...samlConfig,
					spMetadata: {
						...samlConfig.spMetadata,
						metadata: runtimeSamlSPMetadata(legacyDirect.flow.acs),
					},
				};
				await setSamlConfiguration(custom);
				await expect(
					openProcess(databaseURL, alpha, true, alpha.slug, undefined, {
						...admission,
						configurationDigest: encryptedSamlFixtureConfigurationDigest({
							...provider,
							samlConfig: custom,
						}),
					}),
				).rejects.toThrow(unsupported);
			} finally {
				try {
					await service?.stop();
				} finally {
					try {
						await database?.end();
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 90_000);

		it.each(["protected", "production"] as const)("rehearses native-stored GCM configuration and certificate renewal at the verified custom SAML receiver (%s)", async (cohort) => {
			const production = cohort === "production";
			const local: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixture, "utf8"),
			);
			const base = new URL(local.DATABASE_URL);
			if (
				local.container !== "allauth-production-test-20261007" ||
				base.hostname !== "127.0.0.1" ||
				base.port !== "55445"
			)
				throw new Error("Custom encrypted SAML requires isolated PostgreSQL.");
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			const admin = new Pool({ connectionString: base.href, max: 1 });
			let created = false;
			let database: Pool | undefined;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const { alpha, beta, samlKeys } = await seed(databaseURL);
				const encryption = await createRuntimeSamlKeys();
				const renewedCertificate = await renewRuntimeSamlCertificate(
					encryption.privateKey,
				);
				expect(renewedCertificate).not.toBe(encryption.certificate);
				const passphrase = "synthetic-persisted-saml-key-passphrase";
				const encryptedKey = createPrivateKey(encryption.privateKey).export({
					type: "pkcs8",
					format: "pem",
					cipher: "aes-256-cbc",
					passphrase,
				});
				database = new Pool({ connectionString: databaseURL });
				const scope = `"${alpha.schemaName}"."ssoProvider"`;
				const domain = "runtime-encrypted-saml-fixture.net";
				const host = `accounts.${domain}`;
				const defaultHost = `${alpha.slug}-accounts.allauth.co`;
				const callback = `/api/auth/sso/saml2/sp/acs/${runtimeSamlProvider}`;
				const acs = `https://${host}${callback}`;
				const pair = randomUUID();
				await database.query(
					`INSERT INTO public."allauthDomainPair" (id,"projectId",domain) VALUES ($1,$2,$3)`,
					[pair, alpha.id, domain],
				);
				for (const [kind, hostname] of [
					["accounts", host],
					["frontend-api", `api.${domain}`],
				]) {
					await database.query(
						`INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerStatus","sslStatus","routingVerifiedAt")
						 VALUES ($1,$2,$3,$4,$5,'fixture-domain-proof',now(),'active','active',now())`,
						[randomUUID(), pair, alpha.id, kind, hostname],
					);
				}
				// Keep the seeded account link but replace its provider row through the real native endpoint.
				await database.query(`DELETE FROM ${scope} WHERE "providerId"=$1`, [
					runtimeSamlProvider,
				]);
				const metadata = runtimeSamlSPMetadata(acs, [
					encryption.certificate,
					renewedCertificate,
				]);
				const { issuer, ...signing } = runtimeSamlConfiguration(samlKeys);
				const algorithmHints = {
					dataEncryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
					keyEncryptionAlgorithm:
						"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
				};
				service = await openProcess(databaseURL, alpha, false);
				const login = await service.request("/api/auth/sign-in/email", {
					host: defaultHost,
					clientIP: "192.0.2.182",
					body: {
						email: credentials.realmAdmin.email,
						password: credentials.password,
					},
				});
				expect(login.status).toBe(200);
				const administrator = cookie(login);
				const registered = await service.request("/api/auth/sso/register", {
					host: defaultHost,
					cookie: administrator,
					clientIP: "192.0.2.182",
					body: {
						providerId: runtimeSamlProvider,
						issuer,
						domain: "runtime.fixture.example",
						samlConfig: {
							...signing,
							...algorithmHints,
							idpMetadata: {
								...signing.idpMetadata,
								...algorithmHints,
								isAssertionEncrypted: true,
							},
							spMetadata: {
								...algorithmHints,
								metadata,
								isAssertionEncrypted: true,
								encPrivateKey: encryption.privateKey,
							},
						},
					},
				});
				expect(registered.status).toBe(200);
				async function savedProvider() {
					const result = await database!.query<{
						id: string;
						providerId: string;
						issuer: string;
						domain: string;
						organizationId: string | null;
						samlConfig: string;
					}>(
						`SELECT id,"providerId",issuer,domain,"organizationId","samlConfig" FROM ${scope} WHERE "providerId"=$1`,
						[runtimeSamlProvider],
					);
					const row = result.rows[0]!;
					const samlConfig: Record<string, unknown> & {
						idpMetadata: Record<string, unknown>;
						spMetadata: Record<string, unknown>;
					} = JSON.parse(row.samlConfig);
					return { ...row, samlConfig };
				}
				function checkStoredEncryption(
					provider: Awaited<ReturnType<typeof savedProvider>>,
					key: string,
					password?: string,
				) {
					const { samlConfig } = provider;
					for (const record of [
						samlConfig,
						samlConfig.idpMetadata,
						samlConfig.spMetadata,
					]) {
						for (const name of Object.keys(algorithmHints))
							expect(Object.hasOwn(record, name)).toBe(false);
					}
					expect(samlConfig.idpMetadata.isAssertionEncrypted).toBe(true);
					expect(samlConfig.spMetadata.isAssertionEncrypted).toBe(true);
					expect(samlConfig.spMetadata.metadata).toBe(metadata);
					expect(samlConfig.spMetadata.encPrivateKey === key).toBe(true);
					expect(samlConfig.spMetadata.encPrivateKeyPass === password).toBe(
						true,
					);
				}
				checkStoredEncryption(await savedProvider(), encryption.privateKey);
				const updated = await service.request("/api/auth/sso/update-provider", {
					host: defaultHost,
					cookie: administrator,
					clientIP: "192.0.2.182",
					body: {
						providerId: runtimeSamlProvider,
						samlConfig: {
							...algorithmHints,
							spMetadata: {
								...algorithmHints,
								encPrivateKey: encryptedKey,
								encPrivateKeyPass: passphrase,
							},
						},
					},
				});
				expect(updated.status).toBe(200);
				const provider = await savedProvider();
				checkStoredEncryption(provider, encryptedKey, passphrase);
				await database.query(
					`UPDATE ${scope} SET "domainVerified"=TRUE WHERE id=$1`,
					[provider.id],
				);
				const writerCli = (args: string[], environment: Partial<NodeJS.ProcessEnv> = {}) =>
					promisify(execFile)(
						process.execPath,
						["scripts/project-engine-writer.mjs", ...args],
						{
							cwd: appRoot,
							env: {
								...childEnvironment(),
								DATABASE_URL: databaseURL,
								...environment,
							},
						},
					);
				let fencedProject: Project;
				if (production) {
					await service.stop();
					service = undefined;
					await database.query(
						`UPDATE public."allauthProject" SET environment='production' WHERE id=$1`,
						[alpha.id],
					);
					await writerCli(["register-production", alpha.id, alpha.workspaceId]);
					fencedProject = { ...alpha, environment: "production", projectEngineFenced: true };
					service = await openProcess(databaseURL, fencedProject, false);
				} else {
					await database.query(
						`UPDATE public."allauthProject" SET "workspaceId"=$1 WHERE id=$2`,
						[platformWorkspaceId, alpha.id],
					);
					fencedProject = { ...alpha, workspaceId: platformWorkspaceId };
				}
				const rolloutEnvironment = (policy?: object): Partial<NodeJS.ProcessEnv> =>
					production
						? {
								ALLAUTH_PROJECT_ENGINE_PRODUCTION_REVISIONS: JSON.stringify({ [alpha.id]: 0 }),
								ALLAUTH_PROJECT_ENGINE_PRODUCTION_SAML_APPROVALS:
									policy && JSON.stringify({ [alpha.id]: policy }),
							}
						: {
								ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: alpha.id,
								ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION: "0",
								ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL:
									policy && JSON.stringify(policy),
							};
				const admission = {
					projectId: alpha.id,
					schemaName: alpha.schemaName,
					providerId: provider.providerId,
					recordId: provider.id,
					configurationDigest:
						encryptedSamlFixtureConfigurationDigest(provider),
				};
				const directPrefix = `/api/projects/${alpha.slug}/auth`;
				const direct: SamlTransport = {
					prefix: directPrefix,
					baseURL: `${platformOrigin}${directPrefix}`,
					destination: `${platformOrigin}/account?from=custom-encrypted-direct`,
					clientIP: "192.0.2.184",
				};
				const hosted: SamlTransport = {
					prefix: "/api/auth",
					host,
					baseURL: `https://${host}/api/auth`,
					destination: `https://${host}/account?from=custom-encrypted-hosted`,
					clientIP: "192.0.2.185",
				};
				const starts = (writer: Awaited<ReturnType<typeof openProcess>>) =>
					Promise.all([
						startRuntimeSaml(writer, direct, acs),
						startRuntimeSaml(writer, hosted, acs),
					]);
				async function inspect(
					form: URLSearchParams,
					receiver = acs,
					projectId: string | null = alpha.id,
				) {
					const operator = spawn(
						process.execPath,
						[
							"--import",
							"tsx",
							"scripts/rehearsal/verify-project-encrypted-saml.ts",
							...(production && projectId ? ["--project", projectId] : []),
							alpha.slug,
							runtimeSamlProvider,
						],
						{
							cwd: appRoot,
							env: {
								...childEnvironment(),
								DATABASE_URL: databaseURL,
								...rolloutEnvironment(),
							},
							timeout: 10_000,
						},
					);
					let output = "";
					let diagnostics = "";
					operator.stdout.setEncoding("utf8").on("data", (chunk: string) => {
						output += chunk;
					});
					operator.stderr.setEncoding("utf8").on("data", (chunk: string) => {
						diagnostics += chunk;
					});
					operator.stdin.end(
						JSON.stringify({
							receiver,
							samlResponse: form.get("SAMLResponse"),
							relayState: form.get("RelayState"),
						}),
					);
					const [code] = await once(operator, "close");
					return { code, output, diagnostics };
				}
				const rejectedEvidence = {
					code: 1,
					output: "",
					diagnostics:
						"The encrypted SAML preflight sample could not be verified.\n",
				};
				const responseFor = (
					pending: Awaited<ReturnType<typeof startRuntimeSaml>>,
					approvedCipher?: string,
				) =>
					runtimeSamlResponse(
						samlKeys,
						pending.flow,
						credentials.project.email,
						{
							certificate: pending.transport.host
								? renewedCertificate
								: encryption.certificate,
							dataAlgorithm:
								approvedCipher ??
								(pending.transport.host
									? algorithmHints.dataEncryptionAlgorithm
									: "http://www.w3.org/2009/xmlenc11#aes128-gcm"),
						},
					);
				const finish = async (
					writer: Awaited<ReturnType<typeof openProcess>>,
					pending: Awaited<ReturnType<typeof startRuntimeSaml>>,
					{ checkAlternate = false, checkEvidence = false, form }: {
						checkAlternate?: boolean;
						checkEvidence?: boolean;
						form?: URLSearchParams;
					} = {},
				) => {
					form ??= await responseFor(pending);
					if (checkEvidence) {
						if (!pending.transport.host) {
							if (production) {
								expect(await inspect(form, acs, beta.id)).toEqual(rejectedEvidence);
								expect(await inspect(form, acs, null)).toEqual(rejectedEvidence);
							}
							expect(
								await inspect(form, `https://${defaultHost}${callback}`),
							).toEqual(rejectedEvidence);
							const cbc = await runtimeSamlResponse(
								samlKeys,
								pending.flow,
								credentials.project.email,
								{
									certificate: encryption.certificate,
									dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
								},
							);
							expect(await inspect(cbc)).toEqual(rejectedEvidence);
						}
						const evidence = await inspect(form);
						expect(evidence.code, evidence.diagnostics).toBe(0);
						expect(evidence.diagnostics).toBe("");
						expect(JSON.parse(evidence.output)).toEqual({
							kind: "observed-encrypted-saml-sample",
							projectId: alpha.id,
							schemaName: alpha.schemaName,
							providerId: runtimeSamlProvider,
							providerRecordId: provider.id,
							legacyWriterRevision: 0,
							receiver: acs,
							issuer: runtimeSamlIssuer,
							configurationFingerprint:
								expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
							observedAt: expect.any(String),
							cipher: pending.transport.host ? "aes256-gcm" : "aes128-gcm",
							keyTransport: "rsa-oaep-mgf1p",
							envelopeSigned: false,
							assertionSigned: true,
						});
					}
					if (checkAlternate) {
						const alternate = await writer.request(callback, {
							host: defaultHost,
							clientIP: "192.0.2.186",
							origin: runtimeSamlOrigin,
							body: form,
						});
						expect(alternate.status).toBe(400);
						expect(cookie(alternate)).toBe("");
					}
					const completed = await writer.request(callback, {
						host,
						clientIP: pending.transport.clientIP,
						origin: runtimeSamlOrigin,
						body: form,
					});
					expect(completed.status, await completed.clone().text()).toBe(302);
					expect(completed.headers.get("location")).toBe(
						pending.transport.destination,
					);
					const session = await writer.request("/api/auth/get-session", {
						host,
						cookie: cookie(completed),
					});
					expect(await session.json()).toMatchObject({
						user: credentials.project,
					});
					if (checkEvidence)
						expect(await inspect(form)).toEqual(rejectedEvidence);
				};
				for (const pending of await starts(service))
					await finish(service, pending, { checkEvidence: true });
				const nativePending = production ? [] : await starts(service);
				await service.stop();
				service = undefined;
				const setConfiguration = (value: object) =>
					database!.query(`UPDATE ${scope} SET "samlConfig"=$1 WHERE id=$2`, [
						JSON.stringify(value),
						provider.id,
					]);
				if (!production) {
					const unsupported =
						"configured SAML provider outside the candidate scope";
					await expect(openProcess(databaseURL, alpha, true)).rejects.toThrow(
						unsupported,
					);
					const mismatched = {
						...provider.samlConfig,
						spMetadata: {
							...provider.samlConfig.spMetadata,
							metadata: runtimeSamlSPMetadata(acs, [
								encryption.certificate,
								samlKeys.certificate,
							]),
						},
					};
					await setConfiguration(mismatched);
					await expect(
						openProcess(databaseURL, alpha, true, alpha.slug, undefined, {
							...admission,
							configurationDigest: encryptedSamlFixtureConfigurationDigest({
								...provider,
								samlConfig: mismatched,
							}),
						}),
					).rejects.toThrow(unsupported);
					await setConfiguration(provider.samlConfig);
					service = await openProcess(
						databaseURL,
						alpha,
						true,
						alpha.slug,
						undefined,
						admission,
					);
					for (const transport of [direct, hosted]) {
						const published = await service.request(
							`${transport.prefix}/sso/saml2/sp/metadata?providerId=${runtimeSamlProvider}`,
							{ host: transport.host },
						);
						expect(published.status).toBe(200);
						expect(await published.text()).toBe(metadata);
					}
					const view = await service.request(
						`/api/auth/sso/get-provider?providerId=${runtimeSamlProvider}`,
						{
							host: defaultHost,
							cookie: administrator,
						},
					);
					expect(view.status).toBe(200);
					const publicRecord = await view.text();
					for (const privateValue of [
						"encPrivateKey",
						"BEGIN ENCRYPTED PRIVATE KEY",
						passphrase,
					])
						expect(publicRecord.includes(privateValue)).toBe(false);
					for (const pending of nativePending)
						await finish(service, pending, { checkAlternate: true });
					const ownedPending = await starts(service);
					await service.stop();
					service = undefined;
					service = await openProcess(databaseURL, alpha, false);
					for (const pending of ownedPending) await finish(service, pending);
					await service.stop();
					service = undefined;
				}
				const fence = createProjectEngineWriterLease({
					database,
					project: fencedProject,
					selectedProjectId: alpha.id,
				});
				const approval = {
					kind: "operator-verified-encrypted-saml-policy-v1",
					projectId: alpha.id,
					schemaName: alpha.schemaName,
					providerId: provider.providerId,
					providerRecordId: provider.id,
					legacyWriterRevision: 0,
					receiver: acs,
					configurationFingerprint: encryptedSamlConfigurationFingerprint(
						platformSecret,
						alpha.id,
						alpha.schemaName,
						acs,
						{ ...provider, domainVerified: true },
					),
					policyRevision: "synthetic-idp-policy-revision",
					verifiedAt: new Date(Date.now() - 60_000).toISOString(),
					expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
					profiles: [{ cipher: "aes256-gcm", signatures: "assertion" }],
				};
				const expired = {
					...approval,
					expiresAt: new Date(Date.now() - 1000).toISOString(),
				};
				const openFenced = (policy?: object, overrides: Partial<NodeJS.ProcessEnv> = {}) =>
					openProcess(databaseURL, fencedProject, false, fencedProject.slug, undefined, undefined, {
						EMAIL_PROVIDER: "cloudflare",
						EMAIL_FROM: "saml-restart@runtime.fixture.example",
						CLOUDFLARE_ACCOUNT_ID: "a".repeat(32),
						CLOUDFLARE_EMAIL_API_TOKEN: "synthetic-saml-restart-mail-token",
						...rolloutEnvironment(policy),
						...overrides,
					});
				const incompatible = {
					...approval,
					profiles: [{ cipher: "aes256-gcm", signatures: "response" }],
				};
				const sampleReceipt = {
					...approval,
					kind: "observed-encrypted-saml-sample",
				};
				for (const unapproved of [
					undefined,
					expired,
					incompatible,
					sampleReceipt,
				]) {
					service = await openFenced(unapproved);
					expect((await service.request("/api/health")).status).toBe(503);
					await service.stop();
					service = undefined;
				}
				const switchWithCli = (
					policy: object | undefined,
					previous = "legacy",
					revision = "0",
					next = "allauth",
					overrides: Partial<NodeJS.ProcessEnv> = {},
				) =>
					writerCli(
						[
							...(production ? ["--project", alpha.id] : []),
							"switch",
							previous,
							revision,
							next,
						],
						{
							...rolloutEnvironment(policy),
							...overrides,
						},
					);
				await expect(switchWithCli(undefined)).rejects.toThrow(
					"requires deployment approval",
				);
				if (production) {
					const foreignApproval = {
						...approval,
						projectId: beta.id,
						schemaName: beta.schemaName,
					};
					const foreignSettings = {
						ALLAUTH_PROJECT_ENGINE_PRODUCTION_SAML_APPROVALS: JSON.stringify({ [beta.id]: foreignApproval }),
						ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL: JSON.stringify(approval),
					};
					service = await openFenced(undefined, foreignSettings);
					expect((await service.request("/api/health")).status).toBe(503);
					await service.stop();
					service = undefined;
					await expect(switchWithCli(undefined, "legacy", "0", "allauth", foreignSettings)).rejects.toThrow(
						"requires deployment approval",
					);
					await expect(switchWithCli(foreignApproval)).rejects.toThrow();
					expect(await fence.read()).toEqual({ writer: "legacy", revision: 0 });
				}
				await expect(switchWithCli(expired)).rejects.toThrow(
					"outside its activation window",
				);
				for (const malformed of [
					{
						...approval,
						profiles: [...approval.profiles, ...approval.profiles],
					},
					{ ...approval, extra: true },
					{
						...approval,
						profiles: [{ ...approval.profiles[0]!, extra: true }],
					},
					{
						...approval,
						verifiedAt: new Date(approval.verifiedAt).toUTCString(),
					},
				]) {
					await expect(switchWithCli(malformed)).rejects.toThrow(
						"outside its activation window",
					);
					expect(await fence.read()).toEqual({ writer: "legacy", revision: 0 });
				}
				await setConfiguration({});
				await expect(switchWithCli(undefined)).rejects.toThrow(
					"stored project SAML configuration is unavailable",
				);
				expect(await fence.read()).toEqual({ writer: "legacy", revision: 0 });
				await setConfiguration(provider.samlConfig);
				const configurationFingerprint = (
					receiver: string,
					samlConfig: Record<string, unknown>,
				) =>
					encryptedSamlConfigurationFingerprint(
						platformSecret,
						alpha.id,
						alpha.schemaName,
						receiver,
						{ ...provider, samlConfig, domainVerified: true },
					);
				const alternateReceiver = `https://${defaultHost}${callback}`;
				await expect(
					switchWithCli({
						...approval,
						receiver: alternateReceiver,
						configurationFingerprint: configurationFingerprint(
							alternateReceiver,
							provider.samlConfig,
						),
					}),
				).rejects.toThrow("does not match deployment approval");
				const xmlRequiresAssertion = {
					...provider.samlConfig,
					wantAssertionsSigned: false,
				};
				await setConfiguration(xmlRequiresAssertion);
				await expect(
					switchWithCli({
						...incompatible,
						configurationFingerprint: configurationFingerprint(
							acs,
							xmlRequiresAssertion,
						),
					}),
				).rejects.toThrow("does not match deployment approval");
				expect(await fence.read()).toEqual({ writer: "legacy", revision: 0 });
				await setConfiguration({
					...provider.samlConfig,
					wantAssertionsSigned: false,
				});
				await expect(switchWithCli(approval)).rejects.toThrow(
					"does not match deployment approval",
				);
				await setConfiguration(provider.samlConfig);
				expect(await fence.read()).toEqual({ writer: "legacy", revision: 0 });
				service = await openFenced(approval);
				expect((await service.request("/api/health")).status).toBe(200);
				const proxiedDirect = {
					...direct,
					proxy: fencedProject,
					origin: fencedProject.primaryOrigin,
				};
				const fencedStarts = (
					writer: Awaited<ReturnType<typeof openProcess>>,
				) =>
					Promise.all([
						startRuntimeSaml(writer, proxiedDirect, acs),
						startRuntimeSaml(writer, hosted, acs),
					]);
				const legacyFlows = await fencedStarts(service);
				const legacyForms = await Promise.all(legacyFlows.map((pending) =>
					responseFor(pending, algorithmHints.dataEncryptionAlgorithm),
				));
				if (production)
					for (const form of legacyForms) {
						const evidence = await inspect(form);
						expect(evidence.code, evidence.diagnostics).toBe(0);
						expect(JSON.parse(evidence.output)).toMatchObject({
							projectId: approval.projectId,
							configurationFingerprint: approval.configurationFingerprint,
							legacyWriterRevision: approval.legacyWriterRevision,
							cipher: "aes256-gcm",
						});
					}
				expect(JSON.parse((await switchWithCli(approval)).stdout)).toEqual({
					writer: "allauth",
					revision: 1,
				});
				expect((await service.request("/api/health")).status).toBe(200);
				for (const [index, pending] of legacyFlows.entries())
					await finish(service, pending, { form: legacyForms[index]! });
				const pending = await startRuntimeSaml(service, hosted, acs);
				const profileDrift = await runtimeSamlResponse(
					samlKeys,
					pending.flow,
					credentials.project.email,
					{
						certificate: renewedCertificate,
						dataAlgorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
					},
				);
				const wrongProfile = await service.request(callback, {
					host,
					origin: runtimeSamlOrigin,
					body: profileDrift,
				});
				expect(wrongProfile.status).toBe(400);
				expect(cookie(wrongProfile)).toBe("");
				const cbc = await runtimeSamlResponse(
					samlKeys,
					pending.flow,
					credentials.project.email,
					{
						certificate: renewedCertificate,
						dataAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
					},
				);
				const legacyCipher = await service.request(callback, {
					host,
					origin: runtimeSamlOrigin,
					body: cbc,
				});
				expect(legacyCipher.status).toBe(400);
				expect(cookie(legacyCipher)).toBe("");
				const valid = await runtimeSamlResponse(
					samlKeys,
					pending.flow,
					credentials.project.email,
					{ certificate: renewedCertificate },
				);
				const assertUnavailable = async () => {
					expect((await service!.request("/api/health")).status).toBe(503);
					const start = await service!.request(`${directPrefix}/sign-in/sso`, {
						proxy: fencedProject,
						origin: fencedProject.primaryOrigin,
						clientIP: "192.0.2.189",
						body: {
							providerId: runtimeSamlProvider,
							providerType: "saml",
							callbackURL: direct.destination,
						},
					});
					expect(start.status).toBe(503);
				};
				const tagged = new Pool({
					connectionString: databaseURL,
					max: 1,
					options: projectEngineWriterConnectionOptions(alpha.id, {
						writer: "allauth",
						revision: 1,
					}),
				});
				try {
					const save = (value: object) =>
						tagged.query(`UPDATE ${scope} SET "samlConfig"=$1 WHERE id=$2`, [
							JSON.stringify(value),
							provider.id,
						]);
					await save({ ...provider.samlConfig, wantAssertionsSigned: false });
					await assertUnavailable();
					const drift = await service.request(callback, {
						host,
						origin: runtimeSamlOrigin,
						body: valid,
					});
					expect(drift.status).toBe(503);
					expect(cookie(drift)).toBe("");
					await save(provider.samlConfig);
				} finally {
					await tagged.end();
				}
				await database.query(
					`UPDATE public."allauthCustomHostname" SET "routingVerifiedAt"=NULL WHERE "pairId"=$1 AND hostname=$2`,
					[pair, host],
				);
				await assertUnavailable();
				await database.query(
					`UPDATE public."allauthCustomHostname" SET "routingVerifiedAt"=now() WHERE "pairId"=$1 AND hostname=$2`,
					[pair, host],
				);
				expect((await service.request("/api/health")).status).toBe(200);
				await finish(service, pending, { form: valid });
				await service.stop();
				service = undefined;
				service = await openFenced(expired);
				expect((await service.request("/api/health")).status).toBe(200);
				const expiredFlow = await startRuntimeSaml(service, hosted, acs);
				await finish(service, expiredFlow, {
					form: await responseFor(expiredFlow, algorithmHints.dataEncryptionAlgorithm),
				});
				const rollbackFlows = await fencedStarts(service);
				const rollbackForms = await Promise.all(rollbackFlows.map((pending) =>
					responseFor(pending, algorithmHints.dataEncryptionAlgorithm),
				));
				expect(
					JSON.parse(
						(await switchWithCli(expired, "allauth", "1", "legacy")).stdout,
					),
				).toEqual({ writer: "legacy", revision: 2 });
				for (const [index, pending] of rollbackFlows.entries())
					await finish(service, pending, { form: rollbackForms[index]! });
				if (production) {
					for (const [index, form] of [...legacyForms, ...rollbackForms].entries()) {
						const replay = await service.request(callback, {
							host,
							clientIP: `192.0.2.${190 + index}`,
							origin: runtimeSamlOrigin,
							body: form,
						});
						expect(replay.status).toBe(302);
						expect(replay.headers.get("location")).toContain("error=invalid_saml_response");
						expect(cookie(replay)).toBe("");
					}
				}
			} finally {
				try {
					await service?.stop();
				} finally {
					try {
						await database?.end();
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 180_000);

		it.each(["protected", "production"] as const)("switches and restores the %s Agent writer with shared replay and verified hosted boundaries", async (scope) => {
			const production = scope === "production";
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
					"Agent restart requires the isolated local PostgreSQL fixture.",
				);
			const admin = new Pool({ connectionString: base.href, max: 1 });
			const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
			const databaseURL = new URL(`/${name}`, base).href;
			let created = false;
			let database: Pool | undefined;
			let service: Awaited<ReturnType<typeof openProcess>> | undefined;
			try {
				await admin.query(`CREATE DATABASE "${name}"`);
				created = true;
				const seeded = await seed(databaseURL, !production);
				database = new Pool({ connectionString: databaseURL, max: 2 });
				const productionProject = (project: Project): Project =>
					production ? { ...project, environment: "production", projectEngineFenced: true } : project;
				const alpha = productionProject(seeded.alpha);
				const beta = productionProject(seeded.beta);
				const writer = createProjectEngineWriterLease({
					database,
					project: alpha,
					selectedProjectId: alpha.id,
				});
				const schema = `"${alpha.schemaName}"`;
				const direct = `/api/projects/${alpha.slug}/auth`;
				const outside = `/api/projects/${beta.slug}/auth`;
				const hosted = "/api/auth";
				const host = `${alpha.slug}-accounts.allauth.co`;
				const directIssuer = `${platformOrigin}${direct}`;
				const hostedIssuer = `https://${host}${hosted}`;
				const proxy = { proxy: alpha, origin: alpha.primaryOrigin };
				const [hostKey, agentKey] = await Promise.all([
					generateKeyPair("EdDSA", { extractable: true }),
					generateKeyPair("EdDSA", { extractable: true }),
				]);
				const kid = "runtime-native-agent-host";
				const publicKey = { ...(await exportJWK(hostKey.publicKey)), kid };
				const siblingApproval = issueAgentReplayDrainEvidence(
					platformSecret, beta.id, 0, "fixture-sibling-bridge", Date.now() - 120_000,
				);
				function productionAgentEnvironment(
					approval: string | undefined,
					bridgeId: string | null,
					preparedRevision?: string,
				): Record<string, string> {
					return {
						[productionAgentReplayBridgeIdsSetting]: bridgeId ?? "",
						[productionAgentReplayApprovalsSetting]: JSON.stringify({
							[beta.id]: JSON.parse(siblingApproval),
							...(approval ? { [alpha.id]: JSON.parse(approval) } : {}),
						}),
						[productionProjectEngineRevisionsSetting]: preparedRevision === undefined
							? ""
							: JSON.stringify({ [alpha.id]: Number(preparedRevision) }),
					};
				}
				const start = (agentReplayApproval?: string, agentBridgeId = alpha.id) =>
					production
						? openProcess(databaseURL, alpha, { legacyAgentBridgeOnly: true }, alpha.slug, undefined, undefined,
							productionAgentEnvironment(agentReplayApproval, agentBridgeId, agentReplayApproval ? "0" : undefined))
						: openProcess(databaseURL, alpha, { agentReplayApproval, agentBridgeId });
				async function writerCommand(
					args: string[],
					approval?: string,
					revision = "0",
					bridgeId: string | null = alpha.id,
					candidateId: string | null = alpha.id,
				) {
					const { stdout } = await promisify(execFile)(
						process.execPath,
						["scripts/project-engine-writer.mjs", ...(production ? ["--project", alpha.id] : []), ...args],
						{
							cwd: appRoot,
							env: {
								...childEnvironment(),
								DATABASE_URL: databaseURL,
								...(production
									? productionAgentEnvironment(approval, bridgeId, args[0] === "switch" ? revision : undefined)
									: {
										ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: candidateId ?? "",
										ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION: revision,
										[agentReplayApprovalSetting]: approval ?? "",
										[agentReplayBridgeIdSetting]: bridgeId ?? "",
									}),
							},
						},
					);
					return stdout.trim();
				}
				const evidenceRequest = [
					"agent-replay-evidence",
					"fixture-bridge",
					new Date(Date.now() - 120_000).toISOString(),
				];
				if (production) {
					await database.query(`UPDATE public."allauthProject" SET environment='production' WHERE id=ANY($1::text[])`, [[alpha.id, beta.id]]);
					await expect(writerCommand(evidenceRequest)).rejects.toThrow("requires the registered production legacy writer");
					service = await start();
					expect((await service.request("/api/health")).status).toBe(503);
					await service.stop();
					service = undefined;
					for (const project of [alpha, beta])
						await database.query("SELECT public.allauth_register_project_engine_production($1,$2)", [project.id, project.workspaceId]);
				}
				service = await openProcess(databaseURL, alpha, false);
				expect(await writer.read()).toEqual({ writer: "legacy", revision: 0 });
				const login = await service.request(`${hosted}/sign-in/email`, {
					host,
					body: {
						email: credentials.project.email,
						password: credentials.password,
					},
				});
				expect(login.status).toBe(200);
				const browser = { host, cookie: cookie(login) };
				const creation = await service.request(`${hosted}/host/create`, {
					...browser,
					body: { name: "Native Agent host" },
				});
				expect(creation.status).toBe(200);
				const pending = (await creation.json()) as {
					hostId: string;
					enrollmentToken: string;
				};
				expect(pending).toMatchObject({
					hostId: expect.any(String),
					enrollmentToken: expect.any(String),
					status: "pending_enrollment",
				});
				const detail = `${hosted}/host/get?host_id=${encodeURIComponent(pending.hostId)}`;
				const nativeDetail = await service.request(detail, browser);
				expect(nativeDetail.status).toBe(200);
				let before = await nativeDetail.json();
				const [previousKeys, previousAgentKeys, pendingAgentKeys] =
					await Promise.all([
						generateKeyPair("EdDSA", { extractable: true }),
						generateKeyPair("EdDSA", { extractable: true }),
						generateKeyPair("EdDSA", { extractable: true }),
					]);
				const previousHost = await service.request(`${hosted}/host/create`, {
					...browser,
					body: {
						name: "Previously active host",
						public_key: { ...(await exportJWK(previousKeys.publicKey)), kid: "native-previous-fixture-host" },
					},
				});
				expect(previousHost.status).toBe(200);
				const { hostId: previousHostId } = (await previousHost.json()) as {
					hostId: string;
				};
				const previousRegistration = await new SignJWT({
					agent_public_key: await exportJWK(previousAgentKeys.publicKey),
				})
					.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
					.setIssuer(previousHostId)
					.setAudience(directIssuer)
					.setIssuedAt()
					.setExpirationTime("45s")
					.setJti(randomUUID())
					.sign(previousKeys.privateKey);
				const priorAgent = await service.request(`${direct}/agent/register`, {
					...proxy,
					authorization: `Bearer ${previousRegistration}`,
					body: { name: "Agent from native", mode: "delegated" },
				});
				expect(priorAgent.status).toBe(200);
				const { agent_id: previousAgentId } = (await priorAgent.json()) as {
					agent_id: string;
				};
				const pendingRegistration = await new SignJWT({
					agent_public_key: await exportJWK(pendingAgentKeys.publicKey),
				})
					.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
					.setIssuer(previousHostId)
					.setAudience(directIssuer)
					.setIssuedAt()
					.setExpirationTime("45s")
					.setJti(randomUUID())
					.sign(previousKeys.privateKey);
				const pendingAgent = await service.request(`${direct}/agent/register`, {
					...proxy,
					authorization: `Bearer ${pendingRegistration}`,
					body: {
						name: "Native Agent pending owner approval",
						mode: "delegated",
						force_approval: true,
					},
				});
				expect(pendingAgent.status).toBe(200);
				const pendingDevice = (await pendingAgent.json()) as {
					agent_id: string;
					approval: { device_code: string; user_code: string };
				};
				const beforeBridge = await service.request(`${direct}/agent/status`, {
					...proxy, authorization: await signAgentProof(previousHostId, previousAgentId, previousAgentKeys.privateKey),
				});
				expect(beforeBridge.status).toBe(200);
				async function agentReplayRows(project: Project) {
					const result = await database!.query(`SELECT count(*)::int AS count FROM "${project.schemaName}"."verification" WHERE identifier LIKE 'agent-status-jti:%'`);
					return result.rows[0]?.count;
				}
				expect(await agentReplayRows(alpha)).toBe(0);
				await service.stop();
				service = undefined;
				service = production
					? await start()
					: await openProcess(databaseURL, alpha, { agentBridgeId: alpha.id, legacyAgentBridgeOnly: true });
				expect((await service.request("/api/health")).status).toBe(200);
				expect(await writer.read()).toEqual({ writer: "legacy", revision: 0 });
				const siblingHostId = randomUUID();
				const siblingAgentId = randomUUID();
				const siblingKeys = await generateKeyPair("EdDSA", { extractable: true });
				const siblingKey = JSON.stringify(await exportJWK(siblingKeys.publicKey));
				await database.query(`INSERT INTO "${beta.schemaName}"."agentHost" (id,"userId","publicKey",status,"createdAt","updatedAt") VALUES ($1,$2,$3,'active',now(),now())`, [siblingHostId, credentials.project.id, siblingKey]);
				await database.query(`INSERT INTO "${beta.schemaName}"."agent" (id,name,"userId","hostId",status,mode,"publicKey","createdAt","updatedAt","activatedAt","expiresAt") VALUES ($1,'Sibling Agent',$2,$3,'active','delegated',$4,now(),now(),now(),now()+interval '15 minutes')`, [siblingAgentId, credentials.project.id, siblingHostId, siblingKey]);
				const siblingProof = await new SignJWT({})
					.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" }).setIssuer(siblingHostId).setSubject(siblingAgentId)
					.setAudience(`${platformOrigin}${outside}`).setIssuedAt().setExpirationTime("45s").setJti(randomUUID()).sign(siblingKeys.privateKey);
				const siblingStatus = await service.request(`${outside}/agent/status`, { proxy: beta, origin: beta.primaryOrigin, authorization: `Bearer ${siblingProof}` });
				expect(siblingStatus.status).toBe(200);
				expect(await agentReplayRows(beta)).toBe(0);
				const [nativeRotationKey, ownedRotationKey, unusedRotationKey] =
					await Promise.all([
						generateKeyPair("EdDSA", { extractable: true }),
						generateKeyPair("EdDSA", { extractable: true }),
						generateKeyPair("EdDSA", { extractable: true }),
					]);
				async function rotationProof() {
					return `Bearer ${await new SignJWT({})
						.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
						.setIssuer(previousHostId)
						.setAudience(directIssuer)
						.setIssuedAt()
						.setExpirationTime("45s")
						.setJti(randomUUID())
						.sign(previousKeys.privateKey)}`;
				}
				const nativeRotationProof = await rotationProof();
				const nativeRotated = await service.request(
					`${direct}/agent/rotate-key`,
					{
						...proxy,
						authorization: nativeRotationProof,
						body: {
							agent_id: previousAgentId,
							public_key: await exportJWK(nativeRotationKey.publicKey),
						},
					},
				);
				expect(nativeRotated.status, await nativeRotated.text()).toBe(200);
				const bridgedRegistration = await new SignJWT({ agent_public_key: await exportJWK(previousAgentKeys.publicKey) })
					.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt" })
					.setIssuer(previousHostId).setAudience(directIssuer).setIssuedAt().setExpirationTime("45s").setJti(randomUUID())
					.sign(previousKeys.privateKey);
				const bridged = await service.request(`${direct}/agent/register`, {
					...proxy, authorization: `Bearer ${bridgedRegistration}`,
					body: { name: "Agent from the bridged native writer", mode: "delegated" },
				});
				expect(bridged.status).toBe(200);
				async function signAgentProof(
					hostId: string,
					agentId: string,
					key: typeof agentKey.privateKey,
				) {
					return `Bearer ${await new SignJWT({ htm: "GET" })
						.setProtectedHeader({ alg: "EdDSA", typ: "agent+jwt" })
						.setIssuer(hostId)
						.setSubject(agentId)
						.setAudience([directIssuer, hostedIssuer])
						.setIssuedAt()
						.setExpirationTime("45s")
						.setJti(randomUUID())
						.sign(key)}`;
				}
				const usedByNative = await signAgentProof(
					previousHostId,
					previousAgentId,
					nativeRotationKey.privateKey,
				);
				await database.query(`CREATE FUNCTION ${schema}.deny_fixture_agent_replay() RETURNS trigger LANGUAGE plpgsql AS $$
				 BEGIN RAISE EXCEPTION 'Fixture Agent replay unavailable'; END; $$;
				 CREATE TRIGGER deny_fixture_agent_replay BEFORE INSERT ON ${schema}."verification" FOR EACH ROW
				 WHEN (NEW.identifier LIKE 'agent-status-jti:%') EXECUTE FUNCTION ${schema}.deny_fixture_agent_replay()`);
				try {
					const unavailable = await service.request(`${direct}/agent/status`, {
						...proxy,
						authorization: usedByNative,
					});
					expect(unavailable.status).toBeGreaterThanOrEqual(500);
				} finally {
					await database.query(
						`DROP TRIGGER deny_fixture_agent_replay ON ${schema}."verification"; DROP FUNCTION ${schema}.deny_fixture_agent_replay()`,
					);
				}
				const nativeWriter = service;
				const nativeReads = await Promise.all(
					[0, 1].map(() =>
						nativeWriter.request(`${direct}/agent/status`, {
							...proxy,
							authorization: usedByNative,
						}),
					),
				);
				expect(nativeReads.map((result) => result.status).sort()).toEqual([
					200, 401,
				]);
				expect(await agentReplayRows(alpha)).toBe(1);
				await database.query(
					`UPDATE ${schema}."agent" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
					[previousAgentId],
				);
				expect((await service.request("/api/health")).status).toBe(200);
				if (!production)
					await expect(writerCommand(["switch", "legacy", "0", "allauth"], undefined, "0", null)).rejects.toThrow("Agent replay bridge is unavailable");
				await expect(
					writerCommand(["switch", "legacy", "0", "allauth"]),
				).rejects.toThrow(production
					? "Stored Agent state requires production replay approval before activation."
					: "Agent replay drain evidence is unavailable");
				if (production)
					await expect(writerCommand(["switch", "legacy", "0", "allauth"], siblingApproval)).rejects.toThrow("Agent replay drain evidence is unavailable");
				await expect(
					writerCommand([
						"agent-replay-evidence",
						"fixture-bridge",
						new Date().toISOString(),
					]),
				).rejects.toThrow("Agent replay drain evidence is unavailable");
				await expect(writerCommand(evidenceRequest, undefined, "0", null)).rejects.toThrow(production
					? "Agent replay bridge is unavailable"
					: "exact protected Agent replay bridge ID");
				await expect(writerCommand(evidenceRequest, undefined, "0", beta.id)).rejects.toThrow("Agent replay bridge is unavailable");
				const approval = await writerCommand(evidenceRequest, undefined, "0", alpha.id, null);
				await expect(writerCommand(["switch", "legacy", "0", "allauth"], approval, "0", beta.id)).rejects.toThrow("Agent replay bridge is unavailable");
				const oldObservation = Date.now() - 16 * 60_000;
				const staleApproval = issueAgentReplayDrainEvidence(
					platformSecret,
					alpha.id,
					0,
					"fixture-bridge",
					oldObservation - 120_000,
					oldObservation,
				);
				await expect(
					writerCommand(["switch", "legacy", "0", "allauth"], staleApproval),
				).rejects.toThrow("Agent replay drain evidence is unavailable");
				expect(
					verifyAgentReplayDrainEvidence(
						staleApproval,
						platformSecret,
						alpha.id,
						0,
						Date.now(),
						"active",
					),
				).toBe(true);
				const tampered = approval.replace(
					"fixture-bridge",
					"different-deployment",
				);
				await expect(
					writerCommand(["switch", "legacy", "0", "allauth"], tampered),
				).rejects.toThrow("Agent replay drain evidence is unavailable");
				await service.stop();
				service = undefined;
				service = await start(approval, beta.id);
				expect((await service.request("/api/health")).status).toBe(503);
				await service.stop();
				service = undefined;
				service = await start(approval);
				await database.query(
					`UPDATE ${schema}."agentHost" SET "defaultCapabilities"='["unsupported"]' WHERE id=$1`,
					[pending.hostId],
				);
				expect((await service.request("/api/health")).status).toBe(503);
				if (production)
					await expect(writerCommand(evidenceRequest)).rejects.toThrow("stored Agent Auth outside the candidate scope");
				expect(await writer.read()).toEqual({ writer: "legacy", revision: 0 });
				await database.query(
					`UPDATE ${schema}."agentHost" SET "defaultCapabilities"='[]' WHERE id=$1`,
					[pending.hostId],
				);
				const incompatibleApproval = randomUUID();
				await database.query(
					`INSERT INTO ${schema}."approvalRequest" (id,method,"hostId","userId",status,"deliveryMode",interval,"expiresAt","createdAt","updatedAt")
					 VALUES ($1,'ciba',$2,$3,'pending','push',5,now()+interval '5 minutes',now(),now())`,
					[incompatibleApproval, previousHostId, credentials.project.id],
				);
				expect((await service.request("/api/health")).status).toBe(503);
				await database.query(
					`DELETE FROM ${schema}."approvalRequest" WHERE id=$1`,
					[incompatibleApproval],
				);
				const preparing = service;
				await expect
					.poll(async () => {
						const result = await preparing.request("/api/health");
						return { status: result.status, body: await result.json() };
					})
					.toEqual({ status: 200, body: { status: "ok" } });
				const conflictingHost = await service.request(`${hosted}/host/update`, {
					...browser, body: { host_id: pending.hostId, public_key: { ...publicKey, kid: "native-previous-fixture-host" } },
				});
				expect(conflictingHost.status).toBe(200);
				await expect(writerCommand(["switch", "legacy", "0", "allauth"], approval)).rejects.toThrow("stored Agent Auth outside the candidate scope");
				expect(await writer.read()).toEqual({ writer: "legacy", revision: 0 });
				const repairedHost = await service.request(`${hosted}/host/update`, {
					...browser, body: { host_id: pending.hostId, public_key: publicKey },
				});
				expect(repairedHost.status).toBe(200);
				before = await (await service.request(detail, browser)).json();
				expect(
					JSON.parse(
						await writerCommand(["switch", "legacy", "0", "allauth"], approval),
					),
				).toEqual({ writer: "allauth", revision: 1 });
				if (production) {
					const unrelatedStatus = await service.request(`${outside}/agent/status`, {
						proxy: beta, origin: beta.primaryOrigin, authorization: `Bearer ${siblingProof}`,
					});
					expect(unrelatedStatus.status).toBe(200);
					expect(await agentReplayRows(beta)).toBe(0);
				}
				await expect(
					database.query(
						`UPDATE ${schema}."verification" SET value=value WHERE false`,
					),
				).rejects.toMatchObject({ code: "55000" });
				const nativeReplay = await service.request(`${direct}/agent/status`, {
					...proxy,
					authorization: usedByNative,
				});
				expect(nativeReplay.status).toBe(401);
				expect(await nativeReplay.json()).toMatchObject({
					error: "jti_replay",
				});
				const renewal = await service.request(`${direct}/agent/status`, {
					...proxy,
					authorization: await signAgentProof(
						previousHostId,
						previousAgentId,
						nativeRotationKey.privateKey,
					),
				});
				expect(renewal.status).toBe(200);
				expect(await renewal.json()).toMatchObject({
					agent_id: previousAgentId,
					host_id: previousHostId,
					status: "active",
				});
				const priorRegistrationReplay = await service.request(
					`${direct}/agent/register`,
					{
						...proxy,
						authorization: `Bearer ${bridgedRegistration}`,
						body: { name: "Agent from native", mode: "delegated" },
					},
				);
				expect(priorRegistrationReplay.status).toBe(401);
				expect(await priorRegistrationReplay.json()).toMatchObject({
					error: "jti_replay",
				});
				const approved = await service.request(
					`${hosted}/agent/approve-capability`,
					{
						...browser,
						body: {
							approval_id: pendingDevice.approval.device_code,
							user_code: pendingDevice.approval.user_code,
							action: "approve",
						},
					},
				);
				expect(approved.status).toBe(200);
				expect(await approved.json()).toMatchObject({
					status: "approved",
					agentId: pendingDevice.agent_id,
				});
				const nativeRotationReplay = await service.request(
					`${direct}/agent/rotate-key`,
					{
						...proxy,
						authorization: nativeRotationProof,
						body: {
							agent_id: previousAgentId,
							public_key: await exportJWK(unusedRotationKey.publicKey),
						},
					},
				);
				expect(nativeRotationReplay.status).toBe(401);
				expect(await nativeRotationReplay.json()).toMatchObject({
					error: "jti_replay",
				});
				const ownedRotationProof = await rotationProof();
				const ownedRotated = await service.request(
					`${direct}/agent/rotate-key`,
					{
						...proxy,
						authorization: ownedRotationProof,
						body: {
							agent_id: pendingDevice.agent_id,
							public_key: await exportJWK(ownedRotationKey.publicKey),
						},
					},
				);
				expect(ownedRotated.status).toBe(200);

				const stored = await service.request(detail, browser);
				expect(stored.status).toBe(200);
				expect(await stored.json()).toEqual(before);
				const enrollment = {
					token: pending.enrollmentToken,
					public_key: publicKey,
				};
				const sibling = await service.request(`${outside}/host/enroll`, {
					proxy: beta,
					origin: beta.primaryOrigin,
					body: enrollment,
				});
				expect(sibling.status).toBe(401);
				const enrolled = await service.request(`${direct}/host/enroll`, {
					...proxy,
					body: enrollment,
				});
				expect(enrolled.status).toBe(200);
				expect(await enrolled.json()).toMatchObject({
					hostId: pending.hostId,
					status: "active",
					default_capabilities: [],
				});

				const signedHost = await new SignJWT({
					agent_public_key: await exportJWK(agentKey.publicKey),
				})
					.setProtectedHeader({ alg: "EdDSA", typ: "host+jwt", kid })
					.setIssuer(pending.hostId)
					.setAudience(directIssuer)
					.setIssuedAt()
					.setExpirationTime("45s")
					.setJti(randomUUID())
					.sign(hostKey.privateKey);
				const registration = await service.request(`${direct}/agent/register`, {
					...proxy,
					authorization: `Bearer ${signedHost}`,
					body: { name: "Restarted delegated Agent", mode: "delegated" },
				});
				expect(registration.status).toBe(200);
				const registered = (await registration.json()) as { agent_id: string };
				expect(registered).toMatchObject({
					agent_id: expect.any(String),
					host_id: pending.hostId,
					status: "active",
					agent_capability_grants: [],
				});
				const agentBearer = () =>
					signAgentProof(
						pending.hostId,
						registered.agent_id,
						agentKey.privateKey,
					);
				const ciba = await service.request(`${direct}/agent/ciba/authorize`, {
					...proxy,
					authorization: `Bearer ${signedHost}`,
					body: { login_hint: credentials.project.email },
				});
				expect(ciba.status).toBe(200);
				const { auth_req_id: receipt } = (await ciba.json()) as {
					auth_req_id: string;
				};
				const authority = {
					agent_id: registered.agent_id,
					host_id: pending.hostId,
					user_id: credentials.project.id,
					status: "active",
					mode: "delegated",
					agent_capability_grants: [],
				};
				async function expectDirectAgent(
					writer: NonNullable<typeof service>,
					authorization: string,
				) {
					const viaGateway = await writer.request(`${hosted}/agent/status`, {
						host,
						authorization,
					});
					expect(viaGateway.status).toBe(401);
					expect(await viaGateway.json()).toEqual({
						error: "unauthorized",
						message: "Authentication required",
					});
					const viaProject = await writer.request(`${direct}/agent/status`, {
						...proxy,
						authorization,
					});
					expect(viaProject.status).toBe(200);
					expect(await viaProject.json()).toMatchObject(authority);
				}
				const previousBearer = await agentBearer();
				await expectDirectAgent(service, previousBearer);
				const updatedName = "Agent host updated by AllAuth";
				const update = await service.request(`${hosted}/host/update`, {
					...browser,
					body: { host_id: pending.hostId, name: updatedName },
				});
				expect(update.status).toBe(200);
				await service.stop();
				service = undefined;

				service = await start(approval);
				expect((await service.request("/api/health")).status).toBe(200);
				const replay = await service.request(`${direct}/agent/status`, {
					...proxy,
					authorization: previousBearer,
				});
				expect(replay.status).toBe(401);
				expect(await replay.json()).toMatchObject({ error: "jti_replay" });
				await service.stop();
				service = undefined;
				await expect(writerCommand(["switch", "allauth", "1", "legacy"], approval, "0", null)).rejects.toThrow("Agent replay bridge is unavailable");
				expect(await writer.read()).toEqual({ writer: "allauth", revision: 1 });

				expect(
					JSON.parse(
						await writerCommand(["switch", "allauth", "1", "legacy"], approval),
					),
				).toEqual({ writer: "legacy", revision: 2 });
				await expect(
					writerCommand(["switch", "legacy", "2", "allauth"], approval, "2"),
				).rejects.toThrow("Agent replay drain evidence is unavailable");
				service = await start();
				const rolledBack = await service.request(detail, browser);
				expect(rolledBack.status).toBe(200);
				expect(await rolledBack.json()).toMatchObject({
					id: pending.hostId,
					name: updatedName,
					status: "active",
				});
				await expectDirectAgent(service, await agentBearer());
				const ownedReplay = await service.request(`${direct}/agent/status`, {
					...proxy,
					authorization: previousBearer,
				});
				expect(ownedReplay.status).toBe(401);
				expect(await ownedReplay.json()).toMatchObject({ error: "jti_replay" });
				const priorReceipt = await service.request(
					`${hosted}/agent/ciba/pending`,
					browser,
				);
				expect(priorReceipt.status).toBe(200);
				expect(await priorReceipt.json()).toMatchObject({
					requests: [{ approval_id: receipt, method: "ciba", agent_id: null }],
				});
				const ownedRegistrationReplay = await service.request(
					`${direct}/agent/register`,
					{
						...proxy,
						authorization: `Bearer ${signedHost}`,
						body: { name: "Restarted delegated Agent", mode: "delegated" },
					},
				);
				expect(ownedRegistrationReplay.status).toBe(401);
				expect(await ownedRegistrationReplay.json()).toMatchObject({
					error: "jti_replay",
				});
				const nativeRotationDenied = await service.request(
					`${direct}/agent/rotate-key`,
					{
						...proxy,
						authorization: ownedRotationProof,
						body: {
							agent_id: pendingDevice.agent_id,
							public_key: await exportJWK(unusedRotationKey.publicKey),
						},
					},
				);
				expect(nativeRotationDenied.status).toBe(401);
				expect(await nativeRotationDenied.json()).toMatchObject({
					error: "jti_replay",
				});
				const sameRotation = await service.request(
					`${direct}/agent/rotate-key`,
					{
						...proxy,
						authorization: ownedRotationProof,
						body: {
							agent_id: pendingDevice.agent_id,
							public_key: await exportJWK(ownedRotationKey.publicKey),
						},
					},
				);
				expect(sameRotation.status).toBe(200);
				const spent = await service.request(`${direct}/host/enroll`, {
					...proxy,
					body: enrollment,
				});
				expect(spent.status).toBe(401);
				expect(await spent.json()).toMatchObject({
					error: "enrollment_token_invalid",
				});
			} catch (error) {
				await service?.stop().catch(() => undefined);
				service = undefined;
				throw error;
			} finally {
				try {
					await service?.stop();
				} finally {
					try {
						await database?.end();
						if (created) await dropClosedFixtureDatabase(admin, name);
					} finally {
						await admin.end();
					}
				}
			}
		}, 180_000);
	},
);
