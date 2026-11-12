import { execFile, fork } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { JSONWebKeySet } from "jose";
import { createLocalJWKSet, jwtVerify } from "jose";
import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { clerkCompatiblePasswords } from "../clerk-password";
import { defaultSecurityPolicy } from "../control/security-policy";
import type { ControlPrincipal } from "../control/types";
import { signEdgeRequest } from "../domains/edge";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { createWorkspace } from "../workspaces/repository";
import type { ProjectRuntimeFixtureBoot } from "./owned-project-runtime-fixture";
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
const oauthClientId = "runtime-issuer-fixture-client";
const oauthRedirectURI = "https://rp.runtime.fixture.example/callback";
const credentials = {
	platform: { id: "fixture-owner", email: "owner@runtime.fixture.example" },
	project: {
		id: "fixture-project-account",
		email: "account@runtime.fixture.example",
	},
	password: "Fixture-native-password-92!",
	updated: "Fixture-rotated-password-73!",
};

function childEnvironment(): NodeJS.ProcessEnv {
	return {
		PATH: process.env.PATH,
		NODE_ENV: "test",
		AUTH_RUNTIME: "node",
		ALLAUTH_AUTH_URL: platformOrigin,
		ALLAUTH_AUTH_SECRET: platformSecret,
		BETTER_AUTH_URL: platformOrigin,
		BETTER_AUTH_SECRET: platformSecret,
		TRUSTED_ORIGINS: "",
		EMAIL_FROM: "",
		SCIM_CREDENTIAL_HASH_SECRET:
			"disposable-project-runtime-fixture-credential-hash-key",
		ALLAUTH_EDGE_SECRET: edgeSecret,
		CLOUDFLARE_SAAS_READY: "true",
		ALLAUTH_HOSTING_BASE_DOMAIN: "allauth.co",
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
) {
	const child = fork(worker, [], {
		cwd: appRoot,
		env: childEnvironment(),
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
				} = {},
			) {
				const origin = options.host
					? `https://${options.host}`
					: platformOrigin;
				const headers = new Headers({ origin: options.origin ?? origin });
				if (options.cookie) headers.set("cookie", options.cookie);
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
				const method = body === undefined ? "GET" : "POST";
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

async function issueFixtureTokens(
	service: Awaited<ReturnType<typeof openProcess>>,
	transport: { prefix: string; issuer: string; host?: string; cookie: string },
) {
	const verifier = "runtime-restart-fixture-project-issuer-proof-verifier";
	const state = randomUUID();
	const query = new URLSearchParams({
		response_type: "code",
		client_id: oauthClientId,
		redirect_uri: oauthRedirectURI,
		scope: "openid profile",
		state,
		code_challenge_method: "S256",
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
	});
	const authorization = await service.request(
		`${transport.prefix}/oauth2/authorize?${query}`,
		transport,
	);
	const location =
		authorization.headers.get("location") ??
		((await authorization.json()) as { url?: string }).url;
	expect(location).toBeTruthy();
	const callback = new URL(location!);
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
			code_verifier: verifier,
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
		async function provision(slug: string) {
			const project = await provisionProject(
				{
					name: slug,
					slug,
					primaryOrigin: `https://${slug}.runtime.fixture.example`,
					origins: [],
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
		return {
			alpha: await provision("runtime-owned-fixture"),
			beta: await provision("runtime-control-fixture"),
		};
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
				const { alpha, beta } = await seed(url(source));
				const alphaPath = `/api/projects/${alpha.slug}/auth`;
				const betaPath = `/api/projects/${beta.slug}/auth`;
				const alphaHost = `${alpha.slug}-accounts.allauth.co`;
				const directIssuer = `${platformOrigin}${alphaPath}`;
				const hostedIssuer = `https://${alphaHost}/api/auth`;
				const betaHost = `${beta.slug}-accounts.allauth.co`;
				const login = {
					email: credentials.project.email,
					password: credentials.password,
				};
				const management = (project: Project) =>
					`/api/admin/organizations?project=${project.slug}`;
				service = await openProcess(url(source), alpha, false);
				expect((await service.request("/api/health")).status).toBe(200);
				const rootLogin = await service.request("/api/auth/sign-in/email", {
					body: {
						email: credentials.platform.email,
						password: credentials.password,
					},
				});
				expect(rootLogin.status).toBe(200);
				const rootCookie = cookie(rootLogin);
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
				expect(
					(await service.request(management(alpha), { cookie: rootCookie }))
						.status,
				).toBe(200);
				await service.stop();
				service = undefined;
				await admin.query(`CREATE DATABASE "${restored}" TEMPLATE "${source}"`);
				created.push(restored);

				service = await openProcess(url(restored), alpha, true);
				expect((await service.request("/api/health")).status).toBe(200);
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
				).toMatchObject({ user: { id: credentials.project.id } });
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
					apiKeys: false,
					enterpriseSSO: false,
					scim: false,
					signUpEnabled: true,
				});
				const legacyConfig = await service.request("/api/config", {
					host: betaHost,
				});
				expect(legacyConfig.status).toBe(200);
				expect(await legacyConfig.json()).toMatchObject({
					apiKeys: true,
					enterpriseSSO: true,
					scim: true,
				});
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
					},
				});
				expect(
					registration.status,
					registration.ok ? undefined : await registration.clone().text(),
				).toBe(200);
				const verificationURL = await vi.waitFor(() => {
					const verification = service!.mail.find(
						({ to }) => to === signupEmail,
					);
					expect(verification?.subject).toContain("Verify your");
					const match = verification?.text.match(
						/https:\/\/[^\s<>\]]+\/verify-email\?[^\s<>\]]+/,
					);
					expect(match?.[0]).toBeTruthy();
					return new URL(match![0]);
				});
				expect(verificationURL.origin).toBe(`https://${alphaHost}`);
				const verified = await service.request(
					verificationURL.pathname + verificationURL.search,
					{ host: alphaHost },
				);
				expect(verified.status).toBe(302);
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

				service = await openProcess(url(restored), alpha, false);
				expect((await service.request("/api/health")).status).toBe(200);
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
				).toMatchObject({ user: { id: credentials.project.id } });
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
				expect(await catalog.json()).toMatchObject({ organizations: [] });
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
				const changed = new Pool({ connectionString: url(restored), max: 1 });
				try {
					await changed.query(
						`UPDATE "${alpha.schemaName}"."oauthClient" SET "grantTypes" = '["client_credentials"]' WHERE "clientId" = $1`,
						[oauthClientId],
					);
				} finally {
					await changed.end();
				}
				await expect(openProcess(url(restored), alpha, true)).rejects.toThrow(
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
