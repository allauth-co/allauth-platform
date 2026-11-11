import { createHash, createHmac, randomBytes } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { admin } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAllAuthProxy } from "../../sdk/next";
import { createAuthOptions } from "../auth";
import { isPlatformAdmin } from "../configuration";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { projectManagement } from "./management-plugin";
import { projectProxySecret, verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import { handleProjectAuthentication } from "./session-introspection";

const origin = "https://allauth.example";
const appOrigin = "https://app.example";
const callbackUrl = `${appOrigin}/api/allauth/support/callback`;
const isolatedOrigin = "https://support.example";
const password = "support-fixture-password";
const opaque = () => randomBytes(32).toString("base64url");
const sha = (value: string) =>
	createHash("sha256").update(value).digest("base64url");
const cookie = (response: Response) =>
	response.headers
		.getSetCookie()
		.map((value) => value.split(";", 1)[0])
		.join("; ");

async function setup() {
	const environment = {
		BETTER_AUTH_SECRET:
			"support-transport-fixture-secret-longer-than-thirty-two",
	};
	const project: Project = {
		id: "project-a",
		slug: "fixture-app",
		name: "Fixture",
		schemaName: "allauth_project_0123456789abcdef0123456789abcdef",
		primaryOrigin: appOrigin,
		origins: [appOrigin, isolatedOrigin],
		workspaceId: "workspace-a",
		applicationId: "application-a",
		environment: "production",
		brokerClientId: "fixture",
		brokerSecret: "fixture",
		proxyVersion: "version-a",
		createdBy: "owner",
		createdAt: new Date(),
		updatedAt: new Date(),
	};
	let enabled = true;
	let applicationEnabled = false;
	let applicationCallbackOrigin = isolatedOrigin;
	const root = await getTestInstance(
		{
			baseURL: origin,
			advanced: { cookiePrefix: "platform" },
			plugins: [admin()],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	const rootContext = await root.auth.$context;
	const registered = await root.auth.api.signUpEmail({
		body: { email: "owner@fixture.example", name: "Owner", password },
	});
	await rootContext.adapter.update({
		model: "user",
		where: [{ field: "id", value: registered.user.id }],
		update: { role: "admin", emailVerified: true },
	});
	const login = await root.auth.api.signInEmail({
		body: { email: "owner@fixture.example", password },
		asResponse: true,
	});
	const rootCookie = cookie(login);
	const requirePlatformAdmin = async (ctx: GenericEndpointContext) => {
		const current = await runWithAdapter(rootContext.adapter, () =>
			root.auth.api.getSession({
				headers: ctx.headers || new Headers(),
				query: { disableCookieCache: true, disableRefresh: true },
			}),
		);
		if (!current || !isPlatformAdmin(current.user, current.session))
			throw new APIError("FORBIDDEN");
		return current as ControlPrincipal;
	};
	const authorizeStoredActor = async (principal: ControlPrincipal) => {
		const stored = await rootContext.adapter.findOne<{
			userId: string;
			expiresAt: Date;
			impersonatedBy?: string;
		}>({
			model: "session",
			where: [{ field: "id", value: principal.session.id }],
		});
		const user = await rootContext.adapter.findOne<{
			id: string;
			emailVerified: boolean;
			banned?: boolean;
			role?: string;
		}>({ model: "user", where: [{ field: "id", value: principal.user.id }] });
		if (
			!stored ||
			stored.userId !== principal.user.id ||
			stored.expiresAt <= new Date() ||
			!user ||
			!isPlatformAdmin(user, stored)
		)
			throw new APIError("FORBIDDEN");
	};
	const basePath = `/api/projects/${project.slug}/auth`;
	const productionHooks = createAuthOptions(undefined, {
		...environment,
		BETTER_AUTH_URL: origin,
		SCIM_CREDENTIAL_HASH_SECRET:
			"support-fixture-scim-secret-longer-than-thirty-two",
	}).hooks;
	const fixture = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			hooks: { before: productionHooks.before },
			advanced: { cookiePrefix: `allauth_project_${project.slug}` },
			trustedOrigins: [origin, appOrigin, isolatedOrigin],
			session: { cookieCache: { enabled: false } },
			user: {
				additionalFields: {
					directoryDisabled: { type: "boolean", required: false },
				},
			},
			plugins: [
				admin(),
				allauthControl(),
				projectManagement({
					projectId: project.id,
					baseURL: origin,
					requirePlatformAdmin,
					support: {
						projectId: project.id,
						projectSlug: project.slug,
						workspaceId: project.workspaceId,
						platformOrigin: origin,
						configuration: async () =>
							enabled
								? {
										callbackUrl: applicationEnabled
											? `${applicationCallbackOrigin}/api/allauth/support/callback`
											: callbackUrl,
										proxyVersion: project.proxyVersion,
										...(applicationEnabled
											? {
													applicationInitiated: {
														enabled: true,
														primaryOrigin: appOrigin,
														authorizeUrl: `${appOrigin}/api/admin/impersonation/authorize`,
														returnUrl: `${appOrigin}/admin`,
													},
												}
											: {}),
									}
								: null,
						requirePlatformAdmin,
						authorizeStoredActor,
						verifyProxy: async (request: Request) => {
							if (!request.headers.has("allauth-proxy-signature"))
								throw new APIError("FORBIDDEN");
							await verifiedProjectRequest(request, project, environment);
							return {
								origin: request.headers.get("allauth-proxy-origin")!,
								proxyVersion: project.proxyVersion,
							};
						},
					},
				}),
			],
			logger: { disabled: true },
		},
		{ disableTestUser: true },
	);
	const context = await fixture.auth.$context;
	const target = await fixture.auth.api.signUpEmail({
		body: { email: "target@fixture.example", name: "Target", password },
	});
	await context.adapter.update({
		model: "user",
		where: [{ field: "id", value: target.user.id }],
		update: { emailVerified: true },
	});
	const request = (
		path: string,
		body?: unknown,
		cookies = rootCookie,
		requestOrigin = origin,
		signed = false,
	) => {
		const url = `${origin}${basePath}${path}`;
		const bytes = body === undefined ? "" : JSON.stringify(body);
		const headers = new Headers({
			cookie: cookies,
			origin: requestOrigin,
			...(body === undefined ? {} : { "content-type": "application/json" }),
		});
		if (signed) {
			const timestamp = String(Math.floor(Date.now() / 1000));
			const parsed = new URL(url);
			const input = [
				timestamp,
				body === undefined ? "GET" : "POST",
				`${parsed.pathname}${parsed.search}`,
				requestOrigin,
				"",
				createHash("sha256").update(bytes).digest("hex"),
			].join("\n");
			headers.set("allauth-proxy-timestamp", timestamp);
			headers.set("allauth-proxy-origin", requestOrigin);
			headers.set("allauth-proxy-ip", "");
			headers.set(
				"allauth-proxy-signature",
				createHmac("sha256", projectProxySecret(project, environment))
					.update(input)
					.digest("hex"),
			);
		}
		return fixture.auth.handler(
			new Request(url, {
				method: body === undefined ? "GET" : "POST",
				headers,
				...(body === undefined ? {} : { body: bytes }),
			}),
		);
	};
	const impersonation = await request("/project-admin/impersonate-user", {
		userId: target.user.id,
	});
	if (impersonation.status !== 200)
		throw new Error("Fixture impersonation failed.");
	const supportCookie = cookie(impersonation);
	const support = (await impersonation.json()) as {
		session: { id: string; expiresAt: string };
	};
	const consoleCookie = `${rootCookie}; ${supportCookie}`;
	const launch = async () => {
		const response = await request(
			"/project-admin/support/launch",
			{},
			consoleCookie,
		);
		expect(response.status).toBe(200);
		const value = (await response.json()) as { url: string };
		return new URL(value.url).searchParams.get("launch")!;
	};
	const grant = async () => {
		const launchCode = await launch();
		const state = opaque();
		const codeVerifier = opaque();
		const response = await request(
			`/project-admin/support/authorize?${new URLSearchParams({ launch: launchCode, state, codeChallenge: sha(codeVerifier) })}`,
			undefined,
			consoleCookie,
		);
		expect(response.status).toBe(302);
		const destination = new URL(response.headers.get("location")!);
		expect(`${destination.origin}${destination.pathname}`).toBe(callbackUrl);
		expect(destination.searchParams.get("state")).toBe(state);
		return {
			code: destination.searchParams.get("code")!,
			state,
			codeVerifier,
			callbackUrl,
		};
	};
	return {
		root,
		rootContext,
		rootCookie,
		actorId: registered.user.id,
		context,
		fixture,
		project,
		environment,
		targetId: target.user.id,
		request,
		supportCookie,
		consoleCookie,
		support,
		launch,
		grant,
		disable: () => {
			enabled = false;
		},
		enableApplication: () => {
			applicationEnabled = true;
		},
		setApplicationCallbackOrigin: (value: string) => {
			applicationCallbackOrigin = value;
		},
	};
}

/** @see ../../INTEGRATION.md */
describe("explicit connected-app support handoff", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => {
		state = await setup();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});
	it("transfers the exact bounded native session using a one-use grant and returns no browser bearer credentials", async () => {
		const grant = await state.grant();
		const response = await state.request(
			"/sdk/support/exchange",
			grant,
			"",
			appOrigin,
			true,
		);
		expect(response.status).toBe(200);
		const data = await response.json();
		expect(data).toMatchObject({
			session: {
				id: state.support.session.id,
				expiresAt: state.support.session.expiresAt,
			},
			user: { id: state.targetId },
			actor: { id: state.actorId, email: "owner@fixture.example" },
			consoleReturnURL: expect.stringContaining("workspace=workspace-a"),
		});
		expect(JSON.stringify(data)).not.toMatch(/"token"|codeVerifier|private/);
		expect(
			response.headers
				.getSetCookie()
				.some((value) => value.includes(".dont_remember=")),
		).toBe(true);
		const current = await state.request(
			"/get-session?disableCookieCache=true&disableRefresh=true",
			undefined,
			cookie(response),
			appOrigin,
			true,
		);
		expect(await current.json()).toMatchObject({
			session: { id: state.support.session.id, impersonatedBy: state.actorId },
			user: { id: state.targetId },
		});
		expect(
			(await state.request("/sdk/support/exchange", grant, "", appOrigin, true))
				.status,
		).toBe(400);
	});
	it("requires real browser administrator and current actor-owned support cookies for launch", async () => {
		for (const cookies of [state.rootCookie, state.supportCookie, ""])
			expect(
				(await state.request("/project-admin/support/launch", {}, cookies))
					.status,
			).toBeGreaterThanOrEqual(400);
		expect(
			(
				await state.request(
					"/project-admin/support/launch",
					{},
					state.consoleCookie,
					appOrigin,
				)
			).status,
		).toBe(403);
		state.disable();
		expect(
			(
				await state.request(
					"/project-admin/support/launch",
					{},
					state.consoleCookie,
				)
			).status,
		).toBe(403);
	});
	it("does not authorize a forged, replayed or browser-unbound launch", async () => {
		const launch = await state.launch();
		const query = new URLSearchParams({
			launch,
			state: opaque(),
			codeChallenge: sha(opaque()),
		});
		expect(
			(
				await state.request(
					`/project-admin/support/authorize?${query}`,
					undefined,
					state.supportCookie,
				)
			).status,
		).toBe(403);
		const first = await state.request(
			`/project-admin/support/authorize?${query}`,
			undefined,
			state.consoleCookie,
		);
		expect(first.status).toBe(302);
		expect(
			(
				await state.request(
					`/project-admin/support/authorize?${query}`,
					undefined,
					state.consoleCookie,
				)
			).status,
		).toBe(400);
	});
	it.each([
		"codeVerifier",
		"state",
		"callbackUrl",
	] as const)("rejects a mismatched exchange %s before issuing cookies", async (field) => {
		const grant = await state.grant();
		const response = await state.request(
			"/sdk/support/exchange",
			{
				...grant,
				[field]:
					field === "callbackUrl"
						? `${appOrigin}/other/support/callback`
						: opaque(),
			},
			"",
			appOrigin,
			true,
		);
		expect(response.status).toBe(400);
		expect(response.headers.getSetCookie()).toEqual([]);
	});
	it("rejects unsigned, foreign-origin and revoked transport authorization", async () => {
		const grant = await state.grant();
		expect(
			(await state.request("/sdk/support/exchange", grant, "", appOrigin))
				.status,
		).toBe(403);
		expect(
			(
				await state.request(
					"/sdk/support/exchange",
					grant,
					"",
					"https://evil.example",
					true,
				)
			).status,
		).toBe(403);
		state.project.proxyVersion = "rotated";
		expect(
			(await state.request("/sdk/support/exchange", grant, "", appOrigin, true))
				.status,
		).toBe(403);
	});
	it.each([
		"actor",
		"target",
		"session",
		"registration",
	])("rechecks revoked %s authority at exchange", async (changed) => {
		const grant = await state.grant();
		if (changed === "actor")
			await state.rootContext.adapter.update({
				model: "user",
				where: [{ field: "id", value: state.actorId }],
				update: { role: "user" },
			});
		if (changed === "target")
			await state.context.adapter.update({
				model: "user",
				where: [{ field: "id", value: state.targetId }],
				update: { banned: true },
			});
		if (changed === "session")
			await state.context.adapter.update({
				model: "session",
				where: [{ field: "id", value: state.support.session.id }],
				update: { expiresAt: new Date(Date.now() - 1000) },
			});
		if (changed === "registration") state.disable();
		const response = await state.request(
			"/sdk/support/exchange",
			grant,
			"",
			appOrigin,
			true,
		);
		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.getSetCookie()).toEqual([]);
	});
	it("allows only one of concurrent code redeemers to receive the shared support session", async () => {
		const grant = await state.grant();
		const responses = await Promise.all([
			state.request("/sdk/support/exchange", grant, "", appOrigin, true),
			state.request("/sdk/support/exchange", grant, "", appOrigin, true),
		]);
		expect(responses.map((response) => response.status).sort()).toEqual([
			200, 400,
		]);
	});
	it("ends the shared support session from the app and preserves the real administrator", async () => {
		const exchange = await state.request(
			"/sdk/support/exchange",
			await state.grant(),
			"",
			appOrigin,
			true,
		);
		const appCookie = cookie(exchange);
		const status = await state.request(
			"/sdk/support/session",
			undefined,
			appCookie,
			appOrigin,
			true,
		);
		expect(await status.json()).toMatchObject({
			session: { id: state.support.session.id },
			actor: { id: state.actorId },
		});
		expect(
			(
				await state.request(
					"/sdk/support/stop",
					{},
					appCookie,
					"https://evil.example",
					true,
				)
			).status,
		).toBe(403);
		const stop = await state.request(
			"/sdk/support/stop",
			{},
			appCookie,
			appOrigin,
			true,
		);
		expect(stop.status).toBe(200);
		expect(await stop.json()).toMatchObject({
			success: true,
			consoleReturnURL: expect.stringContaining("workspace=workspace-a"),
		});
		expect(
			await (
				await state.request(
					"/get-session?disableRefresh=true",
					undefined,
					state.supportCookie,
				)
			).json(),
		).toBeNull();
		expect(
			(
				await state.root.auth.api.getSession({
					headers: new Headers({ cookie: state.rootCookie }),
				})
			)?.user.id,
		).toBe(state.actorId);
		expect(
			(await state.request("/sdk/support/stop", {}, appCookie, appOrigin, true))
				.status,
		).toBe(200);
	});
	it("never treats an ordinary app session as support or revokes it through support-stop", async () => {
		const login = await state.request(
			"/sign-in/email",
			{ email: "target@fixture.example", password },
			"",
			appOrigin,
			true,
		);
		const normalCookie = cookie(login);
		expect(
			await (
				await state.request(
					"/sdk/support/session",
					undefined,
					normalCookie,
					appOrigin,
					true,
				)
			).json(),
		).toBeNull();
		expect(
			(
				await state.request(
					"/sdk/support/stop",
					{},
					normalCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		expect(
			await (
				await state.request(
					"/get-session?disableRefresh=true",
					undefined,
					normalCookie,
					appOrigin,
					true,
				)
			).json(),
		).toMatchObject({ user: { id: state.targetId } });
	});
	it("rechecks connected actor authority before ordinary authenticated app mutations", async () => {
		const exchange = await state.request(
			"/sdk/support/exchange",
			await state.grant(),
			"",
			appOrigin,
			true,
		);
		await state.rootContext.adapter.update({
			model: "user",
			where: [{ field: "id", value: state.actorId }],
			update: { role: "user" },
		});
		const mutation = await state.request(
			"/update-user",
			{ name: "Unauthorized change" },
			cookie(exchange),
			appOrigin,
			true,
		);
		expect(mutation.status).toBe(401);
		expect(
			(await state.context.internalAdapter.findUserById(state.targetId))?.name,
		).toBe("Target");
		expect(
			await state.context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: state.support.session.id }],
			}),
		).toBeNull();
	});
	it("keeps support lifetime fixed even if the client omits its dont-remember cookie", async () => {
		const exchange = await state.request(
			"/sdk/support/exchange",
			await state.grant(),
			"",
			appOrigin,
			true,
		);
		const sessionOnly = cookie(exchange)
			.split("; ")
			.filter((value) => value.includes(".session_token="))
			.join("; ");
		const response = await state.request(
			"/get-session",
			undefined,
			sessionOnly,
			appOrigin,
			true,
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			session: {
				id: state.support.session.id,
				expiresAt: state.support.session.expiresAt,
			},
		});
	});
	it.each([
		false,
		true,
	])("does not refresh support in the production authorization hook before denying an admin request (connected=%s)", async (connected) => {
		const selectedCookie = connected
			? cookie(
					await state.request(
						"/sdk/support/exchange",
						await state.grant(),
						"",
						appOrigin,
						true,
					),
				)
			: state.supportCookie;
		const sessionOnly = selectedCookie
			.split("; ")
			.filter((value) => value.includes(".session_token="))
			.join("; ");
		expect(
			(
				await state.request(
					"/admin/list-users",
					undefined,
					sessionOnly,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		const stored = await state.context.adapter.findOne<{ expiresAt: Date }>({
			model: "session",
			where: [{ field: "id", value: state.support.session.id }],
		});
		expect(stored?.expiresAt.toISOString()).toBe(
			state.support.session.expiresAt,
		);
	});
	it.each([
		"end",
		"actor-demoted",
		"actor-logged-out",
	])("completes the real two-origin SDK flow and restores the ordinary session on the first stop after %s", async (reason) => {
		vi.stubGlobal(
			"fetch",
			(input: string | URL | Request, init?: RequestInit) =>
				state.fixture.auth.handler(new Request(input, init)),
		);
		const proxy = createAllAuthProxy({
			project: state.project.slug,
			proxySecret: projectProxySecret(state.project, state.environment),
			appOrigin,
			allauthURL: origin,
			supportAccess: { enabled: true },
		});
		const jar = new Map<string, string>();
		const receive = (response: Response) => {
			for (const value of response.headers.getSetCookie()) {
				const [pair] = value.split(";");
				const equals = pair!.indexOf("=");
				const name = pair!.slice(0, equals);
				if (/Max-Age=0(?:;|$)/i.test(value)) jar.delete(name);
				else jar.set(name, pair!.slice(equals + 1));
			}
		};
		const appRequest = async (endpoint: string, body?: unknown) => {
			const path = endpoint.split("?", 1)[0]!;
			const response = await proxy(
				new Request(`${appOrigin}/api/allauth/${endpoint}`, {
					method: body === undefined ? "GET" : "POST",
					headers: {
						cookie: [...jar]
							.map(([name, value]) => `${name}=${value}`)
							.join("; "),
						...(body === undefined
							? {}
							: { origin: appOrigin, "content-type": "application/json" }),
					},
					...(body === undefined ? {} : { body: JSON.stringify(body) }),
				}),
				{ params: Promise.resolve({ all: path.split("/") }) },
			);
			receive(response);
			return response;
		};
		expect(
			(
				await appRequest("sign-in/email", {
					email: "target@fixture.example",
					password,
				})
			).status,
		).toBe(200);
		const normal = (await (
			await appRequest("get-session?disableRefresh=true")
		).json()) as { session: { id: string } };
		expect(normal.session.id).not.toBe(state.support.session.id);
		const start = await appRequest(
			`support/start?launch=${await state.launch()}`,
		);
		expect(start.status).toBe(302);
		const authorization = await state.fixture.auth.handler(
			new Request(start.headers.get("location")!, {
				headers: { cookie: state.consoleCookie },
			}),
		);
		expect(authorization.status).toBe(302);
		const callback = new URL(authorization.headers.get("location")!);
		expect(`${callback.origin}${callback.pathname}`).toBe(callbackUrl);
		expect(
			(await appRequest(`support/callback${callback.search}`)).status,
		).toBe(303);
		expect(
			[...jar.keys()].some((name) => name.endsWith(".dont_remember")),
		).toBe(true);
		const support = await (await appRequest("get-session")).json();
		expect(support).toMatchObject({
			session: {
				id: state.support.session.id,
				impersonatedBy: state.actorId,
				expiresAt: state.support.session.expiresAt,
			},
		});
		expect(JSON.stringify(support)).not.toContain('"token"');
		expect(await (await appRequest("support/session")).json()).toMatchObject({
			support: {
				session: { id: state.support.session.id },
				actor: { id: state.actorId },
			},
			canRestore: true,
		});
		if (reason === "actor-demoted")
			await state.rootContext.adapter.update({
				model: "user",
				where: [{ field: "id", value: state.actorId }],
				update: { role: "user" },
			});
		if (reason === "actor-logged-out")
			await state.rootContext.internalAdapter.deleteUserSessions(state.actorId);
		expect(await (await appRequest("support/stop", {})).json()).toMatchObject({
			success: true,
			restored: true,
		});
		expect(await (await appRequest("get-session")).json()).toMatchObject({
			session: { id: normal.session.id, impersonatedBy: null },
		});
		expect(
			await (
				await state.request("/get-session", undefined, state.supportCookie)
			).json(),
		).toBeNull();
	});
});

/** @see ../../../docs/content/docs/integrations/allauth-support-sessions.mdx */
describe("isolated application-initiated native support", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	let actorCookie: string;
	let actorId: string;
	let actorSessionId: string;
	const input = () => ({
		actorSessionId,
		targetUserId: state.targetId,
		reason: "Investigate a reported company issue",
		applicationAuditId: "app-audit-1",
		context: { kind: "company", id: "company-1" },
	});
	beforeEach(async () => {
		state = await setup();
		const actor = await state.fixture.auth.api.signUpEmail({
			body: {
				email: "app-admin@fixture.example",
				name: "Application administrator",
				password,
			},
		});
		actorId = actor.user.id;
		await state.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: actorId }],
			update: { emailVerified: true },
		});
		actorCookie = cookie(
			await state.request(
				"/sign-in/email",
				{ email: "app-admin@fixture.example", password },
				"",
				appOrigin,
				true,
			),
		);
		const current = await state.request(
			"/get-session?disableRefresh=true",
			undefined,
			actorCookie,
			appOrigin,
			true,
		);
		actorSessionId = ((await current.json()) as { session: { id: string } })
			.session.id;
	});
	async function authorize() {
		state.enableApplication();
		const launch = await state.request(
			"/sdk/support/application/launch",
			input(),
			actorCookie,
			appOrigin,
			true,
		);
		expect(launch.status).toBe(200);
		const url = new URL(((await launch.json()) as { url: string }).url);
		expect(url.origin).toBe(isolatedOrigin);
		expect(url.pathname).toBe("/api/allauth/support/start");
		const stateCode = opaque();
		const codeVerifier = opaque();
		const query = {
			launch: url.searchParams.get("launch")!,
			state: stateCode,
			codeChallenge: sha(codeVerifier),
		};
		const redirect = await state.request(
			`/project-admin/support/authorize?${new URLSearchParams(query)}`,
			undefined,
			"",
			origin,
		);
		expect(redirect.status).toBe(302);
		expect(new URL(redirect.headers.get("location")!).origin).toBe(appOrigin);
		const granted = await state.request(
			"/sdk/support/application/authorize",
			query,
			actorCookie,
			appOrigin,
			true,
		);
		expect(granted.status).toBe(200);
		expect(granted.headers.getSetCookie()).toEqual([]);
		const issued = (await granted.json()) as { url: string; sessionId: string };
		const callback = new URL(issued.url);
		return {
			issued,
			query,
			exchange: {
				code: callback.searchParams.get("code")!,
				state: stateCode,
				codeVerifier,
				callbackUrl: `${isolatedOrigin}/api/allauth/support/callback`,
			},
		};
	}
	it("is disabled by default and requires signed live ordinary actor proof on the primary origin", async () => {
		expect(
			(
				await state.request(
					"/sdk/support/application/launch",
					input(),
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		state.enableApplication();
		for (const [cookies, selectedOrigin, signed] of [
			[actorCookie, appOrigin, false],
			[state.rootCookie, appOrigin, true],
			[actorCookie, isolatedOrigin, true],
		] as const)
			expect(
				(
					await state.request(
						"/sdk/support/application/launch",
						input(),
						cookies,
						selectedOrigin,
						signed,
					)
				).status,
			).toBe(403);
		expect(
			(
				await state.request(
					"/sdk/support/application/launch",
					{ ...input(), actorSessionId: "forged-session" },
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
	});
	it("refuses a support origin on another port of the primary cookie hostname", async () => {
		state.enableApplication();
		state.setApplicationCallbackOrigin("https://app.example:8443");
		expect(
			(
				await state.request(
					"/sdk/support/application/launch",
					input(),
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
	});
	it("does not let a stolen launch or different actor session authorize support", async () => {
		state.enableApplication();
		const before = await state.context.adapter.count({ model: "session" });
		const launch = await state.request(
			"/sdk/support/application/launch",
			input(),
			actorCookie,
			appOrigin,
			true,
		);
		const query = {
			launch: new URL(
				((await launch.json()) as { url: string }).url,
			).searchParams.get("launch")!,
			state: opaque(),
			codeChallenge: sha(opaque()),
		};
		expect(await state.context.adapter.count({ model: "session" })).toBe(
			before,
		);
		expect(
			(
				await state.request(
					"/sdk/support/application/authorize",
					query,
					"",
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		const changed = cookie(
			await state.request(
				"/sign-in/email",
				{ email: "app-admin@fixture.example", password },
				"",
				appOrigin,
				true,
			),
		);
		expect(
			(
				await state.request(
					"/sdk/support/application/authorize",
					query,
					changed,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
	});
	it("issues only support-origin cookies, exposes safe actor binding, and preserves the main administrator", async () => {
		const { query, exchange } = await authorize();
		expect(
			(
				await state.request(
					"/sdk/support/exchange",
					exchange,
					"",
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		const response = await state.request(
			"/sdk/support/exchange",
			exchange,
			"",
			isolatedOrigin,
			true,
		);
		expect(response.status).toBe(200);
		const data = (await response.json()) as {
			session: { id: string; expiresAt: string };
		};
		expect(data).toMatchObject({
			actorKind: "application",
			actorSessionId,
			applicationAuditId: "app-audit-1",
			actor: { id: actorId },
			context: { kind: "company", id: "company-1" },
			applicationReturnURL: `${appOrigin}/admin`,
		});
		expect(Date.parse(data.session.expiresAt) - Date.now()).toBeLessThanOrEqual(
			15 * 60000,
		);
		expect(JSON.stringify(data)).not.toMatch(/"token"|reason|codeVerifier/);
		expect(
			(
				await state.request(
					"/sdk/support/application/authorize",
					query,
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(400);
		const main = await state.request(
			"/get-session?disableRefresh=true",
			undefined,
			actorCookie,
			appOrigin,
			true,
		);
		expect(await main.json()).toMatchObject({
			session: { id: actorSessionId, impersonatedBy: null },
			user: { id: actorId },
		});
		const status = await state.request(
			"/sdk/support/session",
			undefined,
			cookie(response),
			isolatedOrigin,
			true,
		);
		expect(await status.json()).toMatchObject({
			actorKind: "application",
			actorSessionId,
		});
		const end = await state.request(
			"/sdk/support/stop",
			{},
			cookie(response),
			isolatedOrigin,
			true,
		);
		expect(end.status).toBe(200);
		expect(await end.json()).toMatchObject({
			applicationReturnURL: `${appOrigin}/admin`,
		});
		expect(
			await (
				await state.request(
					"/get-session?disableRefresh=true",
					undefined,
					actorCookie,
					appOrigin,
					true,
				)
			).json(),
		).toMatchObject({ session: { id: actorSessionId } });
	});
	it("revokes only the bound native app support session from its original main actor, idempotently", async () => {
		const { issued, exchange } = await authorize();
		expect(issued.sessionId).toBeTruthy();
		const connected = await state.request(
			"/sdk/support/exchange",
			exchange,
			"",
			isolatedOrigin,
			true,
		);
		const body = {
			sessionId: issued.sessionId,
			applicationAuditId: "app-audit-1",
		};
		expect(
			(
				await state.request(
					"/sdk/support/application/revoke",
					{ ...body, applicationAuditId: "another-audit" },
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
		expect(
			(
				await state.request(
					"/sdk/support/application/revoke",
					body,
					actorCookie,
					isolatedOrigin,
					true,
				)
			).status,
		).toBe(403);
		for (let attempt = 0; attempt < 2; attempt++)
			expect(
				await (
					await state.request(
						"/sdk/support/application/revoke",
						body,
						actorCookie,
						appOrigin,
						true,
					)
				).json(),
			).toEqual({ success: true, ...body });
		expect(
			await (
				await state.request(
					"/get-session",
					undefined,
					cookie(connected),
					isolatedOrigin,
					true,
				)
			).json(),
		).toBeNull();
		expect(
			await (
				await state.request(
					"/get-session",
					undefined,
					actorCookie,
					appOrigin,
					true,
				)
			).json(),
		).toMatchObject({ session: { id: actorSessionId } });
	});
	it("acknowledges an absent native session after its binding expired using fresh main-app actor proof", async () => {
		const { issued } = await authorize();
		await state.context.adapter.delete({
			model: "session",
			where: [{ field: "id", value: issued.sessionId }],
		});
		await state.context.adapter.update({
			model: "verification",
			where: [
				{ field: "identifier", value: `support-session:${issued.sessionId}` },
			],
			update: { expiresAt: new Date(Date.now() - 1000) },
		});
		const body = {
			sessionId: issued.sessionId,
			applicationAuditId: "app-audit-1",
		};
		for (const [cookies, selectedOrigin, signed] of [
			[actorCookie, appOrigin, false],
			["", appOrigin, true],
		] as const)
			expect(
				(
					await state.request(
						"/sdk/support/application/revoke",
						body,
						cookies,
						selectedOrigin,
						signed,
					)
				).status,
			).toBe(403);
		for (let attempt = 0; attempt < 2; attempt++)
			expect(
				await (
					await state.request(
						"/sdk/support/application/revoke",
						body,
						actorCookie,
						appOrigin,
						true,
					)
				).json(),
			).toEqual({ success: true, ...body, alreadyEnded: true });
		expect(
			(
				await state.request(
					"/sdk/support/application/revoke",
					body,
					actorCookie,
					isolatedOrigin,
					true,
				)
			).status,
		).toBe(403);
		expect(
			await (
				await state.request(
					"/get-session",
					undefined,
					actorCookie,
					appOrigin,
					true,
				)
			).json(),
		).toMatchObject({ session: { id: actorSessionId, impersonatedBy: null } });
		state.disable();
		expect(
			(
				await state.request(
					"/sdk/support/application/revoke",
					body,
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(403);
	});
	it("never uses absence acknowledgement to revoke an existing session without its full binding", async () => {
		const { issued } = await authorize();
		await state.context.internalAdapter.deleteVerificationByIdentifier(
			`support-session:${issued.sessionId}`,
		);
		for (const sessionId of [issued.sessionId, actorSessionId]) {
			const response = await state.request(
				"/sdk/support/application/revoke",
				{ sessionId, applicationAuditId: "forged-audit" },
				actorCookie,
				appOrigin,
				true,
			);
			expect(response.status).toBe(400);
			expect(
				await state.context.adapter.findOne({
					model: "session",
					where: [{ field: "id", value: sessionId }],
				}),
			).not.toBeNull();
		}
	});
	it("retains only an idempotent cleanup receipt after stopping from the support window", async () => {
		const { issued, exchange } = await authorize();
		const connected = await state.request(
			"/sdk/support/exchange",
			exchange,
			"",
			isolatedOrigin,
			true,
		);
		expect(
			(
				await state.request(
					"/sdk/support/stop",
					{},
					cookie(connected),
					isolatedOrigin,
					true,
				)
			).status,
		).toBe(200);
		expect(
			(
				await state.request(
					"/sdk/support/application/revoke",
					{ sessionId: issued.sessionId, applicationAuditId: "app-audit-1" },
					actorCookie,
					appOrigin,
					true,
				)
			).status,
		).toBe(200);
	});
	it.each([
		"revoke-actor",
		"direct-native",
		"disable-registration",
	])("fails closed after %s", async (reason) => {
		const { exchange } = await authorize();
		const response = await state.request(
			"/sdk/support/exchange",
			exchange,
			"",
			isolatedOrigin,
			true,
		);
		const selected = cookie(response);
		if (reason === "revoke-actor")
			await state.context.internalAdapter.deleteUserSessions(actorId);
		if (reason === "disable-registration") state.disable();
		const check = await state.request(
			"/get-session?disableRefresh=true",
			undefined,
			selected,
			isolatedOrigin,
			reason !== "direct-native",
		);
		expect(await check.json()).toBeNull();
	});
	it("completes the isolated native SDK handoff and cleanup while leaving main-app cookies untouched", async () => {
		state.enableApplication();
		const launch = await state.request(
			"/sdk/support/application/launch",
			input(),
			actorCookie,
			appOrigin,
			true,
		);
		const launchURL = new URL(((await launch.json()) as { url: string }).url);
		const optimizedRequests: Request[] = [];
		const ingress = (request: Request) => {
			if (!new URL(request.url).pathname.endsWith("/get-session"))
				return state.fixture.auth.handler(request);
			optimizedRequests.push(new Request(request));
			return handleProjectAuthentication(
				request,
				state.project,
				state.environment,
				state.context.secret,
				{
					consume: async () => ({ allowed: true, retryAfter: 0 }),
					session: async (headers, verified) =>
						runWithAdapter(state.context.adapter, () =>
							state.fixture.auth.api.getSession({
								headers,
								request: verified,
								query: { disableCookieCache: true },
								asResponse: true,
							}),
						),
					fallback: (verified) => state.fixture.auth.handler(verified),
				},
			);
		};
		vi.stubGlobal("fetch", (url: string | URL | Request, init?: RequestInit) =>
			ingress(new Request(url, init)),
		);
		const handler = createAllAuthProxy({
			project: state.project.slug,
			proxySecret: projectProxySecret(state.project, state.environment),
			appOrigin: isolatedOrigin,
			allauthURL: origin,
			supportAccess: {
				enabled: true,
				applicationReturnUrl: `${appOrigin}/admin`,
			},
		});
		const jar = new Map<string, string>();
		const call = async (endpoint: string, body?: unknown) => {
			const path = endpoint.split("?", 1)[0];
			const response = await handler(
				new Request(`${isolatedOrigin}/api/allauth/${endpoint}`, {
					method: body === undefined ? "GET" : "POST",
					headers: {
						cookie: [...jar]
							.map(([key, value]) => `${key}=${value}`)
							.join("; "),
						...(body === undefined
							? {}
							: { origin: isolatedOrigin, "content-type": "application/json" }),
					},
					...(body === undefined ? {} : { body: JSON.stringify(body) }),
				}),
				{ params: Promise.resolve({ all: path.split("/") }) },
			);
			for (const value of response.headers.getSetCookie()) {
				const [pair] = value.split(";");
				const equals = pair.indexOf("=");
				if (/Max-Age=0(?:;|$)/i.test(value)) jar.delete(pair.slice(0, equals));
				else jar.set(pair.slice(0, equals), pair.slice(equals + 1));
			}
			return response;
		};
		const start = await call(`support/start${launchURL.search}`);
		expect(start.status).toBe(302);
		const route = await state.fixture.auth.handler(
			new Request(start.headers.get("location")!),
		);
		expect(route.status).toBe(302);
		const mainAuthorize = new URL(route.headers.get("location")!);
		expect(mainAuthorize.origin).toBe(appOrigin);
		const query = Object.fromEntries(mainAuthorize.searchParams);
		const authorized = await state.request(
			"/sdk/support/application/authorize",
			query,
			actorCookie,
			appOrigin,
			true,
		);
		expect(authorized.status).toBe(200);
		const callback = new URL(
			((await authorized.json()) as { url: string }).url,
		);
		expect((await call(`support/callback${callback.search}`)).status).toBe(303);
		expect(await (await call("support/session")).json()).toMatchObject({
			support: {
				actorKind: "application",
				actorSessionId,
				context: { kind: "company", id: "company-1" },
				applicationReturnURL: `${appOrigin}/admin`,
			},
		});
		expect(await (await call("get-session")).json()).toMatchObject({
			session: { impersonatedBy: actorId },
			user: { id: state.targetId },
		});
		expect(optimizedRequests.length).toBeGreaterThan(0);
		const checkedRequest = optimizedRequests.at(-1)!;
		for (const field of ["allauth-proxy-origin", "allauth-proxy-signature"]) {
			const forged = new Request(checkedRequest);
			forged.headers.set(field, "forged");
			await expect(ingress(forged)).rejects.toMatchObject({ statusCode: 403 });
		}
		const missingOrigin = new Request(checkedRequest);
		missingOrigin.headers.delete("allauth-proxy-origin");
		await expect(ingress(missingOrigin)).rejects.toMatchObject({
			statusCode: 403,
		});
		expect(await (await call("support/session")).json()).toMatchObject({
			support: { actorKind: "application", actorSessionId },
		});
		const stopped = await call("support/stop", {});
		expect(await stopped.json()).toMatchObject({
			success: true,
			restored: false,
			applicationReturnURL: `${appOrigin}/admin`,
		});
		expect(jar.size).toBe(0);
		expect(
			await (
				await state.request(
					"/get-session?disableRefresh=true",
					undefined,
					actorCookie,
					appOrigin,
					true,
				)
			).json(),
		).toMatchObject({ session: { id: actorSessionId, impersonatedBy: null } });
		vi.unstubAllGlobals();
	});
});
