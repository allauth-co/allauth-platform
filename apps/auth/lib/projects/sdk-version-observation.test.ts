import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	GET,
	PATCH,
	POST,
} from "../../app/api/projects/[slug]/auth/[...all]/route";
import { projectProxySecret } from "./proxy";
import type { Project } from "./registry";

const state = vi.hoisted(() => ({
	after: vi.fn(),
	record: vi.fn(async () => {}),
	open: vi.fn(),
	verify: vi.fn(),
	authorizeDirectory: vi.fn(async () => {}),
	environment: {
		BETTER_AUTH_SECRET: "disposable-project-proxy-fixture-secret",
		ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: "82340693-70e3-44b9-a1b1-508403d4de64",
	},
	project: {
		id: "82340693-70e3-44b9-a1b1-508403d4de64",
		slug: "fixture",
		environment: "development",
		workspaceId: "00000000-0000-4000-8000-000000000001",
		schemaName: "allauth_project_8234069370e344b9a1b1508403d4de64",
		proxyVersion: "fixture-key-version",
		origins: ["https://app.fixture.example"],
	} as Project,
	scope: {
		engine: {
			dispatch: vi.fn(async (_request: Request) => Response.json({ ok: true })),
			readSession: vi.fn(),
			readDirectory: vi.fn(async () => Response.json({ users: [] })),
		},
		consumeAdmission: vi.fn(async () => ({ allowed: true, retryAfter: 0 })),
	},
}));
vi.mock("next/server", () => ({ after: state.after }));
vi.mock("@/lib/auth", () => ({
	getAuthEnvironment: async () => state.environment,
}));
vi.mock("@/lib/projects/registry", () => ({
	getProject: async () => state.project,
	projectRegistryPool: () => ({}),
}));
vi.mock("@/lib/projects/runtime", () => {
	async function open(
		project: Project,
		callback: (
			scope: typeof state.scope,
			env: object,
			project: Project,
		) => Promise<Response>,
	) {
		state.open(project);
		return callback(state.scope, state.environment, project);
	}
	return {
		withProjectAuthEngine: async (
			_slug: string,
			callback: Parameters<typeof open>[1],
		) => open(state.project, callback),
		withResolvedProjectAuthEngine: open,
		projectSecret: () => "fixture-secret",
	};
});
vi.mock("@/lib/projects/proxy", async (importOriginal) => {
	const actual = await importOriginal<typeof import("./proxy")>();
	return {
		...actual,
		verifiedProjectRequest: (
			...args: Parameters<typeof actual.verifiedProjectRequest>
		) => {
			state.verify(...args);
			return actual.verifiedProjectRequest(...args);
		},
	};
});
vi.mock("@/lib/projects/backend-credentials", () => ({
	backendCredentialRepository: () => ({ authorize: state.authorizeDirectory }),
}));
vi.mock("@/lib/notifications/repository", () => ({
	recordSdkVersionObservation: state.record,
}));
afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllEnvs();
	vi.useRealTimers();
});

const auth = "https://allauth.co/api/projects/fixture/auth";
const context = { params: Promise.resolve({ slug: "fixture" }) };
function signedHeaders(url: string, method = "GET", body = "") {
	const { pathname, search } = new URL(url);
	const timestamp = String(Math.floor(Date.now() / 1000));
	const origin = state.project.origins[0];
	const input = [
		timestamp,
		method,
		pathname + search,
		origin,
		"192.0.2.3",
		createHash("sha256").update(body).digest("hex"),
	].join("\n");
	return new Headers({
		"allauth-proxy-timestamp": timestamp,
		"allauth-proxy-origin": origin,
		"allauth-proxy-ip": "192.0.2.3",
		"allauth-proxy-signature": createHmac(
			"sha256",
			projectProxySecret(state.project, state.environment),
		)
			.update(input)
			.digest("hex"),
	});
}

describe("optional SDK observations leave authentication unchanged", () => {
	it.each([
		undefined,
		"",
	])("does not observe an unsigned or empty-signature request (%s)", async (signature) => {
		const headers = new Headers({ "x-allauth-sdk-version": "9.9.9" });
		if (signature !== undefined)
			headers.set("allauth-proxy-signature", signature);
		const response = await GET(
			new Request(`${auth}/get-session`, { headers }),
			context,
		);
		expect(response.status).toBe(200);
		expect(state.after).not.toHaveBeenCalled();
		expect(state.record).not.toHaveBeenCalled();
	});
	it("schedules a verified app version after responding and tolerates observation failure", async () => {
		state.record.mockRejectedValueOnce(
			new Error("Observation storage unavailable"),
		);
		const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const url = `${auth}/get-session`;
			const headers = signedHeaders(url);
			headers.set("x-allauth-sdk-version", "1.4.3");
			const response = await GET(new Request(url, { headers }), context);
			expect(response.status).toBe(200);
			expect(state.record).not.toHaveBeenCalled();
			const callback = state.after.mock.calls[0]?.[0] as () => Promise<void>;
			await expect(callback()).resolves.toBeUndefined();
			expect(state.record).toHaveBeenCalledWith(
				state.project,
				"1.4.3",
				state.environment,
			);
		} finally {
			warning.mockRestore();
		}
	});
});

describe("direct proxy verification and the admitted project writer", () => {
	it("meters signed session reads using the active versioned cookie key", async () => {
		const active = "isolated-fixture-active-session-signing-key";
		const previous = "isolated-fixture-previous-session-signing-key";
		vi.stubEnv("BETTER_AUTH_SECRETS", `4:${active},12:${previous}`);
		const url = `${auth}/get-session`;
		const token = "fixture-versioned-session";
		const value = (secret: string) =>
			`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`;
		const cookie = (signedValue: string) =>
			`__Secure-allauth_project_${state.project.slug}.session_token=${encodeURIComponent(signedValue)}`;
		const request = (signedValue: string, signed = true) => {
			const headers = signed ? signedHeaders(url) : new Headers();
			headers.set("cookie", cookie(signedValue));
			return new Request(url, { headers });
		};
		const activeValue = value(active);
		const live = { session: { id: "live-fixture-session" } };
		state.scope.engine.readSession.mockResolvedValueOnce(Response.json(live));
		const admitted = await GET(request(activeValue), context);
		expect(admitted.status).toBe(200);
		expect(await admitted.json()).toEqual(live);
		const digest = createHash("sha256")
			.update(JSON.stringify([state.project.id, activeValue]))
			.digest("hex");
		expect(state.scope.consumeAdmission).toHaveBeenCalledExactlyOnceWith(
			`bff-session:v2:${digest}`,
		);
		expect(state.scope.engine.readSession).toHaveBeenCalledOnce();
		expect(state.scope.engine.dispatch).not.toHaveBeenCalled();

		for (const ordinary of [
			request(activeValue, false),
			request(value(previous)),
			request(value("fixture-secret")),
			request("invalid-fixture-cookie"),
		]) {
			const response = await GET(ordinary, context);
			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({ ok: true });
		}
		expect(state.scope.engine.dispatch).toHaveBeenCalledTimes(4);
		expect(state.scope.engine.readSession).toHaveBeenCalledOnce();
		expect(state.scope.consumeAdmission).toHaveBeenCalledOnce();
	});

	it("verifies once against the exact registry binding before opening the writer and keeps the body", async () => {
		const url = `${auth}/sign-in/email?source=fixture`;
		const body = '{"fixture":true}';
		const request = new Request(url, {
			method: "POST",
			headers: signedHeaders(url, "POST", body),
			body,
		});
		const response = await POST(request, context);
		expect(response.status).toBe(200);
		expect(state.verify).toHaveBeenCalledExactlyOnceWith(
			request,
			state.project,
			state.environment,
			{ consumeBody: true },
		);
		expect(state.open).toHaveBeenCalledExactlyOnceWith(state.project);
		expect(state.open.mock.calls[0][0]).toBe(state.verify.mock.calls[0][1]);
		expect(state.verify.mock.invocationCallOrder[0]).toBeLessThan(
			state.open.mock.invocationCallOrder[0],
		);
		const dispatched = state.scope.engine.dispatch.mock.calls[0][0];
		expect(dispatched.url).toBe(url);
		expect(dispatched.headers.get("x-real-ip")).toBe("192.0.2.3");
		expect(await dispatched.text()).toBe(body);
	});

	it("rejects an invalid proxy envelope before opening the writer or recording an SDK version", async () => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		try {
			const response = await GET(
				new Request(`${auth}/get-session`, {
					headers: {
						"allauth-proxy-signature": "invalid-fixture",
						"x-allauth-sdk-version": "2.0.0",
					},
				}),
				context,
			);
			expect(response.status).toBe(403);
			expect(state.open).not.toHaveBeenCalled();
			expect(state.scope.engine.dispatch).not.toHaveBeenCalled();
			expect(state.after).not.toHaveBeenCalled();
		} finally {
			info.mockRestore();
		}
	});

	it("returns the body timeout before opening the project writer", async () => {
		vi.useFakeTimers();
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		try {
			const url = `${auth}/sign-in/email`;
			const cancel = vi.fn();
			const body = new ReadableStream<Uint8Array>({ cancel });
			const request = new Request(url, {
				method: "POST",
				headers: signedHeaders(url, "POST"),
				body,
				duplex: "half",
			} as RequestInit);
			const response = POST(request, context);
			await vi.advanceTimersByTimeAsync(4999);
			expect(state.verify).toHaveBeenCalledOnce();
			expect(state.open).not.toHaveBeenCalled();
			expect(cancel).not.toHaveBeenCalled();
			await vi.advanceTimersByTimeAsync(1);
			expect((await response).status).toBe(408);
			expect(cancel).toHaveBeenCalledOnce();
			expect(state.open).not.toHaveBeenCalled();
		} finally {
			info.mockRestore();
		}
	});

	it("keeps separately authenticated service-directory reads independent of proxy headers", async () => {
		const response = await GET(
			new Request(`${auth}/service-directory/users`, {
				headers: {
					"allauth-backend-key": `aabk_${state.project.id}_${"a".repeat(43)}`,
					"allauth-proxy-signature": "ignored-by-directory-transport",
				},
			}),
			context,
		);
		expect(response.status).toBe(200);
		expect(state.authorizeDirectory).toHaveBeenCalledOnce();
		expect(state.scope.engine.readDirectory).toHaveBeenCalledOnce();
		expect(state.verify).not.toHaveBeenCalled();
	});
	it.each([
		{
			path: "scim/v2/Users",
			method: "POST",
			handle: POST,
			media: "application/scim+json",
		},
		{
			path: "scim/v2/Groups/fixture-group",
			method: "PATCH",
			handle: PATCH,
			media: "application/json",
		},
		{
			path: "sso/saml2/sp/acs/fixture-provider",
			method: "POST",
			handle: POST,
			media: "application/x-www-form-urlencoded",
		},
	])("bounds unsigned $path before admission", async ({
		path,
		method,
		handle,
		media,
	}) => {
		vi.useFakeTimers();
		const cancel = vi.fn();
		const request = new Request(`${auth}/${path}`, {
			method,
			headers: { "content-type": media },
			body: new ReadableStream<Uint8Array>({ cancel }),
			duplex: "half",
		} as RequestInit);
		const response = handle(request, context);
		await vi.advanceTimersByTimeAsync(4999);
		expect(state.open).not.toHaveBeenCalled();
		expect(cancel).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(1);
		const rejected = await response;
		expect(rejected.status).toBe(408);
		expect(cancel).toHaveBeenCalledOnce();
		expect(state.open).not.toHaveBeenCalled();
		if (path.startsWith("scim/")) {
			expect(rejected.headers.get("content-type")).toBe(
				"application/scim+json",
			);
			expect(await rejected.json()).toMatchObject({
				schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
				status: "408",
			});
		} else {
			expect(await rejected.json()).toMatchObject({
				code: "INVALID_SAML_RESPONSE",
			});
			expect(rejected.headers.has("location")).toBe(false);
		}
	});
	it.each([
		{
			path: "scim/v2/Groups/fixture-group?attributes=displayName",
			method: "PATCH",
			handle: PATCH,
			media: "application/scim+json; charset=utf-8",
			payload:
				'{"Operations":[{"op":"replace","path":"displayName","value":"R&D"}]}',
		},
		{
			path: "sso/saml2/sp/acs/fixture-provider",
			method: "POST",
			handle: POST,
			media: "application/x-www-form-urlencoded",
			payload: "SAMLResponse=fixture%2B%2F%3D&RelayState=opaque",
		},
		{
			path: "scim/v2/Users",
			method: "POST",
			handle: POST,
			media: "application/json",
			payload: '{"userName":"fixture@example.test"}' + " ".repeat(262144),
		},
	])("preserves exact unsigned $path bytes for the selected parser", async ({
		path,
		method,
		handle,
		media,
		payload,
	}) => {
		const url = `${auth}/${path}`;
		state.scope.engine.dispatch.mockImplementationOnce(async (request) => {
			expect(request.url).toBe(url);
			expect(request.method).toBe(method);
			expect(request.headers.get("content-type")).toBe(media);
			expect(request.headers.get("authorization")).toBe(
				"Bearer isolated-fixture",
			);
			expect(await request.text()).toBe(payload);
			return Response.json({ ok: true }, { status: 201 });
		});
		const response = await handle(
			new Request(url, {
				method,
				headers: {
					"content-type": media,
					authorization: "Bearer isolated-fixture",
				},
				body: payload,
			}),
			context,
		);
		expect(response.status).toBe(201);
	});

	it("keeps the same deadline when a large body is handed to the native parser", async () => {
		vi.useFakeTimers();
		const cancel = vi.fn();
		state.scope.engine.dispatch.mockImplementationOnce(async (request) => {
			await request.arrayBuffer();
			return Response.json({ ok: true });
		});
		const request = new Request(`${auth}/scim/v2/Users`, {
			method: "POST",
			headers: { "content-type": "application/scim+json" },
			body: new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new Uint8Array(262145));
				},
				cancel,
			}),
			duplex: "half",
		} as RequestInit);
		const response = POST(request, context);
		await vi.advanceTimersByTimeAsync(4999);
		expect(state.open).toHaveBeenCalledOnce();
		expect(cancel).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(1);
		expect((await response).status).toBe(408);
		expect(cancel).toHaveBeenCalledOnce();
	});
});
