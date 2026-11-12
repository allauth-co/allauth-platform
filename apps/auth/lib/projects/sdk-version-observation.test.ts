import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GET, POST } from "../../app/api/projects/[slug]/auth/[...all]/route";
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
});
