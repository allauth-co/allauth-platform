import { beforeEach, expect, it, vi } from "vitest";
import HostedDevicePage from "@/app/account/device/page";
import DevicePage from "@/app/device/page";
import { DeviceApproval } from "@/components/features/device";
import { HostedProjectUnavailable } from "@/components/hosted-project-unavailable";
import { firstPartyHostedPath } from "../hosted-portal-paths";
import { portalHeader } from "../domains/edge";

const state = vi.hoisted(() => ({
	headers: vi.fn(),
	getAuthEnvironment: vi.fn(),
	getProject: vi.fn(),
	resolveHostedBinding: vi.fn(),
	listStoredActiveProjectHostnames: vi.fn(),
	withPortalHeadersEngine: vi.fn(),
	readWriter: vi.fn(),
	readSession: vi.fn(),
	projectRegistryPool: vi.fn(),
}));

vi.mock("next/headers", () => ({ headers: state.headers }));
vi.mock("next/navigation", () => ({
	notFound: () => { throw new Error("not-found"); },
	redirect: (path: string) => { throw new Error(`redirect:${path}`); },
}));
vi.mock("../auth", () => ({ getAuthEnvironment: state.getAuthEnvironment }));
vi.mock("../domains/hosting", () => ({
	resolveHostedBinding: state.resolveHostedBinding,
	withPortalHeadersEngine: state.withPortalHeadersEngine,
}));
vi.mock("../domains/repository", () => ({
	listStoredActiveProjectHostnames: state.listStoredActiveProjectHostnames,
}));
vi.mock("../projects/project-engine-internal-writer", () => ({
	projectWriterLease: () => ({ read: state.readWriter }),
}));
vi.mock("../projects/registry", () => ({
	getProject: state.getProject,
	projectRegistryPool: state.projectRegistryPool,
}));
vi.mock("../projects/runtime", () => ({
	withResolvedProjectAuthEngine: (
		_project: unknown,
		callback: (scope: { engine: { readSession: typeof state.readSession } }) => unknown,
	) => callback({ engine: { readSession: state.readSession } }),
}));
vi.mock("@/components/features/device", () => ({ DeviceApproval: () => null }));

const project = {
	id: "018dad31-1be5-4f84-9196-68949a8db228",
	slug: "device-fixture",
	schemaName: "allauth_project_018dad311be54f84919668949a8db228",
	environment: "development",
	workspaceId: "c61c3ddc-de6c-4fc8-b307-bd8bf308d859",
	projectEngineFenced: true,
};
const managed = "device-fixture-accounts.allauth.co";
const custom = "accounts.device-fixture.example.com";
const basePath = "/api/projects/device-fixture/auth";
const environment = {
	ALLAUTH_AUTH_URL: "https://allauth.co",
	ALLAUTH_EDGE_SECRET: "fixture-edge-secret-at-least-32-characters",
	CLOUDFLARE_SAAS_READY: "true",
	ALLAUTH_PROJECT_ENGINE_DEVELOPMENT_REVISIONS: JSON.stringify({ [project.id]: 0 }),
};
const code = "ABCD EFGH";
const directPage = (params = { project: project.slug, user_code: code }) =>
	DevicePage({ searchParams: Promise.resolve(params) });
const hostedPage = (params: { project?: string; user_code?: string | string[] } = { user_code: code }) =>
	HostedDevicePage({ searchParams: Promise.resolve(params) });
const binding = (hostname = managed) => ({ kind: "accounts", hostname, project });
const proof = new Headers({ [portalHeader]: "fixture-signed-proof" });
const realCookie = "__Secure-allauth_project_device-fixture.session_token=fixture";

function freshSession() {
	return {
		user: { id: "device-user", emailVerified: true },
		session: {
			userId: "device-user",
			createdAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 3600_000).toISOString(),
		},
	};
}

beforeEach(() => {
	vi.resetAllMocks();
	state.headers.mockResolvedValue(new Headers());
	state.getAuthEnvironment.mockResolvedValue(environment);
	state.getProject.mockResolvedValue(project);
	state.resolveHostedBinding.mockImplementation(async (hostname: string) => binding(hostname));
	state.readWriter.mockResolvedValue({ writer: "allauth", revision: 1 });
});

it("keeps the shared platform device page and rejects repeated project selectors", async () => {
	const shared = await DevicePage({ searchParams: Promise.resolve({ user_code: code }) });
	expect(shared.type).toBe(DeviceApproval);
	expect(shared.props).toEqual({ initialCode: code });
	const invalid = await DevicePage({
		searchParams: Promise.resolve({ project: [project.slug, "other-fixture"], user_code: code }),
	});
	expect(invalid.type).not.toBe(DeviceApproval);
	expect(state.getProject).not.toHaveBeenCalled();
});

it("hands the original code to the exact verified accounts realm without reading shared or foreign sessions", async () => {
	state.headers.mockResolvedValue(new Headers({
		cookie: "__Secure-allauth.session_token=root; __Secure-allauth_project_other.session_token=other",
	}));
	await expect(directPage()).rejects.toThrow(
		`redirect:https://${managed}/account/device?user_code=ABCD+EFGH`,
	);
	expect(state.getProject).toHaveBeenCalledWith(project.slug, environment);
	expect(state.resolveHostedBinding).toHaveBeenCalledWith(managed, environment);
	expect(state.readSession).not.toHaveBeenCalled();
});

it("keeps a live fresh apex project session and reads no refresh, foreign cookie, or bearer state", async () => {
	state.headers.mockResolvedValue(new Headers({
		cookie: `__Secure-allauth.session_token=root; ${realCookie}; __Secure-allauth_project_device-fixture.two_factor=challenge`,
		authorization: "Bearer fixture",
	}));
	state.readSession.mockImplementation(async () => Response.json(freshSession()));
	const result = await directPage();
	expect(result.type).toBe(DeviceApproval);
	expect(result.props).toMatchObject({
		project: project.slug,
		initialCode: code,
		basePath,
		reauthentication: {
			signInURL: `https://${managed}/sign-in`,
			returnPath: "/account/device",
		},
	});
	const request = state.readSession.mock.calls[0]?.[0] as Request;
	expect(request.url).toBe(
		`https://allauth.co${basePath}/get-session?disableRefresh=true&disableCookieCache=true`,
	);
	expect(request.headers.get("cookie")).toBe(realCookie);
	expect(request.headers.has("authorization")).toBe(false);
});

it("hands off a stale project session and preserves an explicitly configured verified custom passkey origin", async () => {
	state.headers.mockResolvedValue(new Headers({ cookie: realCookie }));
	state.readSession.mockImplementation(async () => {
		const current = freshSession();
		current.session.createdAt = new Date(Date.now() - 360_000).toISOString();
		return Response.json(current);
	});
	state.getAuthEnvironment.mockResolvedValue({
		...environment,
		ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({
			[project.slug]: {
				enabled: true,
				projectId: project.id,
				environment: project.environment,
				rpOrigin: `https://${custom}`,
				ios: { teamId: "ABCDEFGHIJ", bundleId: "co.allauth.fixture" },
			},
		}),
	});
	state.listStoredActiveProjectHostnames.mockResolvedValue([
		{ hostname: "frontend-api.device-fixture.example.com", kind: "frontend-api" },
		{ hostname: custom, kind: "accounts" },
	]);
	await expect(directPage()).rejects.toThrow(
		`redirect:https://${custom}/account/device?user_code=ABCD+EFGH`,
	);
	state.resolveHostedBinding.mockImplementation(async (hostname: string) =>
		hostname === custom
			? { ...binding(hostname), project: { ...project, workspaceId: "different" } }
			: binding(hostname),
	);
	await expect(directPage()).rejects.toThrow(
		`redirect:https://${managed}/account/device?user_code=ABCD+EFGH`,
	);
});

it("keeps a local direct review when hosting is unavailable and a verified reauthentication link after rollback", async () => {
	state.getAuthEnvironment.mockResolvedValue({ ...environment, CLOUDFLARE_SAAS_READY: "" });
	expect((await directPage()).props).toMatchObject({
		project: project.slug,
		basePath,
		reauthentication: undefined,
	});
	expect(state.resolveHostedBinding).not.toHaveBeenCalled();
	state.getAuthEnvironment.mockResolvedValue(environment);
	state.readWriter.mockResolvedValue({ writer: "legacy", revision: 2 });
	expect((await directPage()).props).toMatchObject({
		project: project.slug,
		basePath,
		reauthentication: {
			signInURL: `https://${managed}/sign-in`,
			returnPath: "/account/device",
		},
	});
	state.readWriter.mockResolvedValue({ writer: "allauth", revision: 3 });
	expect((await directPage()).type).toBe(HostedProjectUnavailable);
});

it("binds the hosted page only to a verified accounts hostname on either writer", async () => {
	expect(firstPartyHostedPath("/account/device")).toBe(true);
	await expect(hostedPage()).rejects.toThrow("not-found");
	expect(state.withPortalHeadersEngine).not.toHaveBeenCalled();
	state.headers.mockResolvedValue(proof);
	state.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select({}, new Headers(), binding(custom), environment),
	);
	expect((await hostedPage()).props).toEqual({
		project: project.slug,
		initialCode: code,
		basePath: "/api/auth",
		reauthentication: {
			signInURL: "/sign-in",
			returnPath: "/account/device",
		},
	});
	expect((await hostedPage({ user_code: ["one", "two"] })).props.initialCode).toBe("");
	await expect(hostedPage({ project: "other-fixture", user_code: code })).rejects.toThrow("not-found");
	state.withPortalHeadersEngine.mockImplementation(async (_headers, select) =>
		select({}, new Headers(), { ...binding(custom), kind: "frontend-api" }, environment),
	);
	await expect(hostedPage()).rejects.toThrow("not-found");
});
