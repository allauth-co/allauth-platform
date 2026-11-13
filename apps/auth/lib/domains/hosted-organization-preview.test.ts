import { beforeEach, expect, it, vi } from "vitest";
import { GET } from "@/app/api/auth/hosted-presentation/route";
import { projectWriterUnavailable } from "../projects/project-engine-unavailable";
import { platformWorkspaceId } from "../workspaces/types";
import { portalHeader, signPortalBinding } from "./edge";
import { hostedPresentation } from "./hosted-organization-preview";

const fixture = vi.hoisted(() => ({
	id: "018dad31-1be5-4f84-9196-68949a8db228",
	hostname: "accounts.fixture.example",
	secret: "synthetic-hosted-organization-preview-proof-key",
	readEnvironment: vi.fn(),
	resolveBinding: vi.fn(),
	readWriter: vi.fn(),
}));
vi.mock("../auth", () => ({ getAuthEnvironment: fixture.readEnvironment }));
vi.mock("./hosting", () => ({ resolveHostedBinding: fixture.resolveBinding }));
vi.mock("../projects/project-engine-writer-lease", () => ({
	createProjectEngineWriterLease: () => ({ read: fixture.readWriter }),
}));

function bind(kind = "accounts", environment = "development", id = fixture.id) {
	fixture.resolveBinding.mockResolvedValue({
		hostname: fixture.hostname,
		kind,
		project: { id, environment },
	});
}

beforeEach(() => {
	fixture.readEnvironment.mockReset().mockResolvedValue({
		ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: fixture.id,
		ALLAUTH_EDGE_SECRET: fixture.secret,
	});
	fixture.resolveBinding.mockReset();
	fixture.readWriter.mockReset();
	bind();
});

it("requires the real proof and never treats a Host header as a preview grant", async () => {
	const incoming = new Headers({ host: fixture.hostname });
	expect(await hostedPresentation(incoming)).toBeUndefined();
	expect(fixture.readEnvironment).not.toHaveBeenCalled();
	incoming.set(portalHeader, "invalid");
	expect(await hostedPresentation(incoming)).toBeUndefined();
	expect(fixture.resolveBinding).not.toHaveBeenCalled();
	incoming.set(
		portalHeader,
		await signPortalBinding(fixture.hostname, fixture.secret),
	);
	incoming.set("host", "another.fixture.example");
	expect(await hostedPresentation(incoming)).toBe("preview");
	expect(fixture.resolveBinding).toHaveBeenCalledExactlyOnceWith(
		fixture.hostname,
		expect.objectContaining({
			ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS: fixture.id,
		}),
	);
});

it("leaves the preview off for production, API hosts, other projects and the empty allowlist", async () => {
	const incoming = new Headers({
		[portalHeader]: await signPortalBinding(fixture.hostname, fixture.secret),
	});
	bind("accounts", "production");
	expect(await hostedPresentation(incoming)).toBe("legacy");
	bind("frontend-api");
	expect(await hostedPresentation(incoming)).toBe("legacy");
	bind("accounts", "development", "018dad31-1be5-4f84-9196-68949a8db229");
	expect(await hostedPresentation(incoming)).toBe("legacy");
	fixture.resolveBinding.mockClear();
	fixture.readEnvironment.mockResolvedValue({
		ALLAUTH_EDGE_SECRET: fixture.secret,
	});
	expect(await hostedPresentation(incoming)).toBe("legacy");
	expect(fixture.resolveBinding).toHaveBeenCalledOnce();
});

it("serves only the exact bound mode and follows activation and rollback without caching", async () => {
	const url = "https://allauth.fixture.example/api/auth/hosted-presentation";
	const headers = new Headers();
	const read = () => GET(new Request(url, { headers }));
	expect((await read()).status).toBe(404);
	headers.set(
		portalHeader,
		await signPortalBinding(fixture.hostname, fixture.secret),
	);
	fixture.resolveBinding.mockResolvedValue({
		hostname: "other.fixture.example",
	});
	expect((await read()).status).toBe(404);
	fixture.resolveBinding.mockResolvedValue({
		hostname: fixture.hostname,
		kind: "frontend-api",
		project: {
			id: fixture.id,
			environment: "development",
			workspaceId: platformWorkspaceId,
			schemaName: `allauth_project_${fixture.id.replaceAll("-", "")}`,
		},
	});
	fixture.readEnvironment.mockResolvedValue({
		ALLAUTH_EDGE_SECRET: fixture.secret,
		ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: fixture.id,
	});
	for (const [writer, revision] of [
		["legacy", 0],
		["allauth", 1],
		["legacy", 2],
	] as const) {
		fixture.readWriter.mockResolvedValue({ writer, revision });
		const response = await read();
		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		expect(response.headers.has("set-cookie")).toBe(false);
		await expect(response.json()).resolves.toEqual({ mode: writer });
	}
	fixture.readWriter.mockRejectedValue(projectWriterUnavailable());
	const unavailable = await read();
	expect(unavailable.status).toBe(503);
	expect(unavailable.headers.get("cache-control")).toBe("no-store");
});
