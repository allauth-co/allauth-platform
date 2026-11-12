import { beforeEach, expect, it, vi } from "vitest";
import { portalHeader, signPortalBinding } from "./edge";
import { hostedOrganizationPreview } from "./hosted-organization-preview";

const fixture = vi.hoisted(() => ({
	id: "018dad31-1be5-4f84-9196-68949a8db228",
	hostname: "accounts.fixture.example",
	secret: "synthetic-hosted-organization-preview-proof-key",
	readEnvironment: vi.fn(),
	resolveBinding: vi.fn(),
}));
vi.mock("../auth", () => ({ getAuthEnvironment: fixture.readEnvironment }));
vi.mock("./hosting", () => ({ resolveHostedBinding: fixture.resolveBinding }));

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
	bind();
});

it("requires the real proof and never treats a Host header as a preview grant", async () => {
	const incoming = new Headers({ host: fixture.hostname });
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	expect(fixture.readEnvironment).not.toHaveBeenCalled();
	incoming.set(portalHeader, "invalid");
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	expect(fixture.resolveBinding).not.toHaveBeenCalled();
	incoming.set(
		portalHeader,
		await signPortalBinding(fixture.hostname, fixture.secret),
	);
	incoming.set("host", "another.fixture.example");
	expect(await hostedOrganizationPreview(incoming)).toBe(true);
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
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	bind("frontend-api");
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	bind("accounts", "development", "018dad31-1be5-4f84-9196-68949a8db229");
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	fixture.resolveBinding.mockClear();
	fixture.readEnvironment.mockResolvedValue({
		ALLAUTH_EDGE_SECRET: fixture.secret,
	});
	expect(await hostedOrganizationPreview(incoming)).toBe(false);
	expect(fixture.resolveBinding).not.toHaveBeenCalled();
});
