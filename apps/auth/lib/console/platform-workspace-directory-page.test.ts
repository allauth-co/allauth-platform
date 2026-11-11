import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Page from "@/app/admin/platform/workspaces/page";

const state = vi.hoisted(() => ({
	requireScope: vi.fn(),
	redirect: vi.fn((href: string) => { throw new Error(`redirect:${href}`); }),
}));
vi.mock("next/navigation", () => ({ redirect: state.redirect }));
vi.mock("@/lib/console/page-scope", () => ({ requireConsolePageScope: state.requireScope }));
vi.mock("@/components/console/platform-workspace-directory", () => ({
	PlatformWorkspaceDirectory: () => createElement("h1", null, "Workspace directory"),
}));

beforeEach(() => {
	state.redirect.mockClear();
	state.requireScope.mockReset();
	state.requireScope.mockResolvedValue({});
});

describe("platform workspace directory page", () => {
	it("requires platform authority before rendering the directory", async () => {
		const page = await Page({ searchParams: Promise.resolve({}) });
		expect(state.requireScope).toHaveBeenCalledExactlyOnceWith(undefined);
		expect(renderToStaticMarkup(page)).toBe("<h1>Workspace directory</h1>");
	});

	it.each([{ project: "some-project" }, { workspace: "some-workspace" }, { project: ["", "other"] }])(
		"clears explicit tenant context after checking platform authority for %j",
		async (search) => {
			await expect(Page({ searchParams: Promise.resolve(search) })).rejects.toThrow("redirect:/admin/platform/workspaces");
			expect(state.requireScope).toHaveBeenCalledExactlyOnceWith(undefined);
			expect(state.requireScope.mock.invocationCallOrder[0]).toBeLessThan(state.redirect.mock.invocationCallOrder[0]!);
		},
	);

	it("propagates a failed platform authorization before a scoped redirect", async () => {
		state.requireScope.mockRejectedValue(new Error("denied"));
		await expect(Page({ searchParams: Promise.resolve({ workspace: "workspace-a" }) })).rejects.toThrow("denied");
		expect(state.redirect).not.toHaveBeenCalled();
	});
});
