import type { ComponentProps, FormEvent, ReactNode } from "react";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsoleProject } from "@/components/console/shell";
import type { ConsoleWorkspace } from "@/components/console/workspace-client";
import { ApplicationCreationPanel } from "@/components/console/application-creation";

const state = vi.hoisted(() => ({
	draft: {
		name: "New app",
		slug: "new-development",
		primaryOrigin: "https://app.example.com",
		origins: "",
		environment: "development",
	},
	submit: undefined as
		| ((event: FormEvent<HTMLFormElement>) => void)
		| undefined,
	request: vi.fn(),
	invalidate: vi.fn(),
}));
vi.mock("react", async () => {
	const actual = await vi.importActual<typeof import("react")>("react");
	return {
		...actual,
		useState: (initial: unknown) =>
			actual.useState(
				initial && typeof initial === "object" && "primaryOrigin" in initial
					? state.draft
					: initial,
			),
	};
});
vi.mock("@tanstack/react-query", () => ({
	useQueryClient: () => ({ invalidateQueries: state.invalidate }),
}));
vi.mock("sonner", () => ({ toast: { error: vi.fn() } }));
vi.mock("@/components/ui/button", () => ({
	Button: (props: ComponentProps<"button">) => createElement("button", props),
}));
vi.mock("@/components/ui/app-select", () => ({
	AppSelect: ({ children }: { children: ReactNode }) => children,
	AppSelectOption: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/components/console/common", async () => {
	const { Children, isValidElement } = await import("react");
	return {
		managementRequest: state.request,
		DetailPanel: ({ children }: { children: ReactNode }) => {
			for (const child of Children.toArray(children)) {
				if (
					isValidElement<{
						onSubmit?: (event: FormEvent<HTMLFormElement>) => void;
					}>(child) &&
					child.type === "form"
				)
					state.submit = child.props.onSubmit;
			}
			return createElement("section", null, children);
		},
	};
});

const workspace: ConsoleWorkspace = {
	id: "12345678-1234-4123-8123-123456789abc",
	name: "Acme",
	slug: "acme",
	role: "owner",
	protected: false,
	createdBy: null,
	createdAt: "2026-10-07",
	updatedAt: "2026-10-07",
	applicationCount: 1,
	environmentCount: 1,
	memberCount: 1,
};
const instance: ConsoleProject = {
	id: "instance",
	applicationId: "22345678-1234-4123-8123-123456789abc",
	workspaceId: workspace.id,
	slug: "existing-development",
	name: "Existing app",
	environment: "development",
	primaryOrigin: "http://localhost:3000",
	origins: [],
	authPath: "/api/auth",
	createdAt: "2026-10-07",
	updatedAt: "2026-10-07",
};
beforeEach(() => {
	state.submit = undefined;
	state.request
		.mockReset()
		.mockResolvedValue({ project: instance, proxySecret: "fixture-once-key" });
	state.invalidate.mockReset().mockResolvedValue(undefined);
});

describe("persisted application creation panel", () => {
	it("only submits after the user's creation action, refreshes both registries and hands off the issued key", async () => {
		const onCreated = vi.fn();
		const html = renderToStaticMarkup(
			createElement(ApplicationCreationPanel, {
				target: { workspace },
				onClose: vi.fn(),
				onCreated,
			}),
		);
		expect(html).toContain('value="Acme"');
		expect(state.request).not.toHaveBeenCalled();
		state.submit?.({
			preventDefault: vi.fn(),
		} as unknown as FormEvent<HTMLFormElement>);
		await vi.waitFor(() =>
			expect(onCreated).toHaveBeenCalledWith({
				project: instance,
				proxySecret: "fixture-once-key",
			}),
		);
		expect(state.request).toHaveBeenCalledWith("/api/admin/projects", {
			method: "POST",
			body: JSON.stringify({
				name: "New app",
				slug: "new-development",
				primaryOrigin: "https://app.example.com",
				origins: [],
				environment: "development",
				workspaceId: workspace.id,
			}),
		});
		expect(state.invalidate.mock.calls).toEqual([
			[{ queryKey: ["platform-projects"] }],
			[{ queryKey: ["console-workspaces"] }],
		]);
	});
	it("adds only the missing environment to the existing application in the same workspace", async () => {
		const onCreated = vi.fn();
		renderToStaticMarkup(
			createElement(ApplicationCreationPanel, {
				target: { workspace, instances: [instance] },
				onClose: vi.fn(),
				onCreated,
			}),
		);
		state.submit?.({
			preventDefault: vi.fn(),
		} as unknown as FormEvent<HTMLFormElement>);
		await vi.waitFor(() => expect(onCreated).toHaveBeenCalled());
		const [, request] = state.request.mock.calls[0]!;
		expect(JSON.parse(request.body)).toMatchObject({
			name: "Existing app",
			environment: "production",
			applicationId: instance.applicationId,
			workspaceId: workspace.id,
		});
	});
});
