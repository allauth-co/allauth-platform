import type { ReactElement, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ values: [] as unknown[], index: 0, roleError: false }));
vi.mock("react", async (original) => ({
	...await original<typeof import("react")>(),
	useEffect: () => undefined,
	useState: (initial: unknown) => {
		const index = state.index++;
		if (!(index in state.values)) state.values[index] = initial;
		return [state.values[index], (value: unknown) => { state.values[index] = value; }];
	},
}));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams("selected=selected-org") }));
vi.mock("@tanstack/react-query", () => ({
	useQueryClient: () => ({ invalidateQueries: vi.fn() }),
	useQuery: ({ queryKey }: { queryKey: unknown[] }) => ({
		data: queryKey[0] === "console-organization" ? {
			organization: { id: "selected-org", name: "Selected", slug: "selected", memberCount: 1, teamCount: 0 },
			members: [], teams: [], roles: [{ id: "owner", role: "owner", builtIn: true }, { id: "member", role: "member", builtIn: true }], invitations: [], providers: [], permissionResources: {},
		} : queryKey[0] === "console-organization-role-options" ? [{ id: "member", role: "member", builtIn: true }] : undefined,
		isPending: false,
		isError: queryKey[0] === "console-organization-role-options" && state.roleError,
	}),
}));
import { ConsoleOrganizations } from "@/components/console/organizations";

type Element = ReactElement<Record<string, unknown>>;
function elements(node: ReactNode): Element[] {
	if (Array.isArray(node)) return node.flatMap(elements);
	if (!node || typeof node !== "object" || !("props" in node)) return [];
	const element = node as Element;
	return [element, ...elements(element.props.children as ReactNode)];
}

/** @see ../../components/console/organizations.tsx (owner is not offered by the invitation form) */
describe("organization invitation role selection", () => {
	it("does not carry an owner assignment from the add-member form into an invitation", async () => {
		state.values = []; state.index = 0;
		const drawer = elements(ConsoleOrganizations({ project: "development" })).find((element) => typeof element.type === "function" && element.type.name === "OrganizationDrawer")!;
		const run = vi.fn().mockResolvedValue(true);
		state.values = [];
		const render = () => {
			state.index = 0;
			return elements((drawer.type as (props: Record<string, unknown>) => ReactNode)({ ...drawer.props, run }));
		};
		const memberRole = render().find((element) => element.props.id === "org-member-role")!;
		(memberRole.props.onValueChange as (role: string) => void)("owner");
		const invitationsTab = render().find((element) => element.type === "button" && element.props.children === "Invitations")!;
		(invitationsTab.props.onClick as () => void)();
		const invitationForm = render().find((element) => element.type === "form" && elements(element).some((child) => child.props.id === "org-invite-email"))!;
		(invitationForm.props.onSubmit as (event: { preventDefault: () => void }) => void)({ preventDefault: () => undefined });
		expect(run).toHaveBeenCalledWith("/api/admin/organizations/selected-org/invitations", expect.objectContaining({ action: "send", role: "member" }));
	});
	it("disables assignment after a role refresh fails even when stale options remain cached", () => {
		state.values = []; state.index = 0; state.roleError = true;
		const drawer = elements(ConsoleOrganizations({ project: "development" })).find((element) => typeof element.type === "function" && element.type.name === "OrganizationDrawer")!;
		state.values = []; state.index = 0;
		const controls = elements((drawer.type as (props: Record<string, unknown>) => ReactNode)(drawer.props));
		expect(controls.find((element) => element.props.id === "org-member-role")!.props.disabled).toBe(true);
		state.roleError = false;
	});
});
