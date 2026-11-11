import type { ReactElement, ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ values: [] as unknown[], index: 0, queries: [] as boolean[] }));
vi.mock("react", async (original) => ({
	...await original<typeof import("react")>(),
	useEffect: () => undefined,
	useState: (initial: unknown) => {
		const index = state.index++;
		if (!(index in state.values)) state.values[index] = initial;
		return [state.values[index], (value: unknown) => { state.values[index] = value; }];
	},
}));
vi.mock("@tanstack/react-query", () => ({
	useQuery: ({ queryKey, enabled }: { queryKey: unknown[]; enabled: boolean }) => {
		state.queries.push(enabled);
		return { data: { members: [{ id: "membership", userId: queryKey[4] ? "new-user" : "existing-user", name: "Member", email: "member@example.com" }], total: 1, limit: 25, offset: 0 } };
	},
}));
import { ConsoleOrganizationTeam } from "@/components/console/organization-team";

type Element = ReactElement<Record<string, unknown>>;
function elements(node: ReactNode): Element[] {
	if (Array.isArray(node)) return node.flatMap(elements);
	if (!node || typeof node !== "object" || !("props" in node)) return [];
	const element = node as Element;
	return [element, ...elements(element.props.children as ReactNode)];
}
function fixture() {
	state.values = []; state.index = 0; state.queries = [];
	const run = vi.fn().mockResolvedValue(true);
	const render = () => {
		state.index = 0;
		return elements(ConsoleOrganizationTeam({ project: "development", organizationId: "selected-org", team: { id: "selected-team", name: "Selected team", memberCount: 1 }, busy: false, run }));
	};
	return { render, run };
}
afterEach(() => vi.unstubAllGlobals());

/** @see ../../components/console/organization-team.tsx (team roster management) */
describe("team membership controls", () => {
	it("loads the roster on demand and identifies the actual member for removal", () => {
		const { render, run } = fixture();
		const disclosure = render().find((element) => element.props.children === "Manage members")!;
		expect(state.queries).toEqual([false, false]);
		expect(disclosure.props["aria-expanded"]).toBe(false);
		(disclosure.props.onClick as () => void)();
		const remove = render().find((element) => element.props["aria-label"] === "Remove member@example.com from Selected team")!;
		expect(state.queries.slice(-2)).toEqual([true, true]);
		vi.stubGlobal("window", { confirm: () => true });
		(remove.props.onClick as () => void)();
		expect(run).toHaveBeenCalledWith("/api/admin/organizations/selected-org/teams", { action: "remove-member", teamId: "selected-team", userId: "existing-user" });
	});
	it("adds the selected nonmember to the exact team and clears the choice only after success", async () => {
		const { render, run } = fixture();
		(render().find((element) => element.props.children === "Manage members")!.props.onClick as () => void)();
		const select = render().find((element) => element.props.id === "team-member-selected-team")!;
		(select.props.onValueChange as (id: string) => void)("new-user");
		const form = render().find((element) => element.type === "form")!;
		(form.props.onSubmit as (event: { preventDefault: () => void }) => void)({ preventDefault: () => undefined });
		expect(run).toHaveBeenCalledWith("/api/admin/organizations/selected-org/teams", { action: "add-member", teamId: "selected-team", userId: "new-user" });
		await Promise.resolve();
		expect(render().find((element) => element.props.id === "team-member-selected-team")!.props.value).toBe("");
	});
	it("cancels a member removal without sending a mutation", () => {
		const { render, run } = fixture();
		(render().find((element) => element.props.children === "Manage members")!.props.onClick as () => void)();
		vi.stubGlobal("window", { confirm: () => false });
		(render().find((element) => element.props.children === "Remove")!.props.onClick as () => void)();
		expect(run).not.toHaveBeenCalled();
	});
});
