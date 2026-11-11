import { createElement, Fragment } from "react";
import type { ComponentProps, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	change: undefined as ((value: string) => void) | undefined,
	value: "",
	disabled: false,
}));

vi.mock("@/components/ui/select", () => ({
	Select: ({ value, disabled, onValueChange, children }: { value: string; disabled?: boolean; onValueChange: (value: string) => void; children: ReactNode }) => {
		state.value = value;
		state.disabled = Boolean(disabled);
		state.change = onValueChange;
		return createElement("div", null, children);
	},
	SelectTrigger: ({ children, ...props }: ComponentProps<"button">) => createElement("button", props, children),
	SelectValue: ({ children }: { children: ReactNode }) => createElement("span", null, children),
	SelectContent: ({ children }: { children: ReactNode }) => createElement("div", null, children),
	SelectItem: ({ value, children }: { value: string; children: ReactNode }) => createElement("span", { "data-option": value }, children),
}));

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";

function choices() {
	return createElement(Fragment, null,
		createElement(AppSelectOption, { value: "", children: "All outcomes" }),
		createElement(AppSelectOption, { value: "success", children: "Successful" }),
		createElement(AppSelectOption, { value: "allauth-value:success", children: "Literal prefix" }),
	);
}

beforeEach(() => { state.change = undefined; state.value = ""; state.disabled = false; });

describe("styled pulldown form and filter boundaries", () => {
	it("preserves a blank filter and emits the original selection including prefix-like values", () => {
		const changed = vi.fn();
		const html = renderToStaticMarkup(createElement(AppSelect, { value: "", onValueChange: changed, children: choices(), "aria-label": "Outcome" }));
		expect(html).toContain("All outcomes");
		expect(html).toContain('type="button"');
		expect(html).toContain('aria-label="Outcome"');
		state.change?.("allauth-value:success");
		expect(changed).toHaveBeenLastCalledWith("success");
		state.change?.("allauth-value:");
		expect(changed).toHaveBeenLastCalledWith("");
		state.change?.("allauth-value:allauth-value:success");
		expect(changed).toHaveBeenLastCalledWith("allauth-value:success");
	});
	it("keeps required raw form values separate from the internal menu encoding", () => {
		const html = renderToStaticMarkup(createElement(AppSelect, { value: "", name: "outcome", required: true, id: "outcome", children: choices() }));
		expect(html).toContain('name="outcome" required=""');
		expect(html).toContain('aria-required="true"');
		expect(html).toContain('<option value="" selected="">All outcomes</option>');
		expect(html).toContain('<option value="success">Successful</option>');
		expect(html).toContain('aria-hidden="true" tabindex="-1"');
	});
	it("renders a controlled label and forwards disabled state to the menu and form control", () => {
		const html = renderToStaticMarkup(createElement(AppSelect, { value: "success", disabled: true, required: true, children: choices() }));
		expect(state.disabled).toBe(true);
		expect(state.value).toBe("allauth-value:success");
		expect(html).toContain("Successful");
		expect(html).toContain('required="" disabled=""');
	});
});
