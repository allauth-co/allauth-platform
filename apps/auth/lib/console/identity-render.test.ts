import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Identity } from "@/components/console/common";

/** @see https://www.better-auth.com/docs/plugins/magic-link#sign-in-with-magic-link */
describe("console identity for passwordless members", () => {
	it.each(["", "   "])("identifies a member with no display name (%j) by email without repeating it", (name) => {
		const html = renderToStaticMarkup(createElement(Identity, { name, email: "member@example.test" }));
		expect(html).toContain("<strong>member@example.test</strong>");
		expect(html).not.toContain("<small>");
		expect(html.match(/member@example[.]test/g)).toHaveLength(1);
		expect(html).toContain('class="console-avatar">ME</span>');
	});
	it("uses the saved trimmed name and keeps email as secondary identity", () => {
		const html = renderToStaticMarkup(createElement(Identity, { name: "  Member Name  ", email: "member@example.test" }));
		expect(html).toContain("<strong>Member Name</strong>");
		expect(html).toContain("<small>member@example.test</small>");
		expect(html).toContain('class="console-avatar">ME</span>');
	});
	it("does not repeat an email used as a display name", () => {
		const html = renderToStaticMarkup(createElement(Identity, { name: "member@example.test", email: "member@example.test" }));
		expect(html).not.toContain("<small>");
	});
	it("has a safe primary label and avatar when both name and email are absent", () => {
		const html = renderToStaticMarkup(createElement(Identity, { name: "  " }));
		expect(html).toContain("<strong>User</strong>");
		expect(html).toContain('class="console-avatar">US</span>');
		expect(html).not.toContain("<small>");
	});
	it("retains the supplied decorative avatar", () => {
		const html = renderToStaticMarkup(createElement(Identity, { name: "", email: "member@example.test", image: "https://assets.example.test/avatar.png" }));
		expect(html).toContain('<img src="https://assets.example.test/avatar.png" alt="" class="console-avatar"/>');
		expect(html).toContain("<strong>member@example.test</strong>");
	});
});
