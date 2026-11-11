import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { defaultSecurityPolicy } from "@/lib/control/security";
import { ControlSecurity } from "./security";

const state = vi.hoisted(() => ({ mode: "monitor" as "monitor" | "enforce", breachedPasswords: true }));
vi.mock("@tanstack/react-query", () => ({
	useQueryClient: () => ({}),
	useQuery: () => ({
		data: {
			policy: { ...defaultSecurityPolicy, mode: state.mode },
			rules: [],
			stats: { blockedRequests: 0, last24hFailures: 0, activeRules: 0 },
			capabilities: { credentialStuffing: true, velocity: true, blockRules: true, newDeviceNotifications: false, botChallenge: false, impossibleTravel: false, breachedPasswords: state.breachedPasswords },
		},
	}),
}));

/** @see ../../PLUGINS.md#oauth-schema-and-security */
describe("accurate security coverage", () => {
	it("keeps independently enforced password checks active during abuse monitoring", () => {
		state.mode = "monitor";
		state.breachedPasswords = true;
		const html = renderToStaticMarkup(createElement(ControlSecurity));
		const passwordCoverage = html.slice(html.indexOf("Breached-password checks"));
		expect(passwordCoverage).toContain("Active");
		expect(passwordCoverage).not.toContain("Monitoring");
		expect(passwordCoverage).not.toContain("lookup is not configured");
	});
	it("does not advertise password protection when the server reports it absent", () => {
		state.breachedPasswords = false;
		const html = renderToStaticMarkup(createElement(ControlSecurity));
		expect(html.slice(html.indexOf("Breached-password checks"))).toContain("Not active");
	});
});
