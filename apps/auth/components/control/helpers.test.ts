import { describe, expect, it } from "vitest";
import {
	auditQuery,
	controlQueryScope,
	dateToISO,
	emptyAuditFilters,
	pageRange,
	managementHref,
	projectFromSearch,
	parseEmailDomains,
	sessionQuery,
} from "./helpers";

describe("control activity filters", () => {
	it("partitions project data and invalidation from the default platform", () => {
		expect(controlQueryScope()).toEqual(["control", null]);
		expect(controlQueryScope("app-one")).toEqual(["control", "app-one"]);
		expect(controlQueryScope("app-one")).not.toEqual(
			controlQueryScope("app-two"),
		);
	});
	it("preserves project selection in navigation and rejects ambiguous duplicate selection", () => {
		expect(managementHref("/admin/overview", "app-one")).toBe(
			"/admin/overview?project=app-one",
		);
		expect(managementHref("/admin/overview", "")).toBe(
			"/admin/overview?project=",
		);
		expect(projectFromSearch(undefined)).toBeUndefined();
		expect(projectFromSearch(["app-one", "app-two"])).toBe("app-one,app-two");
	});
	it("keeps admin scope and encodes searches without creating extra filters", () => {
		const query = new URLSearchParams(
			auditQuery(
				{ ...emptyAuditFilters, q: " owner &scope=user ", userId: " user-1 " },
				25,
			),
		);
		expect(query.get("scope")).toBe("admin");
		expect(query.getAll("scope")).toHaveLength(1);
		expect(query.get("q")).toBe("owner &scope=user");
		expect(query.get("userId")).toBe("user-1");
		expect(query.get("offset")).toBe("25");
		expect(query.has("from")).toBe(false);
	});
	it("preserves exact UTC date boundaries and rejects reversed ranges", () => {
		const from = "2026-10-07T01:00:00Z";
		const to = "2026-10-07T02:00:00Z";
		const query = new URLSearchParams(
			auditQuery({ ...emptyAuditFilters, from, to }, 0),
		);
		expect(query.get("from")).toBe("2026-10-07T01:00:00.000Z");
		expect(query.get("to")).toBe("2026-10-07T02:00:00.000Z");
		expect(() =>
			auditQuery({ ...emptyAuditFilters, from: to, to: from }, 0),
		).toThrow("start time");
	});
	it("rejects invalid date filters instead of dropping them silently", () => {
		expect(() => dateToISO("not a date")).toThrow("valid date");
		expect(dateToISO("")).toBeUndefined();
	});
	it("keeps exact session user filters with bounded page size", () => {
		const query = new URLSearchParams(
			sessionQuery(" device ", " owner-id ", 50),
		);
		expect(Object.fromEntries(query)).toEqual({
			limit: "25",
			offset: "50",
			q: "device",
			userId: "owner-id",
		});
	});
	it("shows actual returned row counts and handles an empty later page", () => {
		expect(pageRange(53, 50, 3)).toBe("51–53 of 53");
		expect(pageRange(12, 25, 0)).toBe("0 of 12");
		expect(pageRange(0, 0, 0)).toBe("0 of 0");
	});
});

describe("blocked email domain entry", () => {
	it("normalizes and deduplicates exact domains", () => {
		expect(
			parseEmailDomains(" Example.COM\nexample.com, login.example.com "),
		).toEqual(["example.com", "login.example.com"]);
	});
	it("accepts IDN domains using the server's canonical ASCII representation", () => {
		expect(parseEmailDomains("bücher.example")).toEqual([
			"xn--bcher-kva.example",
		]);
	});
	it.each([
		"user@example.com",
		"https://example.com",
		"*.example.com",
		"127.0.0.1",
		"example.com:443",
		"example.com/path",
		"bad domain.com",
	])("rejects unsafe or non-domain entry %s", (value) => {
		expect(() => parseEmailDomains(value)).toThrow();
	});
	it("counts unique domains against the server limit", () => {
		expect(() =>
			parseEmailDomains(
				Array.from(
					{ length: 201 },
					(_, index) => `domain${index}.example`,
				).join("\n"),
			),
		).toThrow("200");
	});
});

it("keeps drilldown query and fragment when selecting an environment", () => {
	expect(
		managementHref("/admin/users?selected=user-id#details", "my-app"),
	).toBe("/admin/users?selected=user-id&project=my-app#details");
	expect(
		managementHref("/admin/users?project=old&selected=user-id", "my-app"),
	).toBe("/admin/users?project=my-app&selected=user-id");
});
