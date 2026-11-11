import { describe, expect, it } from "vitest";
import { domainStatusFacts } from "./domain-presentation";

describe("custom-domain status presentation", () => {
	it("does not equate proven ownership with ready routing or TLS", () => {
		const facts = domainStatusFacts({
			status: "pending",
			ownershipVerifiedAt: "2026-10-07T00:00:00Z",
			routingVerifiedAt: null,
			certificateStatus: "pending_validation",
		});
		expect(facts.ownership.ready).toBe(true);
		expect(facts.routing).toEqual({ ready: false, label: "Pending" });
		expect(facts.tls).toEqual({ ready: false, label: "pending validation" });
	});
	it("does not present a deleting hostname as usable despite previous provider status", () => {
		const facts = domainStatusFacts({
			status: "deleting",
			ownershipVerifiedAt: "2026-10-07T00:00:00Z",
			routingVerifiedAt: "2026-10-07T00:00:00Z",
			certificateStatus: "active",
		});
		expect(facts.routing).toEqual({ ready: false, label: "Disabled" });
		expect(facts.tls.ready).toBe(false);
	});
	it("shows each independently confirmed fact when the hostname is active", () => {
		const facts = domainStatusFacts({
			status: "active",
			ownershipVerifiedAt: "2026-10-07T00:00:00Z",
			routingVerifiedAt: "2026-10-07T00:00:00Z",
			certificateStatus: "active",
		});
		expect(Object.values(facts).every((fact) => fact.ready)).toBe(true);
	});
});
