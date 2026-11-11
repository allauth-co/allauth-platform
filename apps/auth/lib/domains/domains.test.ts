import { describe, expect, it, vi } from "vitest";
import { cloudflareHostnameProvider, provesOwnership, routesToTarget } from "./provider";
import type { DomainFetch } from "./provider";
import { hasIncludedCapacity, publicDomainPair } from "./repository";
import { canonicalHostname, customerDomain, domainDefaults, domainInfrastructure, ownershipRecord } from "./validation";
import type { DomainDns, StoredCustomHostname, StoredDomainPair } from "./types";

const env = { BETTER_AUTH_URL: "https://allauth.co", CLOUDFLARE_SAAS_ZONE_ID: "a".repeat(32), CLOUDFLARE_SAAS_API_TOKEN: "fixture-token-never-production", CLOUDFLARE_SAAS_CNAME_TARGET: "frontend-api.allauth.co", CLOUDFLARE_SAAS_READY: "true" };
const date = new Date("2026-10-07T00:00:00Z");
const pair: StoredDomainPair = { id: "pair", projectId: "project", domain: "acme-customer.com", deleting: false, createdBy: "owner", createdAt: date, updatedAt: date };
const host = (kind: StoredCustomHostname["kind"], extra: Partial<StoredCustomHostname> = {}): StoredCustomHostname => ({ id: kind, pairId: pair.id, projectId: pair.projectId, kind, hostname: `${kind}.${pair.domain}`, proofToken: "proof", ownershipVerifiedAt: date, providerId: `provider-${kind}`, providerAttemptedAt: date, providerStatus: "active", sslStatus: "active", validationRecords: [], routingVerifiedAt: date, checkedAt: date, lastIssue: null, createdAt: date, updatedAt: date, ...extra });
describe("custom-domain boundaries and factual status", () => {
	it.each(["localhost", "customer.local", "customer.internal", "customer.test", "127.0.0.1", "2130706433", "127.1", "[::1]", "https://customer.com", "customer.com:443", "*.customer.com", "customer.com.", "bad..customer.com", "-bad.customer.com", "foo.workers.dev", "foo.up.railway.app", "cüstomer.com"])('rejects private, ambiguous and reserved hostname %s', (value) => expect(() => canonicalHostname(value)).toThrow());
	it("reserves platform hostnames and derives certificate-compatible flat defaults", () => {
		expect(canonicalHostname("  Acme-Customer.COM ")).toBe("acme-customer.com");
		for (const value of ["allauth.co", "accounts.allauth.co", "nested.accounts.allauth.co"]) expect(() => customerDomain(value, env)).toThrow();
		expect(domainDefaults("acme-production", env)).toEqual({ accounts: "https://acme-production-accounts.allauth.co", frontendApi: "https://acme-production-api.allauth.co" });
	});
	it("requires all infrastructure flags without exposing a configured secret", () => {
		const state = domainInfrastructure({ ...env, CLOUDFLARE_SAAS_READY: "false" }); expect(state.configured).toBe(false); expect(state.missing).toEqual(["CLOUDFLARE_SAAS_READY"]); expect(JSON.stringify(state)).not.toContain(env.CLOUDFLARE_SAAS_API_TOKEN);
	});
	it("never calls a partial pair active or exposes provider IDs/private registry configuration", () => {
		const infrastructure = domainInfrastructure(env);
		for (const extra of [{ sslStatus: "pending_validation" }, { providerStatus: "pending" }, { routingVerifiedAt: null }, { ownershipVerifiedAt: null }, { lastIssue: "provider-unavailable" as const }]) expect(publicDomainPair(pair, [host("accounts"), host("frontend-api", extra)], infrastructure).status).toBe("pending");
		expect(publicDomainPair(pair, [host("accounts")], infrastructure).status).toBe("pending");
		expect(publicDomainPair(pair, [host("accounts"), host("frontend-api")], infrastructure).status).toBe("active");
		expect(publicDomainPair({ ...pair, deleting: true }, [host("accounts"), host("frontend-api")], infrastructure).status).toBe("deleting");
		const serialized = JSON.stringify(publicDomainPair(pair, [host("accounts"), host("frontend-api")], infrastructure)); expect(serialized).not.toContain('"providerId"'); expect(serialized).not.toContain("brokerSecret");
	});
	/** @see https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/quotas-and-billing/ */
	it("accounts for pending provider entries and rejects any creation beyond the included allocation", () => {
		expect(hasIncludedCapacity({ allocated: 100, used: 98, exceeded: false, hardCap: 50000 }, 2)).toBe(true);
		expect(hasIncludedCapacity({ allocated: 100, used: 99, exceeded: false, hardCap: 50000 }, 2)).toBe(false);
		expect(hasIncludedCapacity({ allocated: 1000, used: 100, exceeded: false, hardCap: 50000 }, 1)).toBe(false);
		expect(hasIncludedCapacity({ allocated: 100, used: 90, exceeded: false, hardCap: 90 }, 1)).toBe(false);
		expect(hasIncludedCapacity({ allocated: 100, used: 20, exceeded: true, hardCap: null }, 1)).toBe(false);
	});
	it("requires exact TXT proof, supports DNS chunking, and fails closed on lookup failures", async () => {
		const record = ownershipRecord("accounts.acme-customer.com", "private-proof");
		const dns: DomainDns = { txt: async () => [["allauth-domain=", "private-proof"]], cname: async () => [] };
		expect(await provesOwnership(dns, record.name, record.value)).toBe(true);
		expect(await provesOwnership(dns, record.name, `${record.value}x`)).toBe(false);
		expect(await provesOwnership({ ...dns, txt: async () => { throw new Error("lookup unavailable"); } }, record.name, record.value)).toBe(false);
	});
	it("checks a canonical CNAME chain and rejects loops, multiple targets, misses and excessive hops", async () => {
		const chain = new Map([["accounts.acme-customer.com", ["alias.acme-customer.com."]], ["alias.acme-customer.com", ["FRONTEND-API.ALLAUTH.CO."]]]);
		const dns: DomainDns = { txt: async () => [], cname: async (name) => chain.get(name) || [] };
		expect(await routesToTarget(dns, "accounts.acme-customer.com", "frontend-api.allauth.co")).toBe(true);
		chain.set("alias.acme-customer.com", ["accounts.acme-customer.com"]); expect(await routesToTarget(dns, "accounts.acme-customer.com", "frontend-api.allauth.co")).toBe(false);
		chain.set("alias.acme-customer.com", ["frontend-api.allauth.co", "attacker.com"]); expect(await routesToTarget(dns, "accounts.acme-customer.com", "frontend-api.allauth.co")).toBe(false);
	});
});
describe("narrow Cloudflare provider protocol", () => {
	it("reads the actual quota boolean shape and projects only validation records", async () => {
		const request = vi.fn<DomainFetch>(async (input) => Response.json({ success: true, result: String(input).endsWith("/quota") ? { allocated: 100, used: 1, exceeded: false, hard_cap: 50000 } : { id: "provider-id", hostname: "accounts.acme-customer.com", status: "pending", ownership_verification: { type: "txt", name: "_cf-custom-hostname.accounts.acme-customer.com", value: "cf-proof" }, ssl: { status: "pending_validation", private_key: "must-not-escape", validation_records: [{ txt_name: "_acme-challenge.accounts.acme-customer.com", txt_value: "certificate-proof" }] } } }));
		const provider = cloudflareHostnameProvider(env, request);
		expect(await provider.quota()).toEqual({ allocated: 100, used: 1, exceeded: false, hardCap: 50000 });
		const created = await provider.create("accounts.acme-customer.com"); expect(created.records).toHaveLength(2); expect(JSON.stringify(created)).not.toContain("must-not-escape");
		const [, options] = request.mock.calls[1]!; expect(options?.redirect).toBe("error"); expect(JSON.parse(String(options?.body))).toEqual({ hostname: "accounts.acme-customer.com", ssl: { method: "txt", type: "dv", settings: { min_tls_version: "1.2" } } });
	});
	it("does not echo provider error bodies and performs no calls when unconfigured", async () => {
		const request = vi.fn<DomainFetch>(async () => new Response("provider body with secret-token", { status: 403 }));
		await expect(cloudflareHostnameProvider(env, request).quota()).rejects.toThrow("The domain provider could not complete this request.");
		expect(() => cloudflareHostnameProvider({ ...env, CLOUDFLARE_SAAS_API_TOKEN: "" }, request)).toThrow("Custom-domain infrastructure is not configured."); expect(request).toHaveBeenCalledTimes(1);
	});
});
