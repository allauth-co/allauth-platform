import { Resolver } from "node:dns/promises";
import { APIError } from "better-auth";
import * as z from "zod";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import type { DomainDns, DomainRecord, HostnameProvider, ProviderHostname } from "./types";
import { domainInfrastructure } from "./validation";

const providerHostname = z.object({ id: z.string().min(1).max(100), hostname: z.string().min(1).max(253), status: z.string().max(100), ownership_verification: z.object({ type: z.string(), name: z.string().max(512), value: z.string().max(2048) }).optional(), ssl: z.object({ status: z.string().max(100).optional(), validation_records: z.array(z.object({ txt_name: z.string().max(512).optional(), txt_value: z.string().max(2048).optional(), txt_record: z.string().max(2048).optional() })).max(20).optional() }).optional() });
function publicProviderHostname(input: unknown): ProviderHostname {
	const value = providerHostname.parse(input);
	const records: DomainRecord[] = [];
	if (value.ownership_verification?.type.toLowerCase() === "txt") records.push({ type: "TXT", name: value.ownership_verification.name, value: value.ownership_verification.value, purpose: "ownership" });
	for (const record of value.ssl?.validation_records || []) if (record.txt_name && (record.txt_value || record.txt_record)) records.push({ type: "TXT", name: record.txt_name, value: record.txt_value || record.txt_record!, purpose: "certificate" });
	return { id: value.id, hostname: value.hostname.toLowerCase(), status: value.status, sslStatus: value.ssl?.status || null, records };
}
/** Zone-scoped certificate credentials stay server-side; provider response bodies never enter errors or logs. */
export type DomainFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export function cloudflareHostnameProvider(env: AuthEnvironment, request: DomainFetch = fetch): HostnameProvider {
	if (!domainInfrastructure(env).configured) throw new APIError("SERVICE_UNAVAILABLE", { message: "Custom-domain infrastructure is not configured." });
	const zone = setting(env, "CLOUDFLARE_SAAS_ZONE_ID");
	const token = setting(env, "CLOUDFLARE_SAAS_API_TOKEN");
	async function call(path: string, method = "GET", body?: unknown, allowMissing = false): Promise<unknown> {
		const response = await request(`https://api.cloudflare.com/client/v4/zones/${zone}/custom_hostnames${path}`, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: "error", signal: AbortSignal.timeout(10000), cache: "no-store" });
		if (response.status === 404 && allowMissing) return null;
		if (!response.ok) throw new APIError("SERVICE_UNAVAILABLE", { message: "The domain provider could not complete this request." });
		const reader = response.body?.getReader(); const chunks: Uint8Array[] = []; let bytes = 0;
		if (!reader) throw new Error("Missing domain provider response.");
		try { for (;;) { const next = await reader.read(); if (next.done) break; bytes += next.value.length; if (bytes > 1_048_576) { await reader.cancel(); throw new Error("Oversized domain provider response."); } chunks.push(next.value); } } finally { reader.releaseLock(); }
		const buffer = new Uint8Array(bytes); let offset = 0; for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.length; }
		const data = z.object({ success: z.literal(true), result: z.unknown() }).parse(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer)));
		return data.result;
	}
	return {
		async quota() { const value = z.object({ allocated: z.number().int().nonnegative(), used: z.number().int().nonnegative(), exceeded: z.boolean(), hard_cap: z.number().int().nonnegative().nullable().optional() }).parse(await call("/quota")); return { allocated: value.allocated, used: value.used, exceeded: value.exceeded, hardCap: value.hard_cap ?? null }; },
		async find(hostname) { const values = z.array(providerHostname).max(100).parse(await call(`?hostname=${encodeURIComponent(hostname)}&per_page=100`)); const exact = values.filter((item) => item.hostname.toLowerCase() === hostname); if (exact.length > 1) throw new Error("Ambiguous domain registration."); return exact[0] ? publicProviderHostname(exact[0]) : null; },
		async get(id) { if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id)) throw new Error("Invalid provider identifier."); const result = await call(`/${id}`, "GET", undefined, true); return result === null ? null : publicProviderHostname(result); },
		async create(hostname) { return publicProviderHostname(await call("", "POST", { hostname, ssl: { method: "txt", type: "dv", settings: { min_tls_version: "1.2" } } })); },
		async remove(id) { if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id)) throw new Error("Invalid provider identifier."); await call(`/${id}`, "DELETE", undefined, true); },
	};
}
export function publicDomainDns(): DomainDns {
	const resolver = new Resolver({ timeout: 3000, tries: 2 });
	return { txt: (hostname) => resolver.resolveTxt(hostname), cname: (hostname) => resolver.resolveCname(hostname) };
}
/** Proof requires the entire TXT value, joining split DNS character strings exactly. */
export async function provesOwnership(dns: DomainDns, name: string, expected: string): Promise<boolean> { try { return (await dns.txt(name)).some((chunks) => chunks.join("") === expected); } catch { return false; } }
/** Accept only a bounded, loop-free CNAME chain ending at the configured SaaS target. */
export async function routesToTarget(dns: DomainDns, hostname: string, target: string): Promise<boolean> {
	const normalize = (value: string) => value.toLowerCase().replace(/\.$/, "");
	const expected = normalize(target); const seen = new Set<string>(); let current = normalize(hostname);
	try { for (let hops = 0; hops < 8; hops++) { if (seen.has(current)) return false; seen.add(current); const records = await dns.cname(current); if (records.length !== 1) return false; current = normalize(records[0]!); if (current === expected) return true; } } catch { return false; }
	return false;
}
