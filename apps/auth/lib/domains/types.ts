import type { Project } from "../projects/registry";

export type DomainKind = "accounts" | "frontend-api";
export type DomainStatus = "unconfigured" | "pending" | "active" | "deleting";
export type DomainIssue = "ownership-required" | "infrastructure-required" | "provider-unavailable" | "quota-exhausted" | "provider-conflict" | "routing-required" | "certificate-pending" | "cleanup-pending";
export interface DomainRecord { type: "TXT" | "CNAME"; name: string; value: string; purpose: "ownership" | "certificate" | "routing" }
export interface DomainInfrastructure { configured: boolean; missing: string[]; hostnameLimit: 100; cnameTarget: string | null }
export interface StoredDomainPair { id: string; projectId: string; domain: string; deleting: boolean; createdBy: string | null; createdAt: Date; updatedAt: Date }
export interface StoredCustomHostname {
	id: string; pairId: string; projectId: string; kind: DomainKind; hostname: string; proofToken: string;
	ownershipVerifiedAt: Date | null; providerId: string | null; providerAttemptedAt: Date | null;
	providerStatus: string | null; sslStatus: string | null; validationRecords: DomainRecord[];
	routingVerifiedAt: Date | null; checkedAt: Date | null; lastIssue: DomainIssue | null; createdAt: Date; updatedAt: Date;
}
export interface PublicCustomHostname {
	id: string; kind: DomainKind; hostname: string; status: DomainStatus; issue: DomainIssue | null;
	ownershipVerifiedAt: string | null; routingVerifiedAt: string | null; checkedAt: string | null;
	providerStatus: string | null; certificateStatus: string | null; records: DomainRecord[];
}
export interface PublicDomainPair { id: string; projectId: string; domain: string; status: DomainStatus; createdAt: string; updatedAt: string; hostnames: PublicCustomHostname[] }
export interface DomainList { domains: PublicDomainPair[]; defaults: { accounts: string; frontendApi: string }; infrastructure: DomainInfrastructure }
/** Internal routing lookup. The project includes private server configuration and must never be serialized. */
export interface ActiveHostname { project: Project; kind: DomainKind; domainId: string; source: "custom" }
export interface ProviderHostname { id: string; hostname: string; status: string; sslStatus: string | null; records: DomainRecord[] }
export interface HostnameProvider {
	quota(): Promise<{ allocated: number; used: number; exceeded: boolean; hardCap: number | null }>;
	find(hostname: string): Promise<ProviderHostname | null>;
	get(id: string): Promise<ProviderHostname | null>;
	create(hostname: string): Promise<ProviderHostname>;
	remove(id: string): Promise<void>;
}
export interface DomainDns { txt(hostname: string): Promise<string[][]>; cname(hostname: string): Promise<string[]> }
