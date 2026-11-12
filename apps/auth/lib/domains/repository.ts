import { randomBytes, randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import type { Pool, PoolClient } from "pg";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectRegistryPool } from "../projects/registry";
import type { Project } from "../projects/registry";
import { requireWorkspaceActor } from "../workspaces/authorization";
import type { WorkspaceDatabase } from "../workspaces/authorization";
import { workspaceAudit } from "../workspaces/repository";
import { cloudflareHostnameProvider, provesOwnership, publicDomainDns, routesToTarget } from "./provider";
import { customerDomain, domainDefaults, domainInfrastructure, domainInput, ownershipRecord } from "./validation";
import type { ActiveHostname, DomainDns, DomainInfrastructure, DomainIssue, DomainList, DomainStatus, HostnameProvider, ProviderHostname, PublicCustomHostname, PublicDomainPair, StoredCustomHostname, StoredDomainPair } from "./types";

export interface DomainDependencies { pool?: Pool; dns?: DomainDns; provider?: HostnameProvider; onRoutingChanged?: (project: Project, database: PoolClient) => Promise<void> }
async function authorizedProject(principal: ControlPrincipal, identifier: string, env: AuthEnvironment, database: WorkspaceDatabase): Promise<Project> {
	if (!/^[a-zA-Z0-9-]{2,64}$/.test(identifier)) throw new APIError("NOT_FOUND");
	const field = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(identifier) ? "id" : "slug";
	const project = (await database.query<Project>(`SELECT * FROM public."allauthProject" WHERE ${field}=$1 LIMIT 1`, [identifier])).rows[0];
	if (!project) throw new APIError("NOT_FOUND");
	await requireWorkspaceActor(principal, project.workspaceId, env, { database });
	return project;
}
export function publicDomainHostname(host: StoredCustomHostname, pair: StoredDomainPair, infrastructure: DomainInfrastructure): PublicCustomHostname {
	let status: DomainStatus = "pending";
	let issue = host.lastIssue;
	if (pair.deleting) { status = "deleting"; issue ||= "cleanup-pending"; }
	else if (!infrastructure.configured) { status = "unconfigured"; issue = "infrastructure-required"; }
	else if (!host.ownershipVerifiedAt) issue = "ownership-required";
	else if (host.providerStatus === "active" && host.sslStatus === "active" && host.routingVerifiedAt && !host.lastIssue) { status = "active"; issue = null; }
	const records = [ownershipRecord(host.hostname, host.proofToken), ...host.validationRecords];
	if (infrastructure.cnameTarget) records.push({ type: "CNAME", name: host.hostname, value: infrastructure.cnameTarget, purpose: "routing" });
	return { id: host.id, kind: host.kind, hostname: host.hostname, status, issue, ownershipVerifiedAt: host.ownershipVerifiedAt?.toISOString() || null, routingVerifiedAt: host.routingVerifiedAt?.toISOString() || null, checkedAt: host.checkedAt?.toISOString() || null, providerStatus: host.providerStatus, certificateStatus: host.sslStatus, records };
}
export function publicDomainPair(pair: StoredDomainPair, hosts: StoredCustomHostname[], infrastructure: DomainInfrastructure): PublicDomainPair {
	const hostnames = hosts.map((host) => publicDomainHostname(host, pair, infrastructure));
	const status: DomainStatus = pair.deleting ? "deleting" : !infrastructure.configured ? "unconfigured" : hostnames.length === 2 && hostnames.every((host) => host.status === "active") ? "active" : "pending";
	return { id: pair.id, projectId: pair.projectId, domain: pair.domain, status, createdAt: pair.createdAt.toISOString(), updatedAt: pair.updatedAt.toISOString(), hostnames };
}
async function hostsFor(database: WorkspaceDatabase, pairId: string): Promise<StoredCustomHostname[]> { return (await database.query<StoredCustomHostname>('SELECT * FROM public."allauthCustomHostname" WHERE "pairId"=$1 ORDER BY kind', [pairId])).rows; }
async function pairFor(database: WorkspaceDatabase, id: string, projectId: string): Promise<StoredDomainPair> {
	const pair = (await database.query<StoredDomainPair>('SELECT * FROM public."allauthDomainPair" WHERE id=$1 AND "projectId"=$2', [id, projectId])).rows[0];
	if (!pair) throw new APIError("NOT_FOUND", { message: "Domain not found in this application environment." });
	return pair;
}
export async function listProjectDomains(principal: ControlPrincipal, identifier: string, env: AuthEnvironment, dependencies: DomainDependencies = {}): Promise<DomainList> {
	const database = dependencies.pool || projectRegistryPool(env); const project = await authorizedProject(principal, identifier, env, database);
	const pairs = (await database.query<StoredDomainPair>('SELECT * FROM public."allauthDomainPair" WHERE "projectId"=$1 ORDER BY "createdAt",id LIMIT 10', [project.id])).rows;
	const infrastructure = domainInfrastructure(env); const domains: PublicDomainPair[] = [];
	for (const pair of pairs) domains.push(publicDomainPair(pair, await hostsFor(database, pair.id), infrastructure));
	return { domains, defaults: domainDefaults(project.slug, env), infrastructure };
}
/** Reserve both exact hostnames atomically before contacting a certificate provider. */
export async function createProjectDomains(principal: ControlPrincipal, identifier: string, input: unknown, env: AuthEnvironment, dependencies: DomainDependencies = {}) {
	const value = domainInput.parse(input); let domain: string;
	try { domain = customerDomain(value.domain, env); } catch { throw new APIError("BAD_REQUEST", { message: "Use a public customer domain outside AllAuth's reserved domains." }); }
	const database = await (dependencies.pool || projectRegistryPool(env)).connect();
	try {
		await database.query("BEGIN");
		const project = await authorizedProject(principal, identifier, env, database);
		await database.query('SELECT id FROM public."allauthProject" WHERE id=$1 FOR UPDATE', [project.id]);
		const existing = (await database.query<StoredDomainPair>('SELECT * FROM public."allauthDomainPair" WHERE "projectId"=$1 AND domain=$2', [project.id, domain])).rows[0];
		if (existing) { const result = publicDomainPair(existing, await hostsFor(database, existing.id), domainInfrastructure(env)); await database.query("COMMIT"); return { domain: result, infrastructure: domainInfrastructure(env) }; }
		if (Number((await database.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM public."allauthDomainPair" WHERE "projectId"=$1', [project.id])).rows[0]!.count) >= 3) throw new APIError("CONFLICT", { message: "This environment has reached its limit of three domain pairs." });
		const id = randomUUID();
		const pair = (await database.query<StoredDomainPair>('INSERT INTO public."allauthDomainPair" (id,"projectId",domain,"createdBy") VALUES ($1,$2,$3,$4) RETURNING *', [id, project.id, domain, principal.user.id])).rows[0]!;
		for (const kind of ["accounts", "frontend-api"] as const) await database.query('INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","lastIssue") VALUES ($1,$2,$3,$4,$5,$6,\'ownership-required\')', [randomUUID(), id, project.id, kind, `${kind}.${domain}`, randomBytes(24).toString("base64url")]);
		await workspaceAudit(database, principal.user.id, "domain.reserved", id, project.workspaceId);
		const result = publicDomainPair(pair, await hostsFor(database, id), domainInfrastructure(env)); await database.query("COMMIT");
		return { domain: result, infrastructure: domainInfrastructure(env) };
	} catch (error) { await database.query("ROLLBACK"); if (error && typeof error === "object" && "code" in error && error.code === "23505") throw new APIError("CONFLICT", { message: "One of these hostnames is already reserved by an application environment." }); throw error; }
	finally { database.release(); }
}
async function recordIssue(database: PoolClient, hosts: StoredCustomHostname[], issue: DomainIssue) {
	for (const host of hosts) { host.lastIssue = issue; await database.query('UPDATE public."allauthCustomHostname" SET "lastIssue"=$1,"checkedAt"=NOW(),"updatedAt"=NOW() WHERE id=$2', [issue, host.id]); }
}
async function saveProvider(database: PoolClient, host: StoredCustomHostname, value: ProviderHostname): Promise<boolean> {
	if (value.hostname !== host.hostname || (host.providerId && value.id !== host.providerId)) { await recordIssue(database, [host], "provider-conflict"); return false; }
	await database.query('UPDATE public."allauthCustomHostname" SET "providerId"=$1,"providerStatus"=$2,"sslStatus"=$3,"validationRecords"=$4::jsonb,"checkedAt"=NOW(),"updatedAt"=NOW() WHERE id=$5', [value.id, value.status, value.sslStatus, JSON.stringify(value.records), host.id]);
	host.providerId = value.id; host.providerStatus = value.status; host.sslStatus = value.sslStatus; host.validationRecords = value.records;
	return true;
}
/** A session advisory lock serializes quota use and reconciliation without rolling back persisted external-operation intent. */
async function providerLock<T>(env: AuthEnvironment, dependencies: DomainDependencies, action: (database: PoolClient) => Promise<T>): Promise<T> {
	const database = await (dependencies.pool || projectRegistryPool(env)).connect();
	try { await database.query("SELECT pg_advisory_lock(hashtext('allauth-custom-hostnames'))"); return await action(database); }
	finally { try { await database.query("SELECT pg_advisory_unlock(hashtext('allauth-custom-hostnames'))"); } finally { database.release(); } }
}
export function hasIncludedCapacity(quota: Awaited<ReturnType<HostnameProvider["quota"]>>, needed: number): boolean {
	const maximum = Math.min(100, quota.allocated, quota.hardCap ?? 100);
	return !quota.exceeded && needed >= 0 && quota.used + needed <= maximum;
}
/** Refresh proofs, reconcile uncertain POSTs, and create only inside the included hostname allocation. */
export async function verifyProjectDomains(principal: ControlPrincipal, identifier: string, domainId: string, env: AuthEnvironment, dependencies: DomainDependencies = {}) {
	return providerLock(env, dependencies, async (database) => {
		const project = await authorizedProject(principal, identifier, env, database); const pair = await pairFor(database, domainId, project.id); const hosts = await hostsFor(database, pair.id); const infrastructure = domainInfrastructure(env);
		const result = async () => { await dependencies.onRoutingChanged?.(project, database); return { domain: publicDomainPair(await pairFor(database, pair.id, project.id), await hostsFor(database, pair.id), infrastructure), infrastructure }; };
		if (pair.deleting) return result();
		const dns = dependencies.dns || publicDomainDns(); let allProved = hosts.length === 2;
		for (const host of hosts) {
			const record = ownershipRecord(host.hostname, host.proofToken); const proved = await provesOwnership(dns, record.name, record.value);
			await database.query('UPDATE public."allauthCustomHostname" SET "ownershipVerifiedAt"=CASE WHEN $1 THEN NOW() ELSE NULL END,"routingVerifiedAt"=NULL,"lastIssue"=$2,"checkedAt"=NOW(),"updatedAt"=NOW() WHERE id=$3', [proved, proved ? null : "ownership-required", host.id]);
			allProved &&= proved;
		}
		if (!allProved) return result();
		if (!infrastructure.configured) { await recordIssue(database, hosts, "infrastructure-required"); return result(); }
		const provider = dependencies.provider || cloudflareHostnameProvider(env);
		try {
			for (const host of hosts) {
				if (host.providerId) {
					const registered = await provider.get(host.providerId);
					if (registered) { if (!await saveProvider(database, host, registered)) return result(); }
					else { await database.query('UPDATE public."allauthCustomHostname" SET "providerId"=NULL,"providerAttemptedAt"=NULL,"providerStatus"=NULL,"sslStatus"=NULL,"validationRecords"=\'[]\'::jsonb WHERE id=$1', [host.id]); host.providerId = null; host.providerAttemptedAt = null; }
				}
				if (!host.providerId) {
					const registered = await provider.find(host.hostname);
					if (registered) {
						if (!host.providerAttemptedAt) { await recordIssue(database, [host], "provider-conflict"); return result(); }
						if (!await saveProvider(database, host, registered)) return result();
					}
				}
			}
			const missing = hosts.filter((host) => !host.providerId);
			if (missing.length && !hasIncludedCapacity(await provider.quota(), missing.length)) { await recordIssue(database, missing, "quota-exhausted"); return result(); }
			for (const host of missing) {
				await authorizedProject(principal, identifier, env, database);
				if (!hasIncludedCapacity(await provider.quota(), 1)) { await recordIssue(database, [host], "quota-exhausted"); return result(); }
				// Commit the intent before POST so a timeout/crash can be reconciled without duplicate registrations.
				await database.query('UPDATE public."allauthCustomHostname" SET "providerAttemptedAt"=NOW(),"lastIssue"=\'provider-unavailable\',"updatedAt"=NOW() WHERE id=$1', [host.id]); host.providerAttemptedAt = new Date();
				let registered: ProviderHostname;
				try { registered = await provider.create(host.hostname); }
				catch { const reconciled = await provider.find(host.hostname); if (!reconciled) throw new Error("Domain registration outcome requires retry."); registered = reconciled; }
				if (!await saveProvider(database, host, registered)) return result();
			}
			for (const host of hosts) {
				const routed = await routesToTarget(dns, host.hostname, infrastructure.cnameTarget!);
				const issue = !routed ? "routing-required" : host.providerStatus !== "active" || host.sslStatus !== "active" ? "certificate-pending" : null;
				await database.query('UPDATE public."allauthCustomHostname" SET "routingVerifiedAt"=CASE WHEN $1 THEN NOW() ELSE NULL END,"lastIssue"=$2,"checkedAt"=NOW(),"updatedAt"=NOW() WHERE id=$3', [routed, issue, host.id]);
			}
			await database.query('UPDATE public."allauthDomainPair" SET "updatedAt"=NOW() WHERE id=$1', [pair.id]);
			await workspaceAudit(database, principal.user.id, "domain.checked", pair.id, project.workspaceId);
		} catch (error) { if (error instanceof APIError && [401, 403, 404].includes(error.statusCode)) throw error; await recordIssue(database, hosts, "provider-unavailable"); }
		return result();
	});
}
/** Deactivate first, retain reservations on uncertain cleanup, and remove only exact provider IDs owned by this pair. */
export async function deleteProjectDomains(principal: ControlPrincipal, identifier: string, domainId: string, env: AuthEnvironment, dependencies: DomainDependencies = {}) {
	return providerLock(env, dependencies, async (database) => {
		const project = await authorizedProject(principal, identifier, env, database); const pair = await pairFor(database, domainId, project.id); const hosts = await hostsFor(database, pair.id); const infrastructure = domainInfrastructure(env);
		await database.query('UPDATE public."allauthDomainPair" SET deleting=true,"updatedAt"=NOW() WHERE id=$1', [pair.id]);
		await dependencies.onRoutingChanged?.(project, database);
		const pending = async () => ({ success: false, domain: publicDomainPair(await pairFor(database, pair.id, project.id), await hostsFor(database, pair.id), infrastructure), infrastructure });
		if (hosts.some((host) => host.providerId || host.providerAttemptedAt)) {
			if (!infrastructure.configured) { await recordIssue(database, hosts, "cleanup-pending"); return pending(); }
			const provider = dependencies.provider || cloudflareHostnameProvider(env);
			try {
				for (const host of hosts) {
					const registered = host.providerId ? await provider.get(host.providerId) : host.providerAttemptedAt ? await provider.find(host.hostname) : null;
					if (registered) {
						if (registered.hostname !== host.hostname || (host.providerId && registered.id !== host.providerId)) { await recordIssue(database, [host], "provider-conflict"); return pending(); }
						await authorizedProject(principal, identifier, env, database); await provider.remove(registered.id);
						if (await provider.get(registered.id)) { await recordIssue(database, [host], "cleanup-pending"); return pending(); }
					}
					await database.query('UPDATE public."allauthCustomHostname" SET "providerId"=NULL,"providerAttemptedAt"=NULL,"providerStatus"=NULL,"sslStatus"=NULL,"routingVerifiedAt"=NULL,"updatedAt"=NOW() WHERE id=$1', [host.id]);
				}
			} catch (error) { if (error instanceof APIError && [401, 403, 404].includes(error.statusCode)) throw error; await recordIssue(database, hosts, "cleanup-pending"); return pending(); }
		}
		await database.query("BEGIN");
		try { await authorizedProject(principal, identifier, env, database); await database.query('DELETE FROM public."allauthDomainPair" WHERE id=$1 AND "projectId"=$2', [pair.id, project.id]); await workspaceAudit(database, principal.user.id, "domain.deleted", pair.id, project.workspaceId); await database.query("COMMIT"); }
		catch (error) { await database.query("ROLLBACK"); throw error; }
		return { success: true };
	});
}
const activeHostnamePairs = `FROM public."allauthCustomHostname" h
	JOIN public."allauthDomainPair" d ON d.id=h."pairId" AND d."projectId"=h."projectId"
	JOIN public."allauthProject" p ON p.id=h."projectId"
	WHERE NOT d.deleting AND (SELECT COUNT(*) FROM public."allauthCustomHostname" s
		WHERE s."pairId"=d.id AND s."ownershipVerifiedAt" IS NOT NULL AND s."providerStatus"='active'
			AND s."sslStatus"='active' AND s."routingVerifiedAt" IS NOT NULL AND s."lastIssue" IS NULL)=2`;

/** Read saved active accounts names even when deployment hosting settings are missing. */
export async function listStoredActiveProjectAccountsHostnames(
	projectId: string,
	database: WorkspaceDatabase,
): Promise<string[]> {
	const { rows } = await database.query<{ hostname: string }>(
		`SELECT h.hostname ${activeHostnamePairs} AND p.id=$1 AND h.kind='accounts' ORDER BY h.hostname`,
		[projectId],
	);
	return rows.map(({ hostname }) => hostname);
}

/** Only a completely active pair can select a tenant; caller-supplied origin headers are not authority. */
export async function lookupActiveHostname(hostname: string, env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<ActiveHostname | null> {
	if (!domainInfrastructure(env).configured) return null;
	const { rows: [row] } = await database.query<Project & { domainKind: StoredCustomHostname["kind"]; domainId: string }>(
		`SELECT p.*,h.kind AS "domainKind",h."pairId" AS "domainId" ${activeHostnamePairs} AND h.hostname=$1 LIMIT 1`,
		[hostname],
	);
	if (!row) return null;
	const { domainKind: kind, domainId, ...project } = row;
	return { project, kind, domainId, source: "custom" };
}
