import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import type { SCIMScope } from "@better-auth/scim";
import { APIError } from "better-auth";
import * as z from "zod";
import type { AuthInstance } from "./api";
import { json, requireDirectoryAdministrator, requireSameOrigin } from "./api";
import type { AuthEnvironment } from "./configuration";
import { authOrigin } from "./configuration";
import type { DirectoryBinding } from "./enterprise";
import { provisioningDomain, recordAudit } from "./enterprise";

const scopes = ["scim.users.read", "scim.users.write", "scim.groups.read", "scim.groups.write"] as const satisfies readonly SCIMScope[];
const expiry = () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
const baseURL = (env: AuthEnvironment) => `${authOrigin(env)}/api/auth/scim/v2`;

export async function listDirectories(instance: AuthInstance, request: Request, env: AuthEnvironment, organizationId: string) {
	await requireDirectoryAdministrator(instance, request.headers, organizationId);
	const catalog = await instance.api.listSCIMManagedConnections({ body: { provisioningDomainId: provisioningDomain(organizationId) } });
	const database = (await instance.$context).adapter;
	const connections = await Promise.all(catalog.connections.map(async (connection) => {
		const state = await instance.api.getSCIMManagedConnection({ body: { connectionId: connection.connectionId, provisioningDomainId: provisioningDomain(organizationId) } });
		const binding = await database.findOne<DirectoryBinding>({ model: "allauthDirectory", where: [{ field: "connectionId", value: connection.connectionId }, { field: "organizationId", value: organizationId }] });
		return { ...state, providerId: binding?.providerId };
	}));
	return json({ connections, baseURL: baseURL(env) });
}

export async function createDirectory(instance: AuthInstance, request: Request, env: AuthEnvironment, organizationId: string) {
	requireSameOrigin(request, env);
	const actor = await requireDirectoryAdministrator(instance, request.headers, organizationId);
	const { providerId } = z.object({ providerId: z.string().trim().min(1).max(255) }).strict().parse(await request.json());
	const context = await instance.$context;
	const created = await runWithTransaction(context.adapter, async () => {
		const database = await getCurrentAdapter(context.adapter);
		// Updating the immutable ID locks this exact provider for the directory-binding transaction.
		const provider = await database.update<{ providerId: string }>({ model: "ssoProvider", where: [{ field: "providerId", value: providerId }, { field: "organizationId", value: organizationId }, { field: "domainVerified", value: true }], update: { providerId } });
		if (!provider) throw new APIError("BAD_REQUEST", { message: "Select a verified SSO provider belonging to this organization." });
		if (await database.findOne({ model: "allauthDirectory", where: [{ field: "providerId", value: providerId }] })) throw new APIError("CONFLICT", { message: "This SSO provider already has a directory binding." });
		const value = await instance.api.createSCIMManagedConnection({ body: { creationRequestId: crypto.randomUUID(), provisioningDomainId: provisioningDomain(organizationId), actorId: actor.user.id, scopes, expiresAt: expiry() } });
		await database.create({ model: "allauthDirectory", data: { providerId, organizationId, connectionId: value.connection.connectionId, createdAt: new Date() } });
		await recordAudit(database, { actorId: actor.user.id, action: "directory.created", organizationId, targetId: value.connection.connectionId });
		return value;
	});
	return json({ ...created, baseURL: baseURL(env) }, 201);
}

export async function mutateDirectory(instance: AuthInstance, request: Request, env: AuthEnvironment, organizationId: string, connectionId: string, action: "rotate" | "revoke" | "decommission") {
	requireSameOrigin(request, env);
	const actor = await requireDirectoryAdministrator(instance, request.headers, organizationId);
	const database = (await instance.$context).adapter;
	if (!(await database.findOne({ model: "allauthDirectory", where: [{ field: "connectionId", value: connectionId }, { field: "organizationId", value: organizationId }] }))) throw new APIError("NOT_FOUND");
	const body = { connectionId, provisioningDomainId: provisioningDomain(organizationId), actorId: actor.user.id };
	if (action === "rotate") {
		z.object({}).strict().parse(await request.json());
		const result = await instance.api.rotateSCIMManagedCredential({ body: { ...body, scopes, expiresAt: expiry() } });
		await recordAudit(database, { actorId: actor.user.id, action: "directory.credential.rotated", organizationId, targetId: connectionId });
		return json({ ...result, baseURL: baseURL(env) });
	}
	if (action === "revoke") {
		const { credentialId } = z.object({ credentialId: z.string().min(1).max(255) }).strict().parse(await request.json());
		const result = await instance.api.revokeSCIMManagedCredential({ body: { ...body, credentialId } });
		await recordAudit(database, { actorId: actor.user.id, action: "directory.credential.revoked", organizationId, targetId: credentialId });
		return json(result);
	}
	z.object({}).strict().parse(await request.json());
	const result = await instance.api.decommissionSCIMManagedConnection({ body });
	await recordAudit(database, { actorId: actor.user.id, action: "directory.decommissioned", organizationId, targetId: connectionId });
	return json(result);
}
