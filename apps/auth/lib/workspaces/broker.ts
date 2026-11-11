import { AsyncLocalStorage } from "node:async_hooks";
import { tryGetCurrentAuthEndpointContext } from "@better-auth/core/context";
import { APIError } from "better-auth";
import type { AuthInstance } from "../api";
import type { AuthEnvironment } from "../configuration";
import { authOrigin } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { projectInput, projectOrigin } from "../projects/validation";
import type { ProjectInput } from "../projects/validation";
import { requireWorkspaceActor } from "./authorization";
import type { WorkspaceDatabase } from "./authorization";
import { projectRegistryPool } from "../projects/registry";
import type { Project } from "../projects/registry";
import { domainDefaults, domainInfrastructure } from "../domains/validation";

interface BrokerPermit { userId: string; sessionId: string; action: "create" | "delete" | "update"; clientId?: string }
const permits = new AsyncLocalStorage<BrokerPermit>();
const brokerCredentials = new WeakMap<object, { userId: string; sessionId: string; clientId: string }>();
export interface WorkspaceBroker { clientId: string; clientSecret: string }

/** Only the private server helper can permit one fixed native broker operation. HTTP input cannot set this context. */
export function workspaceBrokerPrivilege(user?: { id?: unknown }, session?: { id?: unknown; userId?: unknown }, action?: string): boolean {
	const permit = permits.getStore();
	if (!permit || action !== permit.action || user?.id !== permit.userId || session?.id !== permit.sessionId || session.userId !== permit.userId) return false;
	const endpoint = tryGetCurrentAuthEndpointContext();
	const path = { create: "/admin/oauth2/create-client", delete: "/oauth2/delete-client", update: "/admin/oauth2/update-client" }[permit.action];
	if (endpoint?.path !== path) return false;
	return permit.action === "create" || (endpoint.body as Record<string, unknown> | undefined)?.client_id === permit.clientId;
}
/** Uses the native registration lifecycle with a genuine root session and server-owned broker metadata. */
export async function createWorkspaceBroker(instance: AuthInstance, headers: Headers, principal: ControlPrincipal, workspaceId: string, input: ProjectInput, env: AuthEnvironment): Promise<WorkspaceBroker> {
	const value = projectInput.parse(input);
	if (value.workspaceId && value.workspaceId !== workspaceId) throw new APIError("BAD_REQUEST", { message: "The application workspace must match the selected workspace." });
	if ([value.primaryOrigin, ...value.origins].includes(authOrigin(env))) throw new APIError("BAD_REQUEST", { message: "Choose your app's origin." });
	await requireWorkspaceActor(principal, workspaceId, env);
	const defaults = domainDefaults(value.slug, env);
	const client = await permits.run({ userId: principal.user.id, sessionId: principal.session.id, action: "create" }, () => instance.api.adminCreateOAuthClient({ headers, body: {
		client_name: `${value.name} identity connection`, redirect_uris: [`${value.primaryOrigin}/api/allauth/callback/allauth`, `${defaults.accounts}/api/auth/callback/allauth`, `${defaults.frontendApi}/api/auth/callback/allauth`],
		application_type: value.primaryOrigin.startsWith("http:") ? "native" : "web", token_endpoint_auth_method: "client_secret_basic", grant_types: ["authorization_code"], response_types: ["code"], scope: "openid profile email", require_pkce: true, skip_consent: false,
		metadata: { allauthProjectBroker: value.slug, allauthWorkspaceId: workspaceId, allauthAllowLocalhost: value.primaryOrigin.startsWith("http:") },
	} }));
	if (!client.client_secret) throw new Error("Identity connection did not return a secret.");
	const credentials = { clientId: client.client_id, clientSecret: client.client_secret };
	brokerCredentials.set(credentials, { userId: principal.user.id, sessionId: principal.session.id, clientId: credentials.clientId });
	return credentials;
}
/** Cleanup accepts only the exact credential object returned by this process's creation helper. */
export async function removeUnprovisionedWorkspaceBroker(instance: AuthInstance, headers: Headers, principal: ControlPrincipal, credentials: WorkspaceBroker): Promise<void> {
	const created = brokerCredentials.get(credentials);
	if (!created || created.userId !== principal.user.id || created.sessionId !== principal.session.id || created.clientId !== credentials.clientId) throw new APIError("FORBIDDEN");
	await permits.run({ userId: created.userId, sessionId: created.sessionId, action: "delete", clientId: created.clientId }, () => instance.api.deleteOAuthClient({ headers, body: { client_id: created.clientId } }));
	brokerCredentials.delete(credentials);
}

/** Reconcile only server-owned BFF/default and fully verified custom callback origins for this stored broker. */
export async function updateProjectBrokerRedirects(instance: AuthInstance, headers: Headers, principal: ControlPrincipal, project: Pick<Project, "id">, approvedOrigins: string[], env: AuthEnvironment, database: WorkspaceDatabase = projectRegistryPool(env)): Promise<void> {
	const current = (await database.query<Project>('SELECT * FROM public."allauthProject" WHERE id=$1', [project.id])).rows[0];
	if (!current) throw new APIError("NOT_FOUND");
	await requireWorkspaceActor(principal, current.workspaceId, env, { database });
	const defaults = domainDefaults(current.slug, env);
	const origins = [defaults.accounts, defaults.frontendApi];
	const installed = (await database.query<{ installed: boolean }>("SELECT to_regclass('public.\"allauthCustomHostname\"') IS NOT NULL AS installed")).rows[0]?.installed;
	if (installed && domainInfrastructure(env).configured) {
		const active = (await database.query<{ hostname: string }>('SELECT h.hostname FROM public."allauthCustomHostname" h JOIN public."allauthDomainPair" d ON d.id=h."pairId" WHERE h."projectId"=$1 AND d.deleting=false AND (SELECT COUNT(*) FROM public."allauthCustomHostname" s WHERE s."pairId"=d.id AND s."ownershipVerifiedAt" IS NOT NULL AND s."providerStatus"=\'active\' AND s."sslStatus"=\'active\' AND s."routingVerifiedAt" IS NOT NULL AND s."lastIssue" IS NULL)=2 ORDER BY h.hostname LIMIT 6', [current.id])).rows;
		origins.push(...active.map((host) => `https://${host.hostname}`));
	}
	if (approvedOrigins.length > 8 || approvedOrigins.some((origin) => !origins.includes(origin))) throw new APIError("FORBIDDEN", { message: "Callback origins must be active hostnames owned by this environment." });
	const bffOrigins = [...new Set([current.primaryOrigin, ...current.origins])].map((origin) => projectOrigin.parse(origin));
	if (bffOrigins.length > 11 || bffOrigins.includes(authOrigin(env))) throw new APIError("BAD_REQUEST", { message: "Stored application origins are invalid." });
	const redirects = [...bffOrigins.map((origin) => `${origin}/api/allauth/callback/allauth`), ...origins.map((origin) => `${origin}/api/auth/callback/allauth`)];
	// Preserve unrelated stored bindings: the native update replaces metadata.
	const storedBroker = await (await instance.$context).adapter.findOne<{ metadata?: unknown }>({ model: "oauthClient", where: [{ field: "clientId", value: current.brokerClientId }] });
	if (!storedBroker) throw new APIError("NOT_FOUND");
	const existing: unknown = typeof storedBroker.metadata === "string" ? JSON.parse(storedBroker.metadata) : storedBroker.metadata;
	if (existing !== undefined && existing !== null && (typeof existing !== "object" || Array.isArray(existing))) throw new Error("Stored broker metadata is invalid.");
	// The native hook validates submitted metadata before merging stored client data.
	const metadata = { ...(existing as Record<string, unknown> | null | undefined), allauthProjectBroker: current.slug, allauthWorkspaceId: current.workspaceId, allauthAllowLocalhost: current.environment === "development" && bffOrigins.some(origin => origin.startsWith("http:")) };
	await permits.run({ userId: principal.user.id, sessionId: principal.session.id, action: "update", clientId: current.brokerClientId }, () => instance.api.adminUpdateOAuthClient({ headers, body: { client_id: current.brokerClientId, update: { redirect_uris: redirects, metadata } } }));
}
