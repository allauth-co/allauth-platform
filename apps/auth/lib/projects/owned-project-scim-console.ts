import type { Pool, PoolClient } from "pg";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, isPlatformAdmin, rolesInclude } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import type { HostedBinding } from "../domains/hosting";
import { canonicalHostname } from "../domains/validation";
import { requireWorkspaceActor } from "../workspaces/authorization";
import { createOwnedProjectSCIMDecommission } from "./owned-project-scim-decommission";
import type { OwnedSCIMManagementAuthorization } from "./owned-project-scim-management";
import {
	createOwnedProjectSCIMManagement,
	ownedSCIMManagementPathId,
	withOwnedSCIMManagementTransaction,
} from "./owned-project-scim-management";
import { ownedSCIMManagementFailure } from "./owned-project-scim-management-store";
import type { Project } from "./registry";
import { checkedProjectSchema, projectSlug } from "./validation";

type ProjectIdentity = Pick<
	Project,
	"id" | "schemaName" | "slug" | "workspaceId"
>;
type PrincipalReader = (headers: Headers) => Promise<ControlPrincipal | null>;
export type OwnedProjectSCIMConsoleRoute = { organizationId: string } & (
	| { operation: "list" | "create" }
	| { operation: "rotate" | "revoke" | "decommission"; connectionId: string }
);
export type OwnedProjectSCIMConsole = (
	request: Request,
	route: OwnedProjectSCIMConsoleRoute,
) => Promise<Response>;

export type OwnedProjectSCIMConnector =
	| { kind: "project-path" }
	| {
			kind: "hosted";
			/** Resolve the currently verified server-owned hostname binding. */
			resolve(): Promise<HostedBinding | null>;
	  };

const forbidden = () =>
	ownedSCIMManagementFailure(403, "The request is not permitted.");
const unauthorized = () =>
	ownedSCIMManagementFailure(401, "The request is not permitted.");
const unavailable = () =>
	ownedSCIMManagementFailure(
		503,
		"Directory provisioning is temporarily unavailable.",
	);
const listenerHosts = new Set(["localhost", "127.0.0.1", "0.0.0.0", "[::1]"]);

function bindStandaloneConsoleRequest(request: Request, origin: string) {
	const incoming = new URL(request.url);
	const browserOrigin = request.headers.get("origin");
	if (
		incoming.origin === origin ||
		incoming.protocol !== "http:" ||
		!listenerHosts.has(incoming.hostname) ||
		(browserOrigin !== null && browserOrigin !== origin)
	)
		return request;
	// The standalone listener can supply its local URL. Browser authority is still
	// verified against the configured console origin and the live workspace session.
	const bound = new URL(origin);
	bound.pathname = incoming.pathname;
	bound.search = incoming.search;
	return new Request(bound, request);
}

function matchingRoute(
	request: Request,
	route: OwnedProjectSCIMConsoleRoute,
	project: ProjectIdentity,
	origin: string,
) {
	const url = new URL(request.url);
	const selected = url.searchParams.getAll("project");
	const parts =
		/^\/api\/organizations\/([^/]+)\/scim(?:\/([^/]+)\/(rotate|revoke|decommission))?$/.exec(
			url.pathname,
		);
	if (
		!parts ||
		url.origin !== origin ||
		selected.length !== 1 ||
		selected[0] !== project.slug ||
		ownedSCIMManagementPathId(parts[1]!, 242) !== route.organizationId ||
		request.method !== (route.operation === "list" ? "GET" : "POST")
	)
		return false;
	if (!("connectionId" in route)) return !parts[2];
	return Boolean(
		parts[2] &&
			parts[3] === route.operation &&
			ownedSCIMManagementPathId(parts[2], 255) === route.connectionId,
	);
}

async function connectorURL(
	connector: OwnedProjectSCIMConnector,
	project: ProjectIdentity,
	origin: string,
) {
	if (connector.kind === "project-path")
		return `${origin}/api/projects/${project.slug}/auth/scim/v2`;
	const binding = await connector.resolve();
	if (
		!binding ||
		binding.project.id !== project.id ||
		binding.project.slug !== project.slug ||
		binding.project.schemaName !== project.schemaName ||
		binding.project.workspaceId !== project.workspaceId ||
		(binding.kind !== "accounts" && binding.kind !== "frontend-api")
	)
		throw unavailable();
	let hostname: string;
	try {
		hostname = canonicalHostname(binding.hostname);
	} catch {
		throw unavailable();
	}
	if (hostname !== binding.hostname) throw unavailable();
	return `https://${hostname}/api/auth/scim/v2`;
}

async function projectDirectoryRole(
	client: Pick<PoolClient, "query">,
	principal: ControlPrincipal,
	organizationId: string,
) {
	const result = await client.query<{
		allowed: boolean;
		role: string | null;
		userRole: string | null;
	}>(
		`SELECT u.role AS "userRole", m.role,
		 (u."emailVerified" AND NOT COALESCE(u.banned,false) AND NOT COALESCE(u."isAnonymous",false)
		  AND NOT COALESCE(u."directoryDisabled",false) AND s."impersonatedBy" IS NULL) AS allowed
		 FROM "session" s JOIN "user" u ON u.id = s."userId"
		 LEFT JOIN "member" m ON m."userId" = u.id AND m."organizationId" = $3
		 WHERE s.id = $1 AND u.id = $2 AND s."expiresAt" > statement_timestamp()`,
		[principal.session.id, principal.user.id, organizationId],
	);
	if (!result.rowCount) return unauthorized();
	return result.rows.some(
		(row) =>
			row.allowed &&
			(isPlatformAdmin({ emailVerified: true, role: row.userRole }) ||
				rolesInclude(row.role, "owner") ||
				rolesInclude(row.role, "admin")),
	)
		? { actorId: principal.user.id }
		: forbidden();
}

/** Selects the SCIM console operation only after routing chose a project and its engine. */
export function createOwnedProjectSCIMConsole(options: {
	database: Pool;
	env: AuthEnvironment;
	project: ProjectIdentity;
	connector: OwnedProjectSCIMConnector;
	credentialHashSecret: string;
	/** Trusted browser-session readers for the platform and this project. */
	readWorkspacePrincipal: PrincipalReader;
	readProjectPrincipal: PrincipalReader;
}): OwnedProjectSCIMConsole {
	const project = {
		id: options.project.id,
		workspaceId: options.project.workspaceId,
		slug: projectSlug.parse(options.project.slug),
		schemaName: checkedProjectSchema(options.project.schemaName),
	};
	const managementOrigin = authOrigin(options.env);
	const common = {
		database: options.database,
		schemaName: project.schemaName,
		credentialHashSecret: options.credentialHashSecret,
		managementOrigin,
	};

	return async (incoming, route) => {
		const request = bindStandaloneConsoleRequest(incoming, managementOrigin);
		if (!matchingRoute(request, route, project, managementOrigin))
			return forbidden();
		if (
			route.operation !== "list" &&
			request.headers.get("origin") !== managementOrigin
		)
			return ownedSCIMManagementFailure(
				403,
				"A same-origin request is required.",
			);
		if (request.headers.has("authorization")) return forbidden();
		try {
			// Resolve cookies before holding a pool slot. Each operation checks persisted authority in its own transaction.
			const [workspace, local] = await Promise.all([
				options.readWorkspacePrincipal(request.headers),
				options.readProjectPrincipal(request.headers),
			]);
			if (!workspace && !local) return unauthorized();
			const authorize: OwnedSCIMManagementAuthorization = async ({
				client,
				organizationId,
				operation,
			}) => {
				if (
					organizationId !== route.organizationId ||
					operation !== route.operation
				)
					return forbidden();
				const bound = await client.query(
					`SELECT 1 FROM public."allauthProject" WHERE id = $1 AND slug = $2 AND "schemaName" = $3 AND "workspaceId" = $4`,
					[project.id, project.slug, project.schemaName, project.workspaceId],
				);
				if (!bound.rowCount) return forbidden();
				if (workspace) {
					try {
						await requireWorkspaceActor(
							workspace,
							project.workspaceId,
							options.env,
							{ database: client },
						);
						return { actorId: workspace.user.id };
					} catch (error) {
						if (
							!error ||
							typeof error !== "object" ||
							!("statusCode" in error) ||
							(error.statusCode !== 401 &&
								error.statusCode !== 403 &&
								error.statusCode !== 404)
						)
							throw error;
					}
				}
				if (!local || local.session.userId !== local.user.id)
					return unauthorized();
				return projectDirectoryRole(client, local, organizationId);
			};
			// Check authority before resolving a connector or reading the body. The operation checks it again with its own scoped transaction.
			const admission = await withOwnedSCIMManagementTransaction(
				options.database,
				project.schemaName,
				true,
				(client) =>
					authorize({
						request,
						client,
						organizationId: route.organizationId,
						operation: route.operation,
					}),
			);
			if (admission instanceof Response) return admission;
			const handle =
				route.operation === "decommission"
					? createOwnedProjectSCIMDecommission({ ...common, authorize })
					: createOwnedProjectSCIMManagement({
							...common,
							authorize,
							baseURL: await connectorURL(
								route.operation === "revoke"
									? { kind: "project-path" }
									: options.connector,
								project,
								managementOrigin,
							),
						});
			return (await handle(request)) ?? forbidden();
		} catch (error) {
			if (error instanceof Response) return error;
			return ownedSCIMManagementFailure(
				500,
				"The request could not be completed.",
			);
		}
	};
}
