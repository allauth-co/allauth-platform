import { APIError } from "better-auth";
import { Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import type { ConsoleOrganizationResource } from "../console/organizations";
import {
	consoleOrganizationTransactionClient,
	executeConsoleOrganization,
} from "../console/organizations";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { Project } from "./registry";
import { checkedProjectSchema, projectOrigin, projectSlug } from "./validation";

export type OwnedProjectOrganizationConsole = (
	request: Request,
	readBody: () => Promise<unknown>,
	organizationId?: string,
	resource?: ConsoleOrganizationResource,
) => Promise<{ body: unknown; status: 200 | 201 }>;

type ProjectIdentity = Pick<
	Project,
	"id" | "slug" | "schemaName" | "workspaceId"
>;

const collectionPath = "/api/admin/organizations";
const detailPath = /^\/api\/admin\/organizations\/([^/]+)(?:\/([^/]+))?$/;

function matchesConsoleOrganizationRequest(
	request: Request,
	url: URL,
	organizationId?: string,
	resource?: ConsoleOrganizationResource,
) {
	if (organizationId === undefined)
		return (
			resource === undefined &&
			url.pathname === collectionPath &&
			["GET", "POST"].includes(request.method)
		);
	const path = detailPath.exec(url.pathname);
	const methods = resource ? ["GET", "POST"] : ["GET", "PATCH", "DELETE"];
	if (!path || path[2] !== resource || !methods.includes(request.method))
		return false;
	try {
		return decodeURIComponent(path[1]) === organizationId;
	} catch {
		return false;
	}
}

/** Reuse the console's SQL projection and write contract on the selected project writer. */
export function createOwnedProjectOrganizationConsole(options: {
	database: Pool;
	project: ProjectIdentity;
	managementOrigin: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
}): OwnedProjectOrganizationConsole {
	const project = {
		...options.project,
		slug: projectSlug.parse(options.project.slug),
		schemaName: checkedProjectSchema(options.project.schemaName),
	};
	const origin = projectOrigin.parse(options.managementOrigin);
	const database: ControlDatabase = new Kysely({
		dialect: new PostgresDialect({ pool: options.database }),
	});

	return async (request, readBody, organizationId, resource) => {
		const url = new URL(request.url);
		if (
			url.searchParams.get("project") !== project.slug ||
			!matchesConsoleOrganizationRequest(request, url, organizationId, resource)
		)
			throw new APIError("FORBIDDEN");
		const writing = request.method !== "GET";
		if (writing && request.headers.get("origin") !== origin)
			throw new APIError("FORBIDDEN", {
				message: "A same-origin request is required.",
			});
		if (request.headers.has("authorization"))
			throw new APIError("UNAUTHORIZED");
		const principal = await options.readWorkspacePrincipal(request.headers);
		if (!principal) throw new APIError("UNAUTHORIZED");
		return database.transaction().execute(async (transaction) => {
			await sql`SET LOCAL search_path TO ${sql.id(project.schemaName)}`.execute(
				transaction,
			);
			const authorized = await lockOwnedProjectWorkspaceAdministrator(
				consoleOrganizationTransactionClient(transaction),
				project,
				principal,
			);
			if (!authorized) throw new APIError("UNAUTHORIZED");
			return executeConsoleOrganization(
				transaction,
				request,
				readBody,
				principal.user.id,
				organizationId,
				"owned",
				resource,
			);
		});
	};
}
