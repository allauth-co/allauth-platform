import { APIError } from "better-auth";
import { CompiledQuery, Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import type { ProjectApplicationRecord } from "../applications";
import {
	publicProjectApplication,
	rejectProjectConsoleApplicationWrite,
} from "../applications";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { Project } from "./registry";
import { checkedProjectSchema, projectOrigin } from "./validation";

export type OwnedProjectApplicationConsole = (
	request: Request,
) => Promise<{ applications: ReturnType<typeof publicProjectApplication>[] }>;

const collectionPath = "/api/admin/applications";
const detailPath = /^\/api\/admin\/applications\/([^/]+)$/;

function matchesRoute(pathname: string, method: string) {
	return pathname === collectionPath
		? method === "GET" || method === "POST"
		: detailPath.test(pathname) && (method === "PATCH" || method === "DELETE");
}

/** The workspace console can inspect the selected realm's registered OAuth applications. */
export function createOwnedProjectApplicationConsole(options: {
	database: Pool;
	project: Pick<Project, "id" | "slug" | "schemaName" | "workspaceId">;
	managementOrigin: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
}): OwnedProjectApplicationConsole {
	const { project } = options;
	const schema = checkedProjectSchema(project.schemaName);
	const origin = projectOrigin.parse(options.managementOrigin);
	const database: ControlDatabase = new Kysely({
		dialect: new PostgresDialect({ pool: options.database }),
	});

	return async (request) => {
		const url = new URL(request.url);
		if (
			url.searchParams.get("project") !== project.slug ||
			!matchesRoute(url.pathname, request.method)
		)
			throw new APIError("FORBIDDEN");
		const writing = request.method !== "GET";
		if (writing && request.headers.get("origin") !== origin)
			throw new APIError("FORBIDDEN", {
				message: "A same-origin request is required.",
			});
		if (request.headers.has("authorization")) throw new APIError("FORBIDDEN");
		const principal = await options.readWorkspacePrincipal(request.headers);
		if (!principal) throw new APIError("FORBIDDEN");
		return database.transaction().execute(async (transaction) => {
			const authorized = await lockOwnedProjectWorkspaceAdministrator(
				{
					query: (text, values) =>
						transaction.executeQuery(CompiledQuery.raw(text, values)),
				},
				project,
				principal,
			);
			if (!authorized) throw new APIError("FORBIDDEN");
			if (writing)
				rejectProjectConsoleApplicationWrite(url.pathname === collectionPath);
			const clients = await sql<ProjectApplicationRecord>`
				SELECT "clientId", name, "redirectUris", "tokenEndpointAuthMethod",
					"grantTypes", scopes, disabled,
					jsonb_build_object(
						'allauthOrganizationIds', metadata->'allauthOrganizationIds',
						'allauthResourceURI', metadata->'allauthResourceURI',
						'allauthAllowLocalhost', metadata->'allauthAllowLocalhost'
					) AS metadata
				FROM ${sql.id(schema, "oauthClient")}
			`.execute(transaction);
			return { applications: clients.rows.map(publicProjectApplication) };
		});
	};
}
