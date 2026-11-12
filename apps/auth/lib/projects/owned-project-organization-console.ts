import { APIError } from "better-auth";
import { CompiledQuery, Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import {
	consoleOrganizationListQuery,
	createConsoleOrganization,
	listConsoleOrganizations,
} from "../console/organizations";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { Project } from "./registry";
import { checkedProjectSchema, projectOrigin, projectSlug } from "./validation";

export type OwnedProjectOrganizationConsole = (
	request: Request,
	readBody: () => Promise<unknown>,
) => Promise<{ body: unknown; status: 200 | 201 }>;

type ProjectIdentity = Pick<
	Project,
	"id" | "slug" | "schemaName" | "workspaceId"
>;

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

	return async (request, readBody) => {
		const url = new URL(request.url);
		if (
			url.pathname !== "/api/admin/organizations" ||
			url.searchParams.get("project") !== project.slug ||
			(request.method !== "GET" && request.method !== "POST")
		)
			throw new APIError("FORBIDDEN");
		const writing = request.method === "POST";
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
				{
					query: (text, values) =>
						transaction.executeQuery(CompiledQuery.raw(text, values)),
				},
				project,
				principal,
			);
			if (!authorized) throw new APIError("UNAUTHORIZED");
			if (writing)
				return {
					body: await createConsoleOrganization(
						transaction,
						await readBody(),
						principal.user.id,
					),
					status: 201,
				};
			return {
				body: await listConsoleOrganizations(
					transaction,
					consoleOrganizationListQuery(url.searchParams),
				),
				status: 200,
			};
		});
	};
}
