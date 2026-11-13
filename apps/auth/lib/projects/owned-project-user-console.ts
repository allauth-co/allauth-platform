import { CompiledQuery, Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import { ConsoleRequestError } from "../console/request-error";
import {
	consoleUserListQuery,
	getConsoleUser,
	listConsoleUsers,
	readConsoleUserMetadata,
} from "../console/users";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

const collectionPath = "/api/admin/users";
const metadataAction = "user.metadata.updated";

export type ProjectUserConsoleRoute =
	| { operation: "list" }
	| { operation: "get" | "metadata"; userId: string };

export type OwnedProjectUserConsole = (
	request: Request,
	route: ProjectUserConsoleRoute,
) => Promise<unknown>;

function matchesRoute(
	path: string,
	method: string,
	route: ProjectUserConsoleRoute,
) {
	if (route.operation === "list")
		return path === collectionPath && method === "GET";
	const tail = route.operation === "metadata" ? "/metadata" : "";
	if (!path.startsWith(`${collectionPath}/`) || !path.endsWith(tail))
		return false;
	const encodedId = path.slice(
		collectionPath.length + 1,
		path.length - tail.length,
	);
	if (!encodedId || encodedId.includes("/")) return false;
	try {
		return (
			decodeURIComponent(encodedId) === route.userId &&
			method === (route.operation === "metadata" ? "PATCH" : "GET")
		);
	} catch {
		return false;
	}
}

/** Open the user directory only with current workspace authority in the selected schema. */
export function createOwnedProjectUserConsole(options: {
	database: Pool;
	project: Pick<Project, "id" | "slug" | "schemaName" | "workspaceId">;
	managementOrigin: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
}): OwnedProjectUserConsole {
	const { project } = options;
	const schema = checkedProjectSchema(project.schemaName);
	const database: ControlDatabase = new Kysely({
		dialect: new PostgresDialect({ pool: options.database }),
	});
	return async (request, route) => {
		const url = new URL(request.url);
		if (
			url.searchParams.get("project") !== project.slug ||
			!matchesRoute(url.pathname, request.method, route)
		)
			throw new ConsoleRequestError(403);
		const writing = route.operation === "metadata";
		if (writing && request.headers.get("origin") !== options.managementOrigin)
			throw new ConsoleRequestError(403, "A same-origin request is required.");
		const denied = () => new ConsoleRequestError(writing ? 403 : 401);
		if (request.headers.has("authorization")) throw denied();
		const actor = await options.readWorkspacePrincipal(request.headers);
		if (!actor) throw denied();
		return database.transaction().execute(async (transaction) => {
			await sql`SET LOCAL search_path TO ${sql.id(schema)}`.execute(
				transaction,
			);
			const authorized = await lockOwnedProjectWorkspaceAdministrator(
				{
					query: (text, values) =>
						transaction.executeQuery(CompiledQuery.raw(text, values)),
				},
				project,
				actor,
			);
			if (!authorized) throw denied();
			if (route.operation === "list")
				return listConsoleUsers(
					transaction,
					consoleUserListQuery(url.searchParams),
				);
			if (route.operation === "get")
				return getConsoleUser(transaction, route.userId);
			const body = await readConsoleUserMetadata(request);
			const changes = [sql`"updatedAt" = CURRENT_TIMESTAMP`];
			if (body.publicMetadata !== undefined)
				changes.push(
					sql`"publicMetadata" = ${JSON.stringify(body.publicMetadata)}::jsonb`,
				);
			if (body.privateMetadata !== undefined)
				changes.push(
					sql`"privateMetadata" = ${JSON.stringify(body.privateMetadata)}::jsonb`,
				);
			const result = await sql`UPDATE "user" SET ${sql.join(changes)}
				WHERE id = ${route.userId} RETURNING id`.execute(transaction);
			if (!result.rows.length) throw new ConsoleRequestError(404);
			await sql`INSERT INTO "allauthAudit" (id, "actorId", action, "targetId", "createdAt")
				VALUES (${crypto.randomUUID()}, ${actor.user.id}, ${metadataAction}, ${route.userId}, CURRENT_TIMESTAMP)`.execute(
				transaction,
			);
			await sql`INSERT INTO "allauthEvent" (id, type, outcome, "actorId", "targetId", "createdAt")
				VALUES (${crypto.randomUUID()}, ${metadataAction}, 'success', ${actor.user.id}, ${route.userId}, CURRENT_TIMESTAMP)`.execute(
				transaction,
			);
			return { success: true };
		});
	};
}
