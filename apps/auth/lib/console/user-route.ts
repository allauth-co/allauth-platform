import { randomUUID } from "node:crypto";
import { sql } from "kysely";
import type { AuthInstance } from "../api";
import { apiResponse, json, requireSameOrigin } from "../api";
import { getAuthEnvironment } from "../auth";
import type { AuthEnvironment } from "../configuration";
import { postgresDatabase } from "../postgres-database";
import type { ProjectUserConsoleRoute } from "../projects/owned-project-user-console";
import { projectRegistryPool } from "../projects/registry";
import { withProjectUserConsole } from "../projects/runtime";
import { requirePlatformDirectoryAdmin } from "../workspaces/authorization";
import { ConsoleRequestError } from "./request-error";
import {
	consoleUserListQuery,
	getConsoleUser,
	listConsoleUsers,
	readConsoleUserMetadata,
} from "./users";

export function consoleUserRoute(
	request: Request,
	route: ProjectUserConsoleRoute,
	legacy: (instance: AuthInstance, env: AuthEnvironment) => Promise<Response>,
) {
	const slug = new URL(request.url).searchParams.get("project");
	if (!slug)
		return apiResponse(async () => {
			const env = await getAuthEnvironment();
			if (route.operation === "metadata") requireSameOrigin(request, env);
			const actor = await requirePlatformDirectoryAdmin(request.headers, env);
			const pool = projectRegistryPool(env);
			const { db } = postgresDatabase(pool);
			switch (route.operation) {
				case "list":
					return json(
						await listConsoleUsers(
							db,
							consoleUserListQuery(new URL(request.url).searchParams),
						),
					);
				case "get":
					return json(await getConsoleUser(db, route.userId));
				case "metadata": {
					const { publicMetadata, privateMetadata } =
						await readConsoleUserMetadata(request);
					const changes = [sql`"updatedAt" = CURRENT_TIMESTAMP`];
					if (publicMetadata !== undefined)
						changes.push(
							sql`"publicMetadata" = ${JSON.stringify(publicMetadata)}::jsonb`,
						);
					if (privateMetadata !== undefined)
						changes.push(
							sql`"privateMetadata" = ${JSON.stringify(privateMetadata)}::jsonb`,
						);
					await db.transaction().execute(async (tx) => {
						const updated =
							await sql`UPDATE public."user" SET ${sql.join(changes)} WHERE id = ${route.userId} RETURNING id`.execute(
								tx,
							);
						if (updated.rows.length !== 1) throw new ConsoleRequestError(404);
						await tx
							.insertInto("allauthAudit")
							.values({
								id: randomUUID(),
								actorId: actor.user.id,
								action: "user.metadata.updated",
								targetId: route.userId,
								createdAt: new Date(),
							})
							.execute();
					});
					return json({ success: true });
				}
			}
		});
	return apiResponse((selectWorkspace) =>
		withProjectUserConsole(slug, async (manage, readLegacy, env, project) => {
			selectWorkspace(project.workspaceId);
			return manage
				? json(await manage(request, route))
				: legacy(readLegacy(), env);
		}),
	);
}
