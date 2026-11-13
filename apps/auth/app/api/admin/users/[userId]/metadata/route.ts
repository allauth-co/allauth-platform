import { APIError } from "better-auth";
import { json, requireAdmin, requireSameOrigin } from "@/lib/api";
import { consoleUserRoute } from "@/lib/console/user-route";
import { readConsoleUserMetadata } from "@/lib/console/users";
import { recordAudit } from "@/lib/enterprise";

export const PATCH = async (
	request: Request,
	context: { params: Promise<{ userId: string }> },
) => {
	const { userId } = await context.params;
	return consoleUserRoute(
		request,
		{ operation: "metadata", userId },
		async (instance, env) => {
			requireSameOrigin(request, env);
			const actor = await requireAdmin(instance, request.headers, env);
			const body = await readConsoleUserMetadata(request);
			const database = (await instance.$context).adapter;
			const where = [{ field: "id", value: userId }];
			if (!(await database.findOne({ model: "user", where })))
				throw new APIError("NOT_FOUND");
			await database.update({ model: "user", where, update: body });
			await recordAudit(database, {
				actorId: actor.user.id,
				action: "user.metadata.updated",
				targetId: userId,
			});
			return json({ success: true });
		},
	);
};
