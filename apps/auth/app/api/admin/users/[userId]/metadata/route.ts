import * as z from "zod";
import { APIError } from "better-auth";
import { apiRoute, json, requireAdmin, requireSameOrigin } from "@/lib/api";
import { recordAudit } from "@/lib/enterprise";

const schema = z.object({ publicMetadata: z.record(z.string(), z.unknown()).optional(), privateMetadata: z.record(z.string(), z.unknown()).optional() }).strict().refine((value) => value.publicMetadata !== undefined || value.privateMetadata !== undefined);
export const PATCH = async (request: Request, context: { params: Promise<{ userId: string }> }) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env);
	const actor = await requireAdmin(instance, request.headers);
	const body = schema.parse(await request.json());
	if (JSON.stringify(body).length > 64_000) throw new APIError("BAD_REQUEST");
	const { userId } = await context.params;
	const database = (await instance.$context).adapter;
	if (!(await database.findOne({ model: "user", where: [{ field: "id", value: userId }] }))) throw new APIError("NOT_FOUND");
	await database.update({ model: "user", where: [{ field: "id", value: userId }], update: body });
	await recordAudit(database, { actorId: actor.user.id, action: "user.metadata.updated", targetId: userId });
	return json({ success: true });
});
