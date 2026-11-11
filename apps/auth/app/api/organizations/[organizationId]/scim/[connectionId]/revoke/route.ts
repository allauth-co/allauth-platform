import { apiRoute } from "@/lib/api";
import { mutateDirectory } from "@/lib/scim-management";
export const POST = async (request: Request, context: { params: Promise<{ organizationId: string; connectionId: string }> }) => apiRoute(request, async (instance, env) => { const { organizationId, connectionId } = await context.params; return mutateDirectory(instance, request, env, organizationId, connectionId, "revoke"); });
