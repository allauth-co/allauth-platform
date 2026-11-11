import { apiRoute } from "@/lib/api";
import { createDirectory, listDirectories } from "@/lib/scim-management";
type Context = { params: Promise<{ organizationId: string }> };
export const GET = async (request: Request, context: Context) => apiRoute(request, async (instance, env) => listDirectories(instance, request, env, (await context.params).organizationId));
export const POST = async (request: Request, context: Context) => apiRoute(request, async (instance, env) => createDirectory(instance, request, env, (await context.params).organizationId));
