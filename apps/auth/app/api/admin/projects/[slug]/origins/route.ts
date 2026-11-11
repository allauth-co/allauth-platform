import { projectOriginsRoute } from "@/lib/projects/origin-settings-route";

export const GET = async (request: Request, context: { params: Promise<{ slug: string }> }) => projectOriginsRoute(request, (await context.params).slug);
export const PATCH = GET;
