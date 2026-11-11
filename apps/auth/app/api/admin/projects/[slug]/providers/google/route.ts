import { googleProviderRoute } from "@/lib/project-providers/route";

async function handler(request: Request, context: { params: Promise<{ slug: string }> }) {
	return googleProviderRoute(request, (await context.params).slug);
}
export const GET = handler;
export const PATCH = handler;
