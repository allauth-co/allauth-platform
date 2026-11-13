import { consoleOrganizationRoute } from "@/lib/console/organization-route";

type Context = { params: Promise<{ organizationId: string }> };

async function detail(request: Request, context: Context) {
	return consoleOrganizationRoute(
		request,
		(await context.params).organizationId,
	);
}

export const GET = detail;
export const PATCH = detail;
export const DELETE = detail;
