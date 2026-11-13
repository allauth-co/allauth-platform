import { consoleOrganizationRoute } from "@/lib/console/organization-route";

type Context = { params: Promise<{ organizationId: string }> };

async function members(request: Request, context: Context) {
	return consoleOrganizationRoute(
		request,
		(await context.params).organizationId,
		"members",
	);
}

export const GET = members;
export const POST = members;
