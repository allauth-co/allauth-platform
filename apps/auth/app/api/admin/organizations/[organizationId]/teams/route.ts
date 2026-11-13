import { consoleOrganizationRoute } from "@/lib/console/organization-route";

type Context = { params: Promise<{ organizationId: string }> };

async function teams(request: Request, context: Context) {
	return consoleOrganizationRoute(
		request,
		(await context.params).organizationId,
		"teams",
	);
}

export const GET = teams;
export const POST = teams;
