import { consoleOrganizationRoute } from "@/lib/console/organization-route";

type Context = { params: Promise<{ organizationId: string }> };

export const GET = async (request: Request, context: Context) =>
	consoleOrganizationRoute(
		request,
		(await context.params).organizationId,
		"invitations",
	);

export const POST = GET;
