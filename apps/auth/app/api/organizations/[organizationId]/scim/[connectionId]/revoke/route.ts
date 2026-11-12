import { scimConsoleRoute } from "@/lib/scim-management";

type Context = {
	params: Promise<{ organizationId: string; connectionId: string }>;
};

export async function POST(request: Request, { params }: Context) {
	const { organizationId, connectionId } = await params;
	return scimConsoleRoute(request, {
		operation: "revoke",
		organizationId,
		connectionId,
	});
}
