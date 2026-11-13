import { scimConsoleRoute } from "@/lib/scim-management";

type Context = { params: Promise<{ organizationId: string }> };

export async function GET(request: Request, { params }: Context) {
	const { organizationId } = await params;
	return scimConsoleRoute(request, { operation: "list", organizationId });
}

export async function POST(request: Request, { params }: Context) {
	const { organizationId } = await params;
	return scimConsoleRoute(request, { operation: "create", organizationId });
}
