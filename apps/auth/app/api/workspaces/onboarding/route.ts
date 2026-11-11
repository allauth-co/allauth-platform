import { apiRoute } from "@/lib/api";
import { defaultWorkspaceRoute } from "@/lib/workspaces/onboarding-route";

export const POST = (request: Request) => apiRoute(request, (instance, env) => defaultWorkspaceRoute(request, instance, env), { platformOnly: true });
