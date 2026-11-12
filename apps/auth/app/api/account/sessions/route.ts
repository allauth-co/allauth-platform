import { withPortalAuthEngine } from "@/lib/domains/hosting";

export const GET = (request: Request) => withPortalAuthEngine(request, (engine, _env, bound) => engine.listAccountSessions(bound.headers));
