import { withPortalRequest } from "@/lib/domains/hosting";

export const GET = (request: Request) => withPortalRequest(request,(auth,_env,bound)=>auth.api.accountSessions({headers:bound.headers,asResponse:true}));
