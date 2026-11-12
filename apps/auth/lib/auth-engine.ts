import type { ControlPrincipal } from "./control/types";
import type { OwnedProjectSCIMConsole } from "./projects/owned-project-scim-console";
import type { DirectoryOperation } from "./projects/service-directory-transport";
import type { SessionCheckAdmission } from "./projects/session-introspection-admission";

/** Operations on the authentication realm already selected by trusted routing. */
export interface AuthEngine {
	dispatch(request: Request): Promise<Response>;
	readIssuerMetadata(kind: "openid" | "oauth"): Promise<Response>;
	readOAuthContext(request: Request): Promise<Response>;
	manageSCIMConsole?: OwnedProjectSCIMConsole;
	/** Resolve live identity without trusting the cookie cache. Callers enforce role policy. */
	readPrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	/** Read or refresh a session, preserving the HTTP body and response cookies. */
	readSession(request: Request): Promise<Response>;
	listAccountSessions(headers: Headers): Promise<Response>;
	revokeAccountSession(
		headers: Headers,
		body: { id: string },
	): Promise<Response>;
	readDirectory(
		operation: DirectoryOperation,
		headers: Headers,
		query: Record<string, unknown>,
	): Promise<Response>;
}

/** A project engine and its admission store share the same scoped database. */
export interface ProjectAuthScope {
	engine: AuthEngine;
	consumeAdmission(key: string): Promise<SessionCheckAdmission>;
}
