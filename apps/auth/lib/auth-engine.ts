import type { ControlPrincipal } from "./control/types";
import type { OwnedProjectApplicationConsole } from "./projects/owned-project-application-console";
import type { OwnedProjectOrganizationConsole } from "./projects/owned-project-organization-console";
import type { OwnedProjectSCIMConsole } from "./projects/owned-project-scim-console";
import type { OwnedProjectUserConsole } from "./projects/owned-project-user-console";
import type { DirectoryOperation } from "./projects/service-directory-transport";
import type { SessionCheckAdmission } from "./projects/session-introspection-admission";

export interface PersonalApiKeyVerification {
	key: string;
	configId?: string;
	permissions?: Record<string, string[]>;
}

/** Operations on the authentication realm already selected by trusted routing. */
export interface AuthEngine {
	dispatch(request: Request): Promise<Response>;
	/** Recheck stored SAML configuration even when the protected writer is cached. */
	verifySamlReadiness?(): Promise<void>;
	readIssuerMetadata(kind: "openid" | "oauth"): Promise<Response>;
	readOAuthContext(request: Request): Promise<Response>;
	/** Server-only session transfer. The HTTP generation endpoint stays disabled. */
	issueOneTimeToken?(headers: Headers): Promise<Response>;
	/** These key operations are reserved for server code in the selected realm. */
	verifyApiKey?(input: PersonalApiKeyVerification): Promise<Response>;
	deleteAllExpiredApiKeys?(): Promise<Response>;
	manageSCIMConsole?: OwnedProjectSCIMConsole;
	manageOrganizationConsole?: OwnedProjectOrganizationConsole;
	manageUserConsole?: OwnedProjectUserConsole;
	manageApplicationConsole?: OwnedProjectApplicationConsole;
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
