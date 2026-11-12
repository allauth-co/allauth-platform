import { createHash } from "node:crypto";
import { APIError } from "better-auth";
import { getSessionCookie } from "better-auth/cookies";
import type { AuthEnvironment } from "../configuration";
import { verifyLegacySessionCookie } from "./legacy-session-cookie";
import { verifiedProjectRequest, withoutProjectProxyAssertions } from "./proxy";
import type { Project } from "./registry";
import type { SessionCheckCoordinator } from "./session-check-coordinator";
import { createSessionCheckCoordinator } from "./session-check-coordinator";
import type { SessionCheckAdmission } from "./session-introspection-admission";

export { createSessionCheckCoordinator } from "./session-check-coordinator";
export {
	consumeProxySessionCheck,
	proxySessionCheckRule,
} from "./session-introspection-admission";

interface SessionCheckDiagnostic {
	event: "allauth.session_check";
	projectId: string;
	outcome:
		| "rate_limited"
		| "invalid_session"
		| "verification_failed"
		| "service_failure";
	code: string;
	status: number;
}
interface IntrospectionDependencies {
	consume: (key: string) => Promise<SessionCheckAdmission>;
	session: (headers: Headers, request: Request) => Promise<Response>;
	fallback: (request: Request) => Promise<Response>;
	/** Native instance identity prevents joining work governed by an older policy. */
	scope?: object;
	coordinator?: SessionCheckCoordinator;
	diagnostic?: (event: SessionCheckDiagnostic) => void;
}
type SessionSigningKey = string | (() => string);
const coordinator = createSessionCheckCoordinator();
const scopes = new WeakMap<object, number>();
let nextScope = 0;
function scopeId(scope: object): number {
	let id = scopes.get(scope);
	if (id === undefined) {
		id = ++nextScope;
		scopes.set(scope, id);
	}
	return id;
}
function diagnostic(
	observe: IntrospectionDependencies["diagnostic"],
	project: Project,
	outcome: SessionCheckDiagnostic["outcome"],
	code: string,
	status: number,
): void {
	// Never include cookies, tokens, session digests, IPs, URLs or exception text.
	const event: SessionCheckDiagnostic = {
		event: "allauth.session_check",
		projectId: project.id,
		outcome,
		code,
		status,
	};
	try {
		(observe ?? ((value) => console.info(JSON.stringify(value))))(event);
	} catch {
		/* Observability cannot change authentication. */
	}
}

/** A valid cookie selects a rate bucket; it never establishes live authority. */
function authenticSessionCookie(
	request: Request,
	project: Project,
	secret: string,
): string | null {
	try {
		const serialized = getSessionCookie(request, {
			cookiePrefix: `allauth_project_${project.slug}`,
		});
		if (!serialized || serialized.length > 1024) return null;
		const value = decodeURIComponent(serialized);
		return verifyLegacySessionCookie(value, secret) ? value : null;
	} catch {
		return null;
	}
}

/** Verify the app proxy against the exact registry row before admitting engine work. */
export async function prepareProjectAuthentication(
	request: Request,
	project: Project,
	environment: AuthEnvironment,
	options: {
		consumeBody?: boolean;
		diagnostic?: IntrospectionDependencies["diagnostic"];
	} = {},
) {
	const signed = Boolean(request.headers.get("allauth-proxy-signature"));
	let verified = signed ? request : withoutProjectProxyAssertions(request);
	if (signed) {
		try {
			verified = await verifiedProjectRequest(request, project, environment, {
				consumeBody: options.consumeBody,
			});
		} catch (error) {
			diagnostic(
				options.diagnostic,
				project,
				error instanceof APIError ? "verification_failed" : "service_failure",
				"ALLAUTH_PROXY_VERIFICATION_FAILED",
				error instanceof APIError ? error.statusCode : 503,
			);
			throw error;
		}
	}
	return {
		signed,
		dispatch: (
			sessionKey: SessionSigningKey,
			dependencies: IntrospectionDependencies,
		) =>
			dispatchProjectAuthentication(
				verified,
				project,
				signed,
				sessionKey,
				dependencies,
			),
	};
}

/** Signed server introspection retains live native authority and independently meters every caller. */
export async function handleProjectAuthentication(
	request: Request,
	project: Project,
	environment: AuthEnvironment,
	sessionSecret: string,
	dependencies: IntrospectionDependencies,
): Promise<Response> {
	const authentication = await prepareProjectAuthentication(
		request,
		project,
		environment,
		{ diagnostic: dependencies.diagnostic },
	);
	return authentication.dispatch(sessionSecret, dependencies);
}

async function dispatchProjectAuthentication(
	verified: Request,
	project: Project,
	signed: boolean,
	sessionKey: SessionSigningKey,
	dependencies: IntrospectionDependencies,
): Promise<Response> {
	const url = new URL(verified.url);
	const introspection =
		signed &&
		verified.method === "GET" &&
		url.pathname === `/api/projects/${project.slug}/auth/get-session`;
	if (!introspection) return dependencies.fallback(verified);
	const sessionSecret =
		typeof sessionKey === "function" ? sessionKey() : sessionKey;
	const cookie = authenticSessionCookie(verified, project, sessionSecret);
	if (!cookie) return dependencies.fallback(verified);
	const digest = createHash("sha256")
		.update(JSON.stringify([project.id, cookie]))
		.digest("hex");
	const key = `bff-session:v2:${digest}`;
	// Verification covers each signature/timestamp independently. Railway's
	// request ID and arrival timestamp are correlation metadata, retained on the
	// native request but excluded from equality. Authority-bearing headers stay:
	// different refresh cookies/origins/IPs never join.
	const headers = [...verified.headers].filter(
		([name]) =>
			![
				"allauth-proxy-signature",
				"allauth-proxy-timestamp",
				"x-railway-request-id",
				"x-request-start",
			].includes(name),
	);
	const workKey = createHash("sha256")
		.update(
			JSON.stringify([
				scopeId(dependencies.scope ?? dependencies.session),
				project.id,
				project.proxyVersion,
				sessionSecret,
				cookie,
				url.origin,
				url.pathname,
				url.search,
				headers,
			]),
		)
		.digest("hex");
	const result = await (dependencies.coordinator ?? coordinator).check(
		workKey,
		() => dependencies.consume(key),
		() => dependencies.session(verified.headers, verified),
	);
	if (result.status === 429)
		diagnostic(
			dependencies.diagnostic,
			project,
			"rate_limited",
			"ALLAUTH_SESSION_CHECK_RATE_LIMITED",
			429,
		);
	else if (result.status >= 500)
		diagnostic(
			dependencies.diagnostic,
			project,
			"service_failure",
			"ALLAUTH_SESSION_CHECK_UNAVAILABLE",
			result.status,
		);
	else if (result.status === 401 || result.status === 403)
		diagnostic(
			dependencies.diagnostic,
			project,
			"verification_failed",
			"ALLAUTH_SESSION_CHECK_REJECTED",
			result.status,
		);
	else if (result.status === 200 && (await result.clone().text()) === "null")
		diagnostic(
			dependencies.diagnostic,
			project,
			"invalid_session",
			"ALLAUTH_SESSION_INVALID",
			200,
		);
	return result;
}
