import { APIError } from "better-auth";
import * as z from "zod";
import type { AuthInstance } from "../api";
import { getAuthEnvironment, withAuth, withAuthEngine } from "../auth";
import type { AuthEngine } from "../auth-engine";
import { authPolicyRepository } from "../auth-policy/storage";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { readPlatformIssuerMetadata } from "../issuer-metadata";
import { readPlatformIssuerContext } from "../platform-issuer-context";
import { createPlatformIssuerSessionReader } from "../platform-issuer-session";
import type { Project } from "../projects/registry";
import { getProject, projectRegistryPool } from "../projects/registry";
import {
	withHostedProjectAuth,
	withHostedProjectAuthEngine,
} from "../projects/runtime";
import {
	edgeHeaders,
	portalHeader,
	verifyEdgeRequest,
	verifyPortalBinding,
} from "./edge";
import { lookupActiveHostname } from "./repository";
import type { DomainKind } from "./types";
import { hostingBaseDomain } from "./validation";
export interface HostedBinding {
	project: Project;
	kind: DomainKind;
	hostname: string;
}
/** Infrastructure readiness and an exact stored realm determine routing; unknown names never reach platform auth. */
export async function resolveHostedBinding(
	hostname: string,
	env: AuthEnvironment,
): Promise<HostedBinding | null> {
	if (
		setting(env, "CLOUDFLARE_SAAS_READY") !== "true" ||
		setting(env, "ALLAUTH_EDGE_SECRET").length < 32
	)
		return null;
	const base = hostingBaseDomain(env);
	if (hostname.endsWith(`.${base}`)) {
		const label = hostname.slice(0, -base.length - 1);
		const match = /^([a-z][a-z0-9-]{1,47})-(accounts|api)$/.exec(label);
		if (!match) return null;
		try {
			return {
				project: await getProject(match[1], env),
				kind: match[2] === "accounts" ? "accounts" : "frontend-api",
				hostname,
			};
		} catch (error) {
			if (error instanceof APIError) return null;
			throw error;
		}
	}
	const custom = await lookupActiveHostname(hostname, env);
	return custom
		? { project: custom.project, kind: custom.kind, hostname }
		: null;
}
export function hostedHeaders(
	headers: Headers,
	binding: HostedBinding,
	ip?: string,
): Headers {
	const clean = new Headers(headers);
	clean.delete("authorization");
	const prefix = `allauth_project_${binding.project.slug}.`;
	const cookies = (headers.get("cookie") || "")
		.split(";")
		.map((value) => value.trim())
		.filter((value) => {
			const name = value.slice(0, value.indexOf("="));
			return name.startsWith(prefix) || name.startsWith(`__Secure-${prefix}`);
		});
	if (cookies.length) clean.set("cookie", cookies.join("; "));
	else clean.delete("cookie");
	if (ip) clean.set("x-real-ip", ip);
	return clean;
}
export async function requestHostedBinding(
	request: Request,
	env: AuthEnvironment,
): Promise<{ binding: HostedBinding; headers: Headers } | null> {
	if (!edgeHeaders.some((name) => request.headers.has(name))) return null;
	const edge = await verifyEdgeRequest(
		request,
		setting(env, "ALLAUTH_EDGE_SECRET"),
	);
	if (!edge)
		throw new APIError("FORBIDDEN", {
			message: "Invalid authentication gateway request.",
		});
	const binding = await resolveHostedBinding(edge.hostname, env);
	if (!binding)
		throw new APIError("NOT_FOUND", {
			message: "Authentication hostname is not active.",
		});
	return { binding, headers: hostedHeaders(request.headers, binding, edge.ip) };
}
const confidentialOAuthPaths = new Set([
	"/api/auth/oauth2/token",
	"/api/auth/oauth2/introspect",
	"/api/auth/oauth2/revoke",
	"/api/auth/device/code",
]);

function hostedProtocolAuthorization(request: Request) {
	const authorization = request.headers.get("authorization");
	if (!authorization) return null;
	const path = new URL(request.url).pathname;
	if (request.method === "POST" && confidentialOAuthPaths.has(path))
		return /^Basic [A-Za-z0-9+/]+=*$/i.test(authorization)
			? authorization
			: null;
	if (
		path === "/api/auth/oauth2/userinfo" &&
		["GET", "POST"].includes(request.method)
	)
		return /^(?:Bearer|DPoP) [A-Za-z0-9._~+/-]+=*$/i.test(authorization)
			? authorization
			: null;
	if (
		(path === "/api/auth/scim/v2" || path.startsWith("/api/auth/scim/v2/")) &&
		["GET", "POST", "PUT", "PATCH", "DELETE"].includes(request.method)
	)
		return /^Bearer [A-Za-z0-9._~+/-]+=*$/i.test(authorization)
			? authorization
			: null;
	return null;
}

async function bindPortalRequest(
	request: Request,
	permitProtocolAuthorization = false,
) {
	const env = await getAuthEnvironment();
	const hosted = await requestHostedBinding(request, env);
	if (!hosted) return { env, request, binding: null };
	const incoming = new URL(request.url);
	// Assigning URL.host would keep the standalone listener port.
	const url = new URL(`https://${hosted.binding.hostname}`);
	url.pathname = incoming.pathname;
	url.search = incoming.search;
	// The signed gateway proves the realm. The protocol endpoint independently
	// authenticates the client credential against that realm.
	const authorization =
		permitProtocolAuthorization && hostedProtocolAuthorization(request);
	if (authorization) hosted.headers.set("authorization", authorization);
	const bound = new Request(url, {
		method: request.method,
		headers: hosted.headers,
		body: request.body,
		duplex: "half",
	} as RequestInit);
	return { env, request: bound, binding: hosted.binding };
}

export async function withPortalRequest<T>(
	request: Request,
	callback: (
		instance: AuthInstance,
		env: AuthEnvironment,
		request: Request,
		binding: HostedBinding | null,
	) => Promise<T>,
): Promise<T> {
	const { env, request: bound, binding } = await bindPortalRequest(request);
	if (!binding)
		return withAuth((instance, environment) =>
			callback(instance, environment, bound, null),
		);
	return withHostedProjectAuth(
		binding.project,
		binding.hostname,
		(instance, environment) => callback(instance, environment, bound, binding),
		env,
	);
}

/** The engine is selected only after verifying the gateway envelope and hostname. */
export async function withPortalAuthEngine<T>(
	request: Request,
	callback: (
		engine: AuthEngine,
		env: AuthEnvironment,
		request: Request,
		binding: HostedBinding | null,
	) => Promise<T>,
): Promise<T> {
	const {
		env,
		request: bound,
		binding,
	} = await bindPortalRequest(request, true);
	if (!binding) {
		return withAuthEngine((engine, environment) =>
			callback(engine, environment, bound, null),
		);
	}
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		(engine, environment) => callback(engine, environment, bound, binding),
		env,
	);
}

/** Preserve the platform issuer across ingress aliases and resolve project metadata under its writer lease. */
export async function readPortalIssuerMetadata(
	request: Request,
	kind: "openid" | "oauth",
) {
	const { env, binding } = await bindPortalRequest(request);
	if (!binding) return readPlatformIssuerMetadata(env);
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		(engine) => engine.readIssuerMetadata(kind),
		env,
	);
}

/** The signed context selects a client in the already verified realm. */
export async function readPortalIssuerContext(request: Request) {
	const { env, binding, request: bound } = await bindPortalRequest(request);
	if (!binding)
		return readPlatformIssuerContext(bound, env, projectRegistryPool(env));
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		(engine) => engine.readOAuthContext(bound),
		env,
	);
}
/** Server-rendered pages reverify the gateway proof and the active mapping on each read. */
async function bindPortalHeaders(headers: Headers) {
	const proof = headers.get(portalHeader);
	if (!proof) {
		if (edgeHeaders.some((name) => headers.has(name)))
			throw new APIError("FORBIDDEN");
		return null;
	}
	const env = await getAuthEnvironment();
	const hostname = await verifyPortalBinding(
		proof,
		setting(env, "ALLAUTH_EDGE_SECRET"),
	);
	const binding = hostname ? await resolveHostedBinding(hostname, env) : null;
	if (!binding) throw new APIError("FORBIDDEN");
	return { binding, env, headers: hostedHeaders(headers, binding) };
}

export async function withPortalHeaders<T>(
	headers: Headers,
	callback: (
		instance: AuthInstance,
		headers: Headers,
		binding: HostedBinding | null,
	) => Promise<T>,
): Promise<T> {
	const bound = await bindPortalHeaders(headers);
	if (!bound) return withAuth((instance) => callback(instance, headers, null));
	const { binding, env } = bound;
	return withHostedProjectAuth(
		binding.project,
		binding.hostname,
		(instance) => callback(instance, bound.headers, binding),
		env,
	);
}

export async function withPortalHeadersEngine<T>(
	headers: Headers,
	callback: (
		engine: AuthEngine,
		headers: Headers,
		binding: HostedBinding | null,
		env: AuthEnvironment,
	) => Promise<T>,
): Promise<T> {
	const bound = await bindPortalHeaders(headers);
	if (!bound)
		return withAuthEngine((engine, env) =>
			callback(engine, headers, null, env),
		);
	const { binding, env } = bound;
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		(engine, env) => callback(engine, bound.headers, binding, env),
		env,
	);
}

const portalIdentity = z
	.object({
		user: z.object({
			id: z.string().min(1),
			name: z.string(),
			email: z.string(),
			emailVerified: z.boolean(),
			banned: z.boolean().nullish(),
			isAnonymous: z.boolean().nullish(),
		}),
		session: z.object({
			id: z.string().min(1),
			userId: z.string().min(1),
			impersonatedBy: z.string().nullish(),
		}),
	})
	.nullable();

/** Read the live portal identity from the engine selected by the verified realm. */
export async function portalSessionContext(headers: Headers) {
	const selected = await bindPortalHeaders(headers);
	if (!selected) {
		const binding = null;
		if (!headers.has("cookie")) return { binding, session: null };
		const env = await getAuthEnvironment();
		const database = projectRegistryPool(env);
		const session = await createPlatformIssuerSessionReader(env)(
			headers,
			database,
		);
		if (!session || session.user.directoryDisabled)
			return { binding, session: null };
		const { policy } = await authPolicyRepository(database).read("platform");
		if (
			policy.mfaMode === "required" &&
			!session.session.impersonatedBy &&
			(!session.user.emailVerified || !session.user.twoFactorEnabled)
		)
			return { binding, session: null };
		return { binding, session };
	}
	const { binding, headers: bound, env } = selected;
	return withHostedProjectAuthEngine(
		binding.project,
		binding.hostname,
		async (engine) => {
			const origin = `https://${binding.hostname}`;
			// A browser may navigate here from another site. The server reads only
			// the cookies already admitted for this realm and session device context.
			const sessionHeaders = new Headers({ accept: "application/json" });
			for (const name of [
				"cookie",
				"user-agent",
				"x-real-ip",
				"cf-connecting-ip",
			]) {
				const value = bound.get(name);
				if (value) sessionHeaders.set(name, value);
			}
			const response = await engine.readSession(
				new Request(`${origin}/api/auth/get-session?disableCookieCache=true`, {
					headers: sessionHeaders,
				}),
			);
			if (response.status === 401) return { binding, session: null };
			if (!response.ok) throw new Error("Unable to read the portal session.");
			const identity = portalIdentity.safeParse(
				await response.json().catch(() => undefined),
			);
			if (
				!identity.success ||
				(identity.data &&
					identity.data.session.userId !== identity.data.user.id)
			)
				throw new Error("Invalid portal session response.");
			return { binding, session: identity.data };
		},
		env,
	);
}

/** Read the current identity for an account or authorization page. */
export async function portalSession(headers: Headers) {
	return (await portalSessionContext(headers)).session;
}
