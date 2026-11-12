import { createHash, createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { supportCallbackSchema } from "../auth-policy/policy";
import type { ControlPrincipal } from "../control/types";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import {
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { SupportSession } from "./owned-project-support-store";
import {
	projectSupportStore,
	supportEndedKey,
	supportSessionKey,
} from "./owned-project-support-store";
import type { Project } from "./registry";
import { projectOrigin, projectSlug } from "./validation";

export interface OwnedSupportRegistration {
	callbackUrl: string;
	proxyVersion: string;
	applicationInitiated?: {
		enabled: boolean;
		authorizeUrl: string;
		returnUrl: string;
		primaryOrigin: string;
	};
}

type VerifiedProxy = { origin: string; proxyVersion: string };
export interface OwnedProjectSupportOptions {
	database: Pool;
	project: Pick<Project, "id" | "slug" | "schemaName" | "workspaceId">;
	baseURL: string;
	platformOrigin: string;
	signingSecret: string;
	configuration(): Promise<OwnedSupportRegistration | null>;
	/** Resolve and authorize the current platform session for the selected project's workspace. */
	authorizePlatformRequest?(request: Request): Promise<ControlPrincipal | null>;
	/** Resolve the stored platform actor's current project authority and active session. */
	authorizeStoredActor(principal: ControlPrincipal): Promise<boolean>;
	/** Verify the signed transport and return its current registry key version. */
	verifyProxy(request: Request): Promise<VerifiedProxy | null>;
	readBody(request: Request): Promise<unknown>;
	/** Return only an address established by the platform's trusted ingress. */
	trustedIP?(request: Request): string | null;
	revokeSession?(
		client: PoolClient,
		current: SupportSession,
		request: Request,
	): Promise<boolean>;
}

const identifier = z.string().min(1).max(160);
const principalSchema = z.object({
	user: z.object({
		id: identifier,
		name: z.string().max(1000),
		email: z.string().max(320),
		emailVerified: z.boolean(),
		role: z.string().optional(),
		banned: z.boolean().optional(),
	}),
	session: z.object({
		id: identifier,
		userId: identifier,
		impersonatedBy: z
			.string()
			.nullish()
			.transform((value) => value ?? undefined),
	}),
});
const applicationContext = z
	.object({ kind: z.enum(["user", "company", "practice"]), id: identifier })
	.strict();
const application = z.object({
	actorKind: z.literal("application"),
	actorSessionId: identifier,
	applicationAuditId: identifier,
	context: applicationContext,
	applicationReturnURL: z.url(),
	applicationAuthorizeURL: z.url(),
});
const bindingSchema = z.object({
	application: application.optional(),
	projectId: identifier,
	actor: principalSchema,
	sessionId: identifier,
	userId: identifier,
	sessionExpiresAt: z.iso.datetime(),
	callbackUrl: z.url().max(2048),
	proxyVersion: identifier,
});
const revokeInput = z
	.object({ sessionId: identifier, applicationAuditId: identifier })
	.strict();
const stopInput = z.object({}).strict();
const impersonateInput = z.object({ userId: identifier }).strict();
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const grantSchema = bindingSchema.extend({
	stateHash: opaque,
	codeChallenge: opaque,
});
const applicationLaunchInput = z
	.object({
		actorSessionId: identifier,
		targetUserId: identifier,
		reason: z.string().trim().min(3).max(2000),
		applicationAuditId: identifier,
		context: applicationContext,
	})
	.strict();
const applicationLaunchSchema = applicationLaunchInput
	.omit({ actorSessionId: true })
	.extend({
		kind: z.literal("application-launch"),
		projectId: identifier,
		actor: principalSchema,
		callbackUrl: z.url(),
		proxyVersion: identifier,
		authorizeUrl: z.url(),
		returnUrl: z.url(),
	});
const authorizeInput = z
	.object({ launch: opaque, state: opaque, codeChallenge: opaque })
	.strict();

const exchangeInput = z
	.object({
		code: opaque,
		state: opaque,
		codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
		callbackUrl: z.url().max(2048),
	})
	.strict();
const digest = (value: string) =>
	createHash("sha256").update(value).digest("base64url");
const launchKey = (value: string) => `support-launch:${digest(value)}`;
const grantKey = (value: string) => `support-code:${digest(value)}`;
const randomCode = () => randomBytes(32).toString("base64url");
const auditValue = (value: string) =>
	value.slice(0, 256).replace(/[\u0000-\u001f]/g, "");

type Binding = z.infer<typeof bindingSchema>;
type ApplicationLaunch = z.infer<typeof applicationLaunchSchema>;
type AuthorizeInput = z.infer<typeof authorizeInput>;
type RealmSupport = ReturnType<typeof projectSupportStore>;

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	headers.set("Referrer-Policy", "no-referrer");
	return Response.json(value, { status, headers });
}
const forbidden = () =>
	json(
		{ message: "Connected support access is unavailable for this request." },
		403,
	);
const invalid = () =>
	json(
		{
			message:
				"This support handoff is invalid or has expired. Start again from AllAuth.",
		},
		400,
	);

function decodeStored<T>(
	schema: z.ZodType<T>,
	row: { value: string; expiresAt: Date } | null,
) {
	if (!row || row.expiresAt.getTime() <= Date.now()) return null;
	try {
		const parsed = schema.safeParse(JSON.parse(row.value));
		return parsed.success ? parsed.data : null;
	} catch {
		return null;
	}
}

const decodeBinding = (row: { value: string; expiresAt: Date } | null) =>
	decodeStored(bindingSchema, row);

function exactOrigin(value: string, origin: string) {
	try {
		const parsed = new URL(value);
		return parsed.origin === origin && !parsed.username && !parsed.password;
	} catch {
		return false;
	}
}

function ordinaryActor(value: SupportSession | null): value is SupportSession {
	return Boolean(
		value &&
			!value.impersonatedBy &&
			value.emailVerified &&
			!value.banned &&
			!value.directoryDisabled,
	);
}

function eligibleTarget(
	value: Pick<SupportSession, "banned" | "directoryDisabled" | "role">,
) {
	return (
		!value.banned &&
		!value.directoryDisabled &&
		!value.role?.split(",").some((role) => role.trim() === "admin")
	);
}

function matchingSupport(
	binding: Binding,
	target: SupportSession,
	projectId: string,
) {
	return (
		binding.projectId === projectId &&
		binding.sessionId === target.id &&
		binding.userId === target.userId &&
		binding.actor.user.id === target.impersonatedBy &&
		binding.actor.session.userId === binding.actor.user.id &&
		!binding.actor.session.impersonatedBy
	);
}

function applicationFields(binding: Binding) {
	if (!binding.application) return {};
	const {
		actorKind,
		actorSessionId,
		applicationAuditId,
		context,
		applicationReturnURL,
	} = binding.application;
	return {
		actorKind,
		actorSessionId,
		applicationAuditId,
		context,
		applicationReturnURL,
	};
}

function browserOrigin(request: Request, origin: string) {
	return (
		request.headers.get("origin") === origin &&
		request.headers.get("sec-fetch-site") !== "cross-site"
	);
}

function applicationProof(
	config: OwnedSupportRegistration | null,
	request: Request,
	verified: VerifiedProxy,
) {
	const app = config?.applicationInitiated;
	if (
		!config ||
		!app?.enabled ||
		!supportCallbackSchema.safeParse(config.callbackUrl).success ||
		verified.origin !== app.primaryOrigin ||
		verified.proxyVersion !== config.proxyVersion ||
		!browserOrigin(request, verified.origin) ||
		!exactOrigin(app.authorizeUrl, app.primaryOrigin) ||
		!exactOrigin(app.returnUrl, app.primaryOrigin) ||
		new URL(config.callbackUrl).hostname === new URL(app.primaryOrigin).hostname
	)
		return null;
	return { config, app };
}

function boundedExpiry(maximum: number, remaining: Date) {
	return new Date(Math.min(Date.now() + maximum, remaining.getTime()));
}

function redirect(value: string, query: Record<string, string>) {
	const url = new URL(value);
	for (const [name, item] of Object.entries(query))
		url.searchParams.set(name, item);
	return new Response(null, {
		status: 302,
		headers: {
			Location: url.href,
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			"Referrer-Policy": "no-referrer",
		},
	});
}

function realmActor(value: SupportSession): ControlPrincipal {
	return {
		user: {
			id: value.userId,
			name: value.name,
			email: value.email,
			emailVerified: value.emailVerified,
			role: value.role ?? undefined,
			banned: value.banned ?? undefined,
		},
		session: { id: value.id, userId: value.userId },
	};
}

/** Handle support handoffs and bound project sessions through their separate platform and proxy authorities. */
export function createOwnedProjectSupportHttp(
	options: OwnedProjectSupportOptions,
) {
	const { project } = options;
	const slug = projectSlug.parse(project.slug);
	const platform = projectOrigin.parse(options.platformOrigin);
	const secure = projectOrigin.parse(options.baseURL).startsWith("https:");
	if (options.signingSecret.length < 32)
		throw new Error("A project signing secret is required.");
	const cookiePrefix = `${secure ? "__Secure-" : ""}allauth_project_${slug}.`;
	const store = createProjectEngineStore(options.database, project.schemaName);

	function returnURL(userId?: string) {
		const url = new URL("/admin/users", platform);
		url.searchParams.set("project", slug);
		url.searchParams.set("workspace", project.workspaceId);
		if (userId) url.searchParams.set("selected", userId);
		return url.href;
	}

	function clearSession(request: Request) {
		const headers = new Headers();
		const sessionData = `${cookiePrefix}session_data`;
		const names = new Set([
			`${cookiePrefix}session_token`,
			sessionData,
			`${cookiePrefix}dont_remember`,
		]);
		for (const item of (request.headers.get("cookie") ?? "").split(";")) {
			const name = item.trim().split("=", 1)[0] ?? "";
			if (
				name.startsWith(`${sessionData}.`) &&
				/^\d{1,4}$/.test(name.slice(sessionData.length + 1))
			)
				names.add(name);
		}
		for (const name of names)
			headers.append(
				"Set-Cookie",
				`${name}=; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=0`,
			);
		return headers;
	}

	function issueSessionCookies(token: string) {
		const headers = new Headers();
		for (const [name, value] of [
			["session_token", token],
			["dont_remember", "true"],
		] as const) {
			const signature = createHmac("sha256", options.signingSecret)
				.update(value)
				.digest("base64");
			headers.append(
				"Set-Cookie",
				`${cookiePrefix}${name}=${encodeURIComponent(`${value}.${signature}`)}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`,
			);
		}
		return headers;
	}

	async function boundActor(
		realm: RealmSupport,
		binding: Binding,
		config: OwnedSupportRegistration,
	) {
		const app = binding.application;
		if (!app) return options.authorizeStoredActor(binding.actor);
		const current = config.applicationInitiated;
		if (
			!current?.enabled ||
			app.applicationAuthorizeURL !== current.authorizeUrl ||
			app.applicationReturnURL !== current.returnUrl ||
			app.actorSessionId !== binding.actor.session.id
		)
			return false;
		const original = await realm.session(app.actorSessionId, "id", {
			lock: "read",
		});
		return ordinaryActor(original) && original.userId === binding.actor.user.id;
	}

	async function boundTarget(
		realm: RealmSupport,
		binding: Binding,
		config: OwnedSupportRegistration,
		lock = false,
	) {
		if (
			binding.projectId !== project.id ||
			!(await boundActor(realm, binding, config))
		)
			return null;
		const target = await realm.session(binding.sessionId, "id", {
			lock: lock ? "read" : undefined,
		});
		const expiry = Date.parse(binding.sessionExpiresAt);
		return target &&
			matchingSupport(binding, target, project.id) &&
			eligibleTarget(target) &&
			expiry > Date.now() &&
			target.expiresAt.getTime() <= expiry
			? target
			: null;
	}

	async function currentBoundTarget(
		realm: RealmSupport,
		binding: Binding,
		token: string,
		config: OwnedSupportRegistration | null,
		proxyVersion?: string,
	) {
		if (
			!config ||
			config.callbackUrl !== binding.callbackUrl ||
			config.proxyVersion !== binding.proxyVersion ||
			(proxyVersion !== undefined && proxyVersion !== binding.proxyVersion)
		)
			return null;
		const target = await boundTarget(realm, binding, config);
		return target?.token === token ? target : null;
	}

	function supportBrowserTransport(request: Request) {
		return (
			new URL(request.url).origin === platform &&
			!request.headers.has("authorization") &&
			request.headers.get("sec-fetch-site") !== "cross-site"
		);
	}

	async function admittedBrowserSession(
		request: Request,
		client: PoolClient,
		consoleOAuth = false,
	) {
		const token = readLegacySessionCookie(
			request.headers,
			`${cookiePrefix}session_token`,
			options.signingSecret,
		);
		if (!token) return;
		const revoke = options.revokeSession;
		const realm = projectSupportStore(
			client,
			revoke && ((current) => revoke(client, current, request)),
		);
		const observed = await realm.session(token, "token");
		if (!observed) return "clear" as const;
		if (!observed.impersonatedBy) return;
		const stored = await realm.verification(supportSessionKey(observed.id));
		if (consoleOAuth && stored) return;
		const binding = decodeBinding(stored);
		if (stored && (!binding || !matchingSupport(binding, observed, project.id)))
			return "deny" as const;

		let proxyVersion: string | undefined;
		if (request.headers.has("allauth-proxy-signature")) {
			if (!binding) return "deny" as const;
			const verified = await options.verifyProxy(request);
			if (
				!verified ||
				!exactOrigin(binding.callbackUrl, verified.origin) ||
				!browserOrigin(request, verified.origin)
			)
				return "deny" as const;
			proxyVersion = verified.proxyVersion;
		} else {
			const origin = request.headers.get("origin");
			if (binding?.application || (origin && origin !== platform))
				return "deny" as const;
			const actor = await platformActor(request, false);
			if (actor?.user.id !== observed.impersonatedBy) return "deny" as const;
		}

		const target = binding
			? await currentBoundTarget(
					realm,
					binding,
					token,
					await options.configuration(),
					proxyVersion,
				)
			: consoleOAuth
				? await realm.session(token, "token", { lock: "write" })
				: observed;
		if (!target || !eligibleTarget(target)) {
			if (!consoleOAuth) await realm.revokeSession(observed);
			return "clear" as const;
		}
		// The support exchange locks this same session before adding its
		// connected-app binding. Recheck after taking the console lock.
		if (
			consoleOAuth &&
			(await realm.verification(supportSessionKey(target.id)))
		)
			return "deny" as const;
		const current = await store.session(token, 0, client);
		if (
			!current ||
			current.session.id !== observed.id ||
			current.session.id !== target.id ||
			current.session.impersonatedBy !== observed.impersonatedBy ||
			current.session.impersonatedBy !== target.impersonatedBy ||
			current.user.id !== target.userId ||
			!eligibleTarget(current.user) ||
			Date.parse(current.session.expiresAt) !== target.expiresAt.getTime()
		)
			return "clear" as const;
		return current;
	}

	async function readBrowserSession(request: Request) {
		if (!supportBrowserTransport(request)) return json(null);
		return store.transaction(async (client) => {
			const current = await admittedBrowserSession(request, client);
			if (current === "clear") return json(null, 200, clearSession(request));
			if (!current) return;
			if (current === "deny") return json(null);
			const { session, user } = current;
			return json({
				session: {
					...session,
					createdAt: new Date(session.createdAt).toISOString(),
					updatedAt: new Date(session.updatedAt).toISOString(),
					expiresAt: new Date(session.expiresAt).toISOString(),
				},
				user: projectUserResponse(user),
			});
		});
	}

	/** Read a live, console-only support identity for the issuer's initial browser GET. */
	async function readConsoleOAuthSession(request: Request, client: PoolClient) {
		if (
			!supportBrowserTransport(request) ||
			request.method !== "GET" ||
			new URL(request.url).pathname !==
				`/api/projects/${slug}/auth/oauth2/authorize` ||
			request.headers.has("allauth-proxy-signature")
		)
			return null;
		const current = await admittedBrowserSession(request, client, true);
		return current && typeof current !== "string" ? current : null;
	}

	function supportIdentity(binding: Binding, target: SupportSession) {
		return {
			session: { id: target.id, expiresAt: target.expiresAt.toISOString() },
			user: { id: target.userId, name: target.name, email: target.email },
			actor: {
				id: binding.actor.user.id,
				name: binding.actor.user.name,
				email: binding.actor.user.email,
			},
			consoleReturnURL: returnURL(target.userId),
			...applicationFields(binding),
		};
	}

	async function platformActor(request: Request, write: boolean) {
		if (
			(write && !browserOrigin(request, platform)) ||
			request.headers.has("allauth-proxy-signature")
		)
			return null;
		const actor = principalSchema.safeParse(
			await options.authorizePlatformRequest?.(request),
		);
		if (!actor.success) return null;
		const value = actor.data;
		return value.user.id === value.session.userId &&
			value.user.emailVerified &&
			!value.user.banned &&
			!value.session.impersonatedBy
			? value
			: null;
	}

	function bindingFor(
		actor: ControlPrincipal,
		target: SupportSession,
		config: OwnedSupportRegistration,
	): Binding {
		return {
			projectId: project.id,
			actor: principalSchema.parse(actor),
			sessionId: target.id,
			userId: target.userId,
			sessionExpiresAt: target.expiresAt.toISOString(),
			callbackUrl: config.callbackUrl,
			proxyVersion: config.proxyVersion,
		};
	}

	async function launchTicket(
		realm: RealmSupport,
		value: Binding | ApplicationLaunch,
		expiresAt: Date,
	) {
		if (expiresAt.getTime() <= Date.now()) return invalid();
		const launch = randomCode();
		await realm.createVerification(
			launchKey(launch),
			JSON.stringify(value),
			expiresAt,
		);
		const url = new URL(value.callbackUrl.replace(/\/callback$/, "/start"));
		url.searchParams.set("launch", launch);
		return json({ url: url.href, expiresAt: expiresAt.toISOString() });
	}

	async function issueGrant(
		realm: RealmSupport,
		binding: Binding,
		input: AuthorizeInput,
	) {
		const code = randomCode();
		const expiresAt = boundedExpiry(60_000, new Date(binding.sessionExpiresAt));
		if (expiresAt.getTime() <= Date.now()) throw invalid();
		await realm.createVerification(
			grantKey(code),
			JSON.stringify({
				...binding,
				stateHash: digest(input.state),
				codeChallenge: input.codeChallenge,
			}),
			expiresAt,
		);
		return { code, state: input.state };
	}

	async function impersonateConsoleUser(
		realm: RealmSupport,
		request: Request,
		token: string | null,
		userId: string,
	) {
		if (!browserOrigin(request, platform))
			return json(
				{ message: "Project changes require a same-origin request." },
				403,
			);
		const actor = await platformActor(request, true);
		if (!actor)
			return json(
				{ message: "A verified workspace administrator is required." },
				403,
			);
		const browserSession = token
			? await realm.session(token, "token", { lock: "read" })
			: null;
		if (browserSession?.impersonatedBy)
			return json(
				{
					message: "End the existing support session before starting another.",
				},
				403,
			);
		const user = await realm.target(userId);
		if (!user)
			return json(
				{ message: "This user does not exist in the selected project." },
				404,
			);
		if (
			user.banned ||
			user.role?.split(",").some((role) => role.trim() === "admin")
		)
			return json(
				{
					message: "Administrator and banned accounts cannot be impersonated.",
				},
				403,
			);
		if (user.directoryDisabled)
			return json(
				{ message: "This user cannot receive an impersonation session." },
				403,
			);
		const ip = options.trustedIP?.(request) ?? "";
		const userAgent = request.headers.get("user-agent") ?? "";
		const target = await realm.createSession(user, actor.user.id, {
			expiresAt: new Date(Date.now() + 15 * 60_000),
			ipAddress: isIP(ip) ? ip : "",
			userAgent,
			path: "/project-admin/impersonate-user",
		});
		await realm.recordEvent(
			target,
			userAgent,
			"session.impersonation-started",
			{
				path: "/project-admin/impersonate-user",
				signal: "platform-project-management",
			},
			target.userId,
		);
		return json(
			{
				session: {
					id: target.id,
					userId: target.userId,
					expiresAt: target.expiresAt.toISOString(),
					impersonatedBy: actor.user.id,
				},
				user: {
					id: user.userId,
					email: user.email,
					name: user.name,
					emailVerified: user.emailVerified,
					role: user.role,
					banned: user.banned,
					banReason: user.banReason,
					banExpires: user.banExpires,
					image: user.image,
					createdAt: user.createdAt,
					updatedAt: user.updatedAt,
					publicMetadata: user.publicMetadata,
				},
			},
			200,
			issueSessionCookies(target.token),
		);
	}

	async function stopConsoleImpersonation(
		realm: RealmSupport,
		request: Request,
		token: string | null,
	) {
		if (
			!browserOrigin(request, platform) ||
			request.headers.has("allauth-proxy-signature")
		)
			return json(
				{ message: "Project changes require a same-origin request." },
				403,
			);
		const current = token
			? await realm.session(token, "token", { lock: "write" })
			: null;
		if (!current) return json({ message: "Unauthorized" }, 401);
		if (!current.impersonatedBy)
			return json(
				{ message: "This session is not impersonating a project user." },
				400,
			);
		if (!(await realm.revokeSession(current)))
			return json({ message: "Unauthorized" }, 401);
		await realm.recordEvent(
			current,
			request.headers.get("user-agent"),
			"session.impersonation-stopped",
			{ signal: "platform-project-management" },
		);
		return json({ success: true }, 200, clearSession(request));
	}

	async function consoleStatus(
		realm: RealmSupport,
		request: Request,
		token: string | null,
	) {
		const actor = await platformActor(request, false);
		if (!actor) return forbidden();
		const config = await options.configuration();
		const target = token ? await realm.session(token, "token") : null;
		return json({
			enabled: Boolean(config),
			...(config ? { callbackUrl: config.callbackUrl } : {}),
			launchAvailable: Boolean(
				config &&
					target?.impersonatedBy === actor.user.id &&
					eligibleTarget(target),
			),
		});
	}

	async function consoleLaunch(
		realm: RealmSupport,
		request: Request,
		token: string | null,
	) {
		const actor = await platformActor(request, true);
		if (!actor) return forbidden();
		const config = await options.configuration();
		if (!config || !supportCallbackSchema.safeParse(config.callbackUrl).success)
			return forbidden();
		const target = token
			? await realm.session(token, "token", { lock: "read" })
			: null;
		if (
			!target ||
			target.impersonatedBy !== actor.user.id ||
			!eligibleTarget(target)
		)
			return forbidden();
		return launchTicket(
			realm,
			bindingFor(actor, target, config),
			boundedExpiry(120_000, target.expiresAt),
		);
	}

	async function consoleAuthorize(
		realm: RealmSupport,
		request: Request,
		token: string | null,
		input: AuthorizeInput,
	) {
		const config = await options.configuration();
		if (!config || !supportCallbackSchema.safeParse(config.callbackUrl).success)
			return forbidden();
		const identifier = launchKey(input.launch);
		const stored = await realm.verification(identifier);
		const launch = decodeStored(applicationLaunchSchema, stored);
		if (launch) {
			const app = config.applicationInitiated;
			if (
				!app?.enabled ||
				launch.projectId !== project.id ||
				launch.callbackUrl !== config.callbackUrl ||
				launch.proxyVersion !== config.proxyVersion ||
				launch.authorizeUrl !== app.authorizeUrl ||
				launch.returnUrl !== app.returnUrl ||
				!exactOrigin(app.authorizeUrl, app.primaryOrigin)
			)
				return forbidden();
			return redirect(app.authorizeUrl, input);
		}
		const actor = await platformActor(request, false);
		if (!actor) return forbidden();
		const binding = decodeBinding(stored);
		if (!stored || !binding) return invalid();
		if (
			binding.application ||
			binding.callbackUrl !== config.callbackUrl ||
			binding.proxyVersion !== config.proxyVersion ||
			binding.actor.user.id !== actor.user.id ||
			binding.actor.session.id !== actor.session.id
		)
			return forbidden();
		const target = await boundTarget(realm, binding, config, true);
		if (!target || target.token !== token) return forbidden();
		if (!(await realm.consumeVerification(identifier, stored.id)))
			return invalid();
		return redirect(
			binding.callbackUrl,
			await issueGrant(realm, binding, input),
		);
	}

	async function applicationLaunch(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		token: string | null,
		input: z.infer<typeof applicationLaunchInput>,
	) {
		const proof = applicationProof(
			await options.configuration(),
			request,
			verified,
		);
		if (!proof || !token) return forbidden();
		const actor = await realm.session(token, "token", { lock: "read" });
		if (
			!ordinaryActor(actor) ||
			input.actorSessionId !== actor.id ||
			input.targetUserId === actor.userId
		)
			return forbidden();
		const target = await realm.target(input.targetUserId);
		if (!target || !eligibleTarget(target)) return forbidden();
		const { config, app } = proof;
		const launch: ApplicationLaunch = {
			kind: "application-launch",
			projectId: project.id,
			actor: principalSchema.parse(realmActor(actor)),
			targetUserId: target.userId,
			reason: input.reason,
			applicationAuditId: input.applicationAuditId,
			context: input.context,
			callbackUrl: config.callbackUrl,
			proxyVersion: config.proxyVersion,
			authorizeUrl: app.authorizeUrl,
			returnUrl: app.returnUrl,
		};
		return launchTicket(realm, launch, boundedExpiry(120_000, actor.expiresAt));
	}

	async function applicationAuthorize(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		token: string | null,
		input: AuthorizeInput,
	) {
		const proof = applicationProof(
			await options.configuration(),
			request,
			verified,
		);
		if (!proof || !token) return forbidden();
		const actor = await realm.session(token, "token", { lock: "read" });
		if (!ordinaryActor(actor)) return forbidden();
		const { config, app } = proof;
		const identifier = launchKey(input.launch);
		const stored = await realm.verification(identifier);
		const launch = decodeStored(applicationLaunchSchema, stored);
		if (!stored || !launch) return invalid();
		if (
			launch.projectId !== project.id ||
			launch.actor.user.id !== actor.userId ||
			launch.actor.session.userId !== actor.userId ||
			launch.actor.session.id !== actor.id ||
			launch.actor.session.impersonatedBy ||
			launch.targetUserId === actor.userId ||
			launch.callbackUrl !== config.callbackUrl ||
			launch.proxyVersion !== config.proxyVersion ||
			launch.authorizeUrl !== app.authorizeUrl ||
			launch.returnUrl !== app.returnUrl
		)
			return forbidden();
		const user = await realm.target(launch.targetUserId);
		if (!user || !eligibleTarget(user)) return invalid();
		if (user.directoryManaged)
			return json(
				{
					message:
						"This account must sign in through its enterprise identity provider.",
				},
				403,
			);
		const expiresAt = boundedExpiry(15 * 60_000, actor.expiresAt);
		if (
			expiresAt.getTime() <= Date.now() ||
			!(await realm.consumeVerification(identifier, stored.id))
		)
			return invalid();
		const proxyIP = request.headers.get("allauth-proxy-ip") ?? "";
		const userAgent = request.headers.get("user-agent") ?? "";
		const target = await realm.createSession(user, actor.userId, {
			expiresAt,
			ipAddress: isIP(proxyIP) ? proxyIP : "",
			userAgent,
			path: "/sdk/support/application/authorize",
		});
		const binding = {
			...bindingFor(realmActor(actor), target, config),
			application: {
				actorKind: "application" as const,
				actorSessionId: actor.id,
				applicationAuditId: launch.applicationAuditId,
				context: launch.context,
				applicationReturnURL: app.returnUrl,
				applicationAuthorizeURL: app.authorizeUrl,
			},
		};
		await realm.createVerification(
			supportSessionKey(target.id),
			JSON.stringify(binding),
			expiresAt,
		);
		const query = await issueGrant(realm, binding, input);
		await realm.recordEvent(
			target,
			userAgent,
			"session.impersonation-started",
			{
				signal: "application-support",
				actorKind: "application",
				reason: auditValue(launch.reason),
				applicationAuditId: auditValue(launch.applicationAuditId),
				contextKind: launch.context.kind,
				contextId: auditValue(launch.context.id),
			},
		);
		const url = new URL(config.callbackUrl);
		url.searchParams.set("code", query.code);
		url.searchParams.set("state", query.state);
		return json({
			url: url.href,
			expiresAt: expiresAt.toISOString(),
			sessionId: target.id,
		});
	}

	async function readSupport(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		token: string | null,
	) {
		const observed = token ? await realm.session(token, "token") : null;
		if (!observed?.impersonatedBy) return json(null);
		const binding = decodeBinding(
			await realm.verification(supportSessionKey(observed.id)),
		);
		if (
			!binding ||
			!matchingSupport(binding, observed, project.id) ||
			!exactOrigin(binding.callbackUrl, verified.origin) ||
			!browserOrigin(request, verified.origin)
		)
			return json(null);
		const target = await currentBoundTarget(
			realm,
			binding,
			observed.token,
			await options.configuration(),
			verified.proxyVersion,
		);
		if (target) return json(supportIdentity(binding, target));
		await realm.revokeSession(observed);
		return json(null, 200, clearSession(request));
	}

	async function exchangeSupport(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		input: z.infer<typeof exchangeInput>,
	) {
		const config = await options.configuration();
		if (
			!config ||
			config.proxyVersion !== verified.proxyVersion ||
			!exactOrigin(config.callbackUrl, verified.origin)
		)
			return forbidden();
		const identifier = grantKey(input.code);
		const stored = await realm.verification(identifier);
		const grant = decodeStored(grantSchema, stored);
		if (
			!stored ||
			!grant ||
			grant.stateHash !== digest(input.state) ||
			grant.codeChallenge !== digest(input.codeVerifier) ||
			grant.callbackUrl !== input.callbackUrl
		)
			return invalid();
		if (
			grant.callbackUrl !== config.callbackUrl ||
			grant.proxyVersion !== config.proxyVersion
		)
			return forbidden();
		const target = await boundTarget(realm, grant, config, true);
		if (!target) return forbidden();
		const binding = bindingSchema.parse(grant);
		const key = supportSessionKey(target.id);
		if (!(await realm.verification(key)))
			await realm.reserve(
				key,
				JSON.stringify(binding),
				new Date(binding.sessionExpiresAt),
			);
		const existing = decodeBinding(await realm.verification(key));
		if (
			!existing ||
			!matchingSupport(existing, target, project.id) ||
			existing.actor.session.id !== binding.actor.session.id ||
			existing.callbackUrl !== binding.callbackUrl ||
			existing.proxyVersion !== binding.proxyVersion ||
			JSON.stringify(existing.application) !==
				JSON.stringify(binding.application)
		)
			throw forbidden();
		if (!(await realm.consumeVerification(identifier, stored.id)))
			throw invalid();
		await realm.recordEvent(
			target,
			request.headers.get("user-agent"),
			"session.support-connected",
			{ signal: "connected-app-support" },
		);
		return json(
			supportIdentity(binding, target),
			200,
			issueSessionCookies(target.token),
		);
	}

	async function stopSupport(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		token: string | null,
	) {
		const target = token
			? await realm.session(token, "token", { lock: "write" })
			: null;
		if (!target)
			return json(
				{ success: true, consoleReturnURL: returnURL() },
				200,
				clearSession(request),
			);
		if (!target.impersonatedBy) return forbidden();
		const binding = decodeBinding(
			await realm.verification(supportSessionKey(target.id)),
		);
		if (!binding) return invalid();
		if (
			!matchingSupport(binding, target, project.id) ||
			!exactOrigin(binding.callbackUrl, verified.origin)
		)
			return forbidden();
		if (binding.application)
			await realm.rememberEnded(target.id, JSON.stringify(binding));
		if (await realm.revokeSession(target))
			await realm.recordEnd(target, request.headers.get("user-agent"));
		await realm.deleteBinding(target.id);
		return json(
			{
				success: true,
				consoleReturnURL: returnURL(target.userId),
				...applicationFields(binding),
			},
			200,
			clearSession(request),
		);
	}

	async function revokeApplication(
		realm: RealmSupport,
		request: Request,
		verified: VerifiedProxy,
		token: string | null,
		input: z.infer<typeof revokeInput>,
	) {
		const actor = token
			? await realm.session(token, "token", { lock: "read" })
			: null;
		if (!ordinaryActor(actor)) return forbidden();
		// A concurrent revoke replaces the active binding with the ended marker.
		// Read both together so the request sees one authorization snapshot.
		const stored = await realm.verification(
			supportEndedKey(input.sessionId),
			supportSessionKey(input.sessionId),
		);
		if (!stored || stored.expiresAt.getTime() <= Date.now()) {
			if (!applicationProof(await options.configuration(), request, verified))
				return forbidden();
			if (await realm.session(input.sessionId, "id", { allowExpired: true }))
				return invalid();
			return json({ success: true, ...input, alreadyEnded: true });
		}
		const binding = decodeBinding(stored);
		if (!binding) return invalid();
		const app = binding.application;
		if (
			binding.projectId !== project.id ||
			binding.sessionId !== input.sessionId ||
			!app ||
			app.applicationAuditId !== input.applicationAuditId ||
			app.actorSessionId !== actor.id ||
			binding.actor.user.id !== actor.userId ||
			binding.actor.session.userId !== actor.userId ||
			binding.actor.session.id !== actor.id ||
			!exactOrigin(app.applicationAuthorizeURL, verified.origin) ||
			!browserOrigin(request, verified.origin)
		)
			return forbidden();
		const target = await realm.session(binding.sessionId, "id", {
			allowExpired: true,
			lock: "write",
		});
		if (target && !matchingSupport(binding, target, project.id))
			return forbidden();
		await realm.rememberEnded(binding.sessionId, JSON.stringify(binding));
		if (target && (await realm.revokeSession(target)))
			await realm.recordEnd(
				target,
				request.headers.get("user-agent"),
				app.applicationAuditId,
			);
		await realm.deleteBinding(binding.sessionId);
		return json({ success: true, ...input });
	}

	async function dispatch(
		path: string,
		request: Request,
	): Promise<Response | undefined> {
		const get = request.method === "GET";
		const post = request.method === "POST";
		const read = get && path === "/sdk/support/session";
		const stop = post && path === "/sdk/support/stop";
		const revoke = post && path === "/sdk/support/application/revoke";
		const exchange = post && path === "/sdk/support/exchange";
		const appLaunch = post && path === "/sdk/support/application/launch";
		const appAuthorize = post && path === "/sdk/support/application/authorize";
		const impersonate = post && path === "/project-admin/impersonate-user";
		const consoleStop = post && path === "/project-admin/stop-impersonating";
		const status = get && path === "/project-admin/support/status";
		const launch = post && path === "/project-admin/support/launch";
		const authorize = get && path === "/project-admin/support/authorize";
		const signedProxy =
			read || stop || revoke || exchange || appLaunch || appAuthorize;
		if (
			!signedProxy &&
			!status &&
			!launch &&
			!authorize &&
			!impersonate &&
			!consoleStop
		)
			return;
		if (
			request.headers.has("authorization") ||
			(signedProxy && !request.headers.has("allauth-proxy-signature"))
		)
			return forbidden();
		const verified = signedProxy
			? await options.verifyProxy(request.clone() as Request)
			: null;
		if (signedProxy && !verified) return forbidden();
		const token = readLegacySessionCookie(
			request.headers,
			`${cookiePrefix}session_token`,
			options.signingSecret,
		);
		const input =
			post && !consoleStop ? await options.readBody(request) : undefined;
		const impersonationBody = impersonate
			? impersonateInput.safeParse(input)
			: undefined;
		if ((stop || launch) && !stopInput.safeParse(input).success)
			return invalid();
		const revokeBody = revoke ? revokeInput.safeParse(input) : undefined;
		const exchangeBody = exchange ? exchangeInput.safeParse(input) : undefined;
		const appLaunchBody = appLaunch
			? applicationLaunchInput.safeParse(input)
			: undefined;
		const appAuthorizeBody = appAuthorize
			? authorizeInput.safeParse(input)
			: undefined;
		const query = authorize ? new URL(request.url).searchParams : undefined;
		const authorization =
			query?.size === 3
				? authorizeInput.safeParse(Object.fromEntries(query))
				: undefined;
		if (
			[
				revokeBody,
				exchangeBody,
				appLaunchBody,
				appAuthorizeBody,
				impersonationBody,
			].some((result) => result && !result.success) ||
			(authorize && !authorization?.success)
		)
			return invalid();
		try {
			return await store.transaction(async (client) => {
				const revokeSession = options.revokeSession;
				const realm = projectSupportStore(
					client,
					revokeSession &&
						((current) => revokeSession(client, current, request)),
				);
				if (impersonationBody?.success)
					return impersonateConsoleUser(
						realm,
						request,
						token,
						impersonationBody.data.userId,
					);
				if (consoleStop) return stopConsoleImpersonation(realm, request, token);
				if (status) return consoleStatus(realm, request, token);
				if (launch) return consoleLaunch(realm, request, token);
				if (authorization?.success)
					return consoleAuthorize(realm, request, token, authorization.data);
				if (!verified) return forbidden();
				if (read) return readSupport(realm, request, verified, token);
				if (stop) return stopSupport(realm, request, verified, token);
				if (exchangeBody?.success)
					return exchangeSupport(realm, request, verified, exchangeBody.data);
				if (revokeBody?.success)
					return revokeApplication(
						realm,
						request,
						verified,
						token,
						revokeBody.data,
					);
				if (appLaunchBody?.success)
					return applicationLaunch(
						realm,
						request,
						verified,
						token,
						appLaunchBody.data,
					);
				if (appAuthorizeBody?.success)
					return applicationAuthorize(
						realm,
						request,
						verified,
						token,
						appAuthorizeBody.data,
					);
				return invalid();
			});
		} catch (error) {
			if (error instanceof Response) return error;
			if (
				error &&
				typeof error === "object" &&
				"code" in error &&
				error.code === "PAA02"
			)
				return json(
					{
						code: "IMPERSONATION_LIMIT_REACHED",
						message:
							"This workspace has used its five free impersonations this month. Upgrade to Pro for unlimited impersonations.",
					},
					403,
				);
			throw error;
		}
	}
	return Object.assign(dispatch, {
		readBrowserSession,
		readConsoleOAuthSession,
	});
}
