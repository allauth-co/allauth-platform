import { createHash, createHmac } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ControlPrincipal } from "../control/types";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createProjectEngineStore } from "./owned-project-engine-store";
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
	/** Resolve the stored platform actor's current project authority and active session. */
	authorizeStoredActor(principal: ControlPrincipal): Promise<boolean>;
	/** Verify the signed transport and return its current registry key version. */
	verifyProxy(request: Request): Promise<VerifiedProxy | null>;
	readBody(request: Request): Promise<unknown>;
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
const application = z.object({
	actorKind: z.literal("application"),
	actorSessionId: identifier,
	applicationAuditId: identifier,
	context: z
		.object({ kind: z.enum(["user", "company", "practice"]), id: identifier })
		.strict(),
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
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const grantSchema = bindingSchema.extend({
	stateHash: opaque,
	codeChallenge: opaque,
});
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

type Binding = z.infer<typeof bindingSchema>;
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

function eligibleTarget(value: SupportSession) {
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

/** Read and end existing connected support sessions without refreshing or elevating a session. */
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
		const config = await options.configuration();
		if (
			binding &&
			config &&
			matchingSupport(binding, observed, project.id) &&
			config.callbackUrl === binding.callbackUrl &&
			config.proxyVersion === binding.proxyVersion &&
			verified.proxyVersion === binding.proxyVersion &&
			exactOrigin(binding.callbackUrl, verified.origin)
		) {
			const target = await boundTarget(realm, binding, config);
			if (target?.token === token)
				return json(supportIdentity(binding, target));
		}
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
		const identifier = `support-code:${digest(input.code)}`;
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
		const headers = new Headers();
		for (const [name, value] of [
			["session_token", target.token],
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
		return json(supportIdentity(binding, target), 200, headers);
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
		const stored =
			(await realm.verification(supportEndedKey(input.sessionId))) ??
			(await realm.verification(supportSessionKey(input.sessionId)));
		if (!stored || stored.expiresAt.getTime() <= Date.now()) {
			const config = await options.configuration();
			const app = config?.applicationInitiated;
			if (
				!config ||
				!app?.enabled ||
				verified.origin !== app.primaryOrigin ||
				verified.proxyVersion !== config.proxyVersion ||
				!browserOrigin(request, verified.origin) ||
				!exactOrigin(app.authorizeUrl, app.primaryOrigin) ||
				!exactOrigin(app.returnUrl, app.primaryOrigin) ||
				new URL(config.callbackUrl).hostname ===
					new URL(app.primaryOrigin).hostname
			)
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

	return async (
		path: string,
		request: Request,
	): Promise<Response | undefined> => {
		const read = path === "/sdk/support/session" && request.method === "GET";
		const stop = path === "/sdk/support/stop" && request.method === "POST";
		const revoke =
			path === "/sdk/support/application/revoke" && request.method === "POST";
		const exchange =
			path === "/sdk/support/exchange" && request.method === "POST";
		if (!read && !stop && !revoke && !exchange) return;
		if (
			request.headers.has("authorization") ||
			!request.headers.has("allauth-proxy-signature")
		)
			return forbidden();
		const verified = await options.verifyProxy(request.clone() as Request);
		if (!verified) return forbidden();
		const token = readLegacySessionCookie(
			request.headers,
			`${cookiePrefix}session_token`,
			options.signingSecret,
		);
		const input = read ? undefined : await options.readBody(request);
		if (stop && !stopInput.safeParse(input).success) return invalid();
		const revokeBody = revoke ? revokeInput.safeParse(input) : undefined;
		if (revokeBody && !revokeBody.success) return invalid();
		const exchangeBody = exchange ? exchangeInput.safeParse(input) : undefined;
		if (exchangeBody && !exchangeBody.success) return invalid();
		try {
			return await store.transaction(async (client) => {
				const revoke = options.revokeSession;
				const realm = projectSupportStore(
					client,
					revoke && ((current) => revoke(client, current, request)),
				);
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
				return invalid();
			});
		} catch (error) {
			if (error instanceof Response) return error;
			throw error;
		}
	};
}
