import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { AuthEngine } from "../auth-engine";
import { defaultPasswordPolicy } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { authPolicySchema } from "../auth-policy/policy";
import type { ApplicationBranding } from "../branding/types";
import { clerkCompatiblePasswords } from "../clerk-password";
import { applicationMfaCallback } from "../mfa-continuation";
import type { NativePasskeyCapability } from "../project-native-passkeys";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { readLegacySessionCookie } from "./legacy-session-cookie";
import { createOwnedProjectMfa } from "./owned-mfa";
import { createOwnedMfaEnrollment } from "./owned-mfa-enrollment";
import { createOwnedProjectPasskeyHttp } from "./owned-passkey-http";
import type { ProjectBackchannelTarget } from "./owned-project-backchannel-logout";
import { createOwnedProjectBackchannelLogout } from "./owned-project-backchannel-logout";
import type { OwnedProjectEmailSignInOptions } from "./owned-project-email-sign-in";
import { createOwnedProjectEmailSignIn } from "./owned-project-email-sign-in";
import type { ProjectSession, ProjectUser } from "./owned-project-engine-store";
import {
	afterOwnedProjectCommit,
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { OwnedProjectOAuthOptions } from "./owned-project-oauth";
import {
	createOwnedProjectOAuth,
	ownedProjectOAuthStartInput,
	ownedProjectOAuthUnlinkInput,
	projectOAuthProvider,
} from "./owned-project-oauth";
import type { OwnedProjectOrganizationOptions } from "./owned-project-organization";
import { createOwnedProjectOrganizationHttp } from "./owned-project-organization";
import type { OwnedProjectPasswordChangeOptions } from "./owned-project-password-change";
import { createOwnedProjectPasswordChange } from "./owned-project-password-change";
import { createOwnedProjectProfile } from "./owned-project-profile";
import {
	createOwnedProjectSCIMDiscovery,
	ownedSCIMError,
} from "./owned-project-scim-discovery";
import { createOwnedProjectSCIMGroupWrites } from "./owned-project-scim-group-writes";
import { createOwnedProjectSCIMResources } from "./owned-project-scim-resources";
import { createOwnedProjectSCIMUserWrites } from "./owned-project-scim-user-writes";
import {
	createOwnedProjectSecurity,
	projectSecurityBlockedCode,
} from "./owned-project-security";
import { createOwnedProjectServiceDirectory } from "./owned-project-service-directory";
import type { OwnedProjectSsoOptions } from "./owned-project-sso";
import {
	createOwnedProjectSso,
	ownedProjectSsoInput,
} from "./owned-project-sso";
import type { OwnedProjectSupportOptions } from "./owned-project-support";
import { createOwnedProjectSupportHttp } from "./owned-project-support";
import { createOwnedRecoveryHttp } from "./owned-recovery-http";
import { createOwnedSignUpHttp } from "./owned-sign-up";
import type { Project } from "./registry";
import { consumeProxySessionCheck } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const passwordFields = {
	password: z.string().min(1).max(defaultPasswordPolicy.maxLength),
	callbackURL: z.string().max(2048).optional(),
	rememberMe: z.boolean().optional(),
};
const emailInput = z
	.object({ ...passwordFields, email: z.email().max(320) })
	.strict();
const usernameInput = z
	.object({
		...passwordFields,
		username: z
			.string()
			.min(3)
			.max(30)
			.regex(/^[A-Za-z0-9_.]+$/),
	})
	.strict();
const sessionIdInput = z.object({ id: z.string().min(1).max(160) }).strict();
const deviceSessionInput = z.object({
	sessionToken: z.string().regex(/^[a-z0-9_-]{1,64}$/i),
});
const emptyInput = z.object({}).strict();
const maximumBodyBytes = 8192;
const passwordLimit = { max: 20, window: 900, burst: 5 };

interface OwnedProjectEngineOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	trustedOrigins: readonly string[];
	signingSecret: string;
	policy: AuthPolicy;
	mfaKeys?: LegacyMfaKeys;
	passwordChange?: Pick<
		OwnedProjectPasswordChangeOptions,
		"checkPasswordSafety"
	>;
	serviceDirectory?: Pick<
		Parameters<typeof createOwnedProjectServiceDirectory>[0],
		"projectId" | "environment" | "authorize"
	>;
	sdk?: {
		nativePasskeys?: NativePasskeyCapability;
		getBranding?(): Promise<ApplicationBranding>;
	};
	appName?: string;
	signUp?: Omit<
		Parameters<typeof createOwnedSignUpHttp>[0],
		| "database"
		| "project"
		| "policy"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
	>;
	emailSignIn?: Omit<
		OwnedProjectEmailSignInOptions,
		| "database"
		| "project"
		| "policy"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
		| "completeSignIn"
	>;
	oauth?: Omit<
		OwnedProjectOAuthOptions,
		| "database"
		| "project"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
		| "signingSecret"
		| "signUpEnabled"
		| "requireEmailVerification"
		| "authorizeLinkedAccounts"
		| "complete"
	>;
	sso?: Omit<
		OwnedProjectSsoOptions,
		| "database"
		| "project"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
		| "signingSecret"
		| "signUpEnabled"
		| "complete"
	>;
	scim?: { credentialHashSecret: string };
	support?: Omit<
		OwnedProjectSupportOptions,
		| "database"
		| "project"
		| "baseURL"
		| "signingSecret"
		| "readBody"
		| "revokeSession"
		| "trustedIP"
	> & { projectId: string; workspaceId: string };
	organization?: Pick<
		OwnedProjectOrganizationOptions,
		"membershipLimit" | "invitationEmail"
	>;
	backchannelLogout?: Pick<
		Parameters<typeof createOwnedProjectBackchannelLogout>[0],
		"post" | "defer" | "observe"
	>;
	security?: {
		requireTrustedIP?: boolean;
		newDevice?: {
			defer(delivery: () => Promise<void>): void;
			notify(
				user: Pick<ProjectUser, "id" | "email" | "name">,
				context: { ipAddress?: string; userAgent?: string },
			): Promise<void>;
		};
	};
	passkeys?: Parameters<typeof createOwnedProjectPasskeyHttp>[0]["rp"];
	recovery?: Omit<
		Parameters<typeof createOwnedRecoveryHttp>[0],
		| "database"
		| "project"
		| "policy"
		| "signingSecret"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
		| "completeVerification"
	>;
	/** Only an already authenticated ingress may supply the client IP. */
	trustedIP(request: Request): string | null;
}

function json(value: unknown, status = 200, headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return Response.json(value, { status, headers });
}

function failure(
	status: number,
	code: string,
	message: string,
	headers?: Headers,
) {
	return json({ code, message }, status, headers);
}

function unsupported() {
	return failure(
		501,
		"ALLAUTH_AUTH_OPERATION_UNSUPPORTED",
		"This authentication operation is unavailable in this realm.",
	);
}

function securityBlocked() {
	return failure(
		429,
		projectSecurityBlockedCode,
		"This authentication request is temporarily unavailable. Try again later.",
	);
}

function forbidden() {
	return failure(
		403,
		"FORBIDDEN",
		"This authentication request is not permitted.",
	);
}

async function requestBody(
	request: Request,
	limit = maximumBodyBytes,
): Promise<unknown> {
	if (!request.body) return {};
	if (
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== "application/json"
	)
		return undefined;
	const reader = request.body.getReader();
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let length = 0;
	let body = "";
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > limit) {
				void reader.cancel().catch(() => {});
				return undefined;
			}
			body += decoder.decode(value, { stream: true });
		}
		return JSON.parse(body + decoder.decode());
	} catch {
		return undefined;
	} finally {
		reader.releaseLock();
	}
}

/** This deliberately limited candidate is exercised only by isolated fixtures. */
export function createOwnedProjectEngine(
	options: OwnedProjectEngineOptions,
): AuthEngine {
	const policy = authPolicySchema.parse(options.policy);
	const slug = projectSlug.parse(options.project.slug);
	const origin = projectOrigin.parse(options.baseURL);
	const secure = origin.startsWith("https://");
	const acceptedOrigins = new Set([
		origin,
		...options.trustedOrigins.map((item) => projectOrigin.parse(item)),
	]);
	if (
		!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath) ||
		options.signingSecret.length < 32
	)
		throw new Error("Invalid owned project engine configuration.");
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);
	const backchannel =
		options.backchannelLogout &&
		createOwnedProjectBackchannelLogout({
			...options.backchannelLogout,
			database: options.database,
			schemaName: options.project.schemaName,
			issuer: `${origin}${options.basePath}`,
			keys: options.oauth?.tokenKeys ??
				options.mfaKeys ?? { secret: options.signingSecret },
		});
	const prefix = `${secure ? "__Secure-" : ""}allauth_project_${slug}.`;
	const sessionCookie = `${prefix}session_token`;
	const rememberCookie = `${prefix}dont_remember`;
	const multiCookiePrefix = `${sessionCookie}_multi-`;
	const attributes = `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
	const updateAge = Math.min(
		86400,
		Math.floor(policy.sessionExpiresInSeconds / 2),
	);
	const refreshWindow = policy.sessionExpiresInSeconds - updateAge;
	const revocationOrigins = new Set([origin]);
	const mfa = createOwnedProjectMfa({
		database: options.database,
		project: options.project,
		signingSecret: options.signingSecret,
		secureCookies: secure,
		keys: options.mfaKeys,
	});
	const updateProfile = createOwnedProjectProfile(store, origin);
	const security = createOwnedProjectSecurity({
		secret: options.signingSecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.security?.requireTrustedIP,
	});
	const newDevice = options.security?.newDevice;
	const notifications = new WeakMap<Request, () => Promise<void>>();
	const committedLogoutTargets = new WeakMap<
		Request,
		ProjectBackchannelTarget[]
	>();
	const unavailableLogout = Symbol(
		"Existing session requires a configured logout handler",
	);
	const deniedMfa = Symbol("MFA sign-in denied by project security");
	const changedMfaOwner = Symbol("MFA account no longer eligible");

	function trustedRequest(
		headers: Headers,
		mutation: boolean,
		allowedOrigins = acceptedOrigins,
	) {
		const candidate = headers.get("origin");
		return (
			!headers.has("authorization") &&
			headers.get("sec-fetch-site") !== "cross-site" &&
			(candidate === null ? !mutation : allowedOrigins.has(candidate))
		);
	}

	function writeCookie(
		headers: Headers,
		name: string,
		value: string,
		maxAge?: number,
	) {
		const signed = value
			? `${value}.${createHmac("sha256", options.signingSecret).update(value).digest("base64")}`
			: "";
		headers.append(
			"Set-Cookie",
			`${name}=${encodeURIComponent(signed)}; ${attributes}${maxAge === undefined ? "" : `; Max-Age=${maxAge}`}`,
		);
	}

	function clearSessionCookies(headers: Headers) {
		for (const name of [sessionCookie, `${prefix}session_data`, rememberCookie])
			writeCookie(headers, name, "", 0);
	}

	function tokenFrom(headers: Headers, name = sessionCookie) {
		return readLegacySessionCookie(headers, name, options.signingSecret);
	}

	function multiCookies(headers: Headers) {
		return [
			...new Set(
				(headers.get("cookie") ?? "")
					.split(";")
					.map((value) => value.trim().split("=", 1)[0]),
			),
		].filter(
			(name) =>
				name.startsWith(multiCookiePrefix) &&
				/^[a-z0-9_-]{1,64}$/.test(name.slice(multiCookiePrefix.length)),
		);
	}

	function multiSessionTokens(headers: Headers) {
		return multiCookies(headers).flatMap((name) => {
			const token = tokenFrom(headers, name);
			return token && name === `${multiCookiePrefix}${token.toLowerCase()}`
				? [{ name, token }]
				: [];
		});
	}

	function currentSession(headers: Headers, client?: PoolClient) {
		return eligibleSession(tokenFrom(headers), client);
	}

	async function eligibleSession(token: string | null, client?: PoolClient) {
		const current = token
			? await store.session(token, refreshWindow, client)
			: null;
		return ordinarySession(token, current);
	}

	function ordinarySession(
		token: string | null,
		current: Awaited<ReturnType<typeof store.session>> | null,
	) {
		if (
			!token ||
			!current ||
			current.user.banned ||
			current.user.directoryDisabled ||
			current.session.impersonatedBy ||
			(policy.mfaMode === "required" &&
				(!current.user.emailVerified || !current.user.twoFactorEnabled))
		)
			return null;
		return { token, ...current };
	}

	function callbackURL(value: string | undefined, request: Request) {
		if (value === undefined) return undefined;
		if (
			!value ||
			value.startsWith("//") ||
			/[\\\u0000-\u0020\u007f]/.test(value)
		)
			return null;
		const callerOrigin = request.headers.get("origin");
		try {
			if (!callerOrigin) return null;
			const target = new URL(value, callerOrigin);
			return target.origin === callerOrigin &&
				!target.username &&
				!target.password
				? target.href
				: null;
		} catch {
			return null;
		}
	}

	function activeUser(user: ProjectUser | null): user is ProjectUser {
		return Boolean(
			user && !user.banned && !user.directoryDisabled && !user.isAnonymous,
		);
	}

	function verifiedUser(user: ProjectUser) {
		return (
			user.emailVerified ||
			(!policy.requireEmailVerification && policy.mfaMode !== "required")
		);
	}

	function rememberPreference(headers: Headers, rememberMe: boolean) {
		writeCookie(
			headers,
			rememberCookie,
			rememberMe ? "" : "true",
			rememberMe ? 0 : undefined,
		);
	}

	function deliverLogoutAfterCommit(
		client: PoolClient,
		request: Request,
		targets: ProjectBackchannelTarget[],
	) {
		if (!targets.length) return;
		afterOwnedProjectCommit(client, () => {
			const pending = committedLogoutTargets.get(request) ?? [];
			committedLogoutTargets.set(request, [...pending, ...targets]);
		});
	}

	async function createSession(
		client: PoolClient,
		user: ProjectUser,
		request: Request,
		rememberMe: boolean,
		path: string,
		prior?: ProjectSession,
	) {
		const headers = new Headers();
		const existing = multiSessionTokens(request.headers);
		const owned = [];
		if (!prior) {
			for (const item of existing) {
				const previous = await store.session(item.token, refreshWindow, client);
				if (previous?.user.id === user.id) owned.push(item);
			}
		}
		if (owned.length) {
			const removed = await store.revoke(
				{ tokens: owned.map((item) => item.token) },
				path,
				Boolean(backchannel),
				client,
			);
			if (!removed) throw unavailableLogout;
			deliverLogoutAfterCommit(client, request, removed.targets);
			for (const item of owned) writeCookie(headers, item.name, "", 0);
		}
		const id = randomUUID();
		const token = btoa(
			String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))),
		)
			.replaceAll("+", "-")
			.replaceAll("/", "_");
		const session = await store.createSession(client, {
			id,
			token,
			userId: user.id,
			expiresIn: rememberMe || prior ? policy.sessionExpiresInSeconds : 86400,
			ip: security.trustedIP(request) ?? "",
			userAgent: request.headers.get("user-agent")?.slice(0, 512) ?? "",
			activeOrganizationId: prior?.activeOrganizationId,
			activeTeamId: prior?.activeTeamId,
		});
		await store.record(client, "session.created", "success", path, user.id, id);
		if (!prior)
			await store.record(client, "auth.sign-in", "success", path, user.id, id);
		const maxAge = rememberMe ? policy.sessionExpiresInSeconds : undefined;
		writeCookie(headers, sessionCookie, token, maxAge);
		if (existing.length - owned.length < 5 || prior) {
			writeCookie(
				headers,
				`${multiCookiePrefix}${token.toLowerCase()}`,
				token,
				maxAge,
			);
		}
		rememberPreference(headers, rememberMe);
		if (!prior && user.emailVerified) {
			const name = `${prefix}control_device`;
			const known = await security.registerDevice(
				client,
				request,
				user.id,
				tokenFrom(request.headers, name),
			);
			writeCookie(headers, name, known.token, 180 * 86400);
			if (known.notify && newDevice) {
				const { id, name, email } = user;
				afterOwnedProjectCommit(client, () =>
					notifications.set(request, async () => {
						try {
							await newDevice.notify(
								{ id, name, email },
								{
									ipAddress: security.trustedIP(request) ?? undefined,
									userAgent: request.headers.get("user-agent")?.slice(0, 512),
								},
							);
						} catch {
							await store.transaction((client) =>
								security.notificationFailed(client, request, id),
							);
						}
					}),
				);
			}
		}
		return { headers, session, token, user: projectUserResponse(user) };
	}

	function mfaContinuation(callback: string): string {
		const { origin: callbackOrigin } = new URL(callback);
		const projectProxy = options.basePath !== "/api/auth";
		const target = new URL(
			projectProxy ? "/sign-in?challenge=two-factor" : "/two-factor",
			callbackOrigin,
		);
		const destination = applicationMfaCallback(
			callback,
			callbackOrigin,
			projectProxy ? "/api/allauth" : "/api/auth",
		);
		if (destination) target.searchParams.set("callbackUrl", destination);
		return target.href;
	}

	function redirect(headers: Headers, location: string) {
		headers.set("Location", location);
		headers.set("Cache-Control", "no-store");
		headers.set("Referrer-Policy", "no-referrer");
		return new Response(null, { status: 302, headers });
	}

	async function primaryResult(
		client: PoolClient,
		user: ProjectUser | null,
		request: Request,
		rememberMe: boolean,
		path: string,
		callback?: string,
		providerProof?: { managed?: boolean; allowUnverifiedEmail: boolean },
	): Promise<Response> {
		if (!activeUser(user) || (user.directoryManaged && !providerProof?.managed))
			return forbidden();
		if (
			!verifiedUser(user) &&
			(!providerProof?.allowUnverifiedEmail || policy.mfaMode === "required")
		)
			return failure(403, "EMAIL_NOT_VERIFIED", "Email not verified");
		if (policy.supportAccess?.enabled) return unsupported();
		if (await security.denySession(client, request, user.email))
			return securityBlocked();
		if (policy.mfaMode === "required" && !user.twoFactorEnabled)
			return forbidden();
		const device = user.twoFactorEnabled
			? await mfa.rotateTrustedDevice(client, user.id, request.headers)
			: null;
		if (user.twoFactorEnabled && !device?.trusted) {
			const challenge = await mfa.issue(client, user.id);
			if (!challenge) return unsupported();
			const headers = new Headers();
			headers.append("Set-Cookie", challenge.setCookie);
			if (device?.setCookie) headers.append("Set-Cookie", device.setCookie);
			rememberPreference(headers, rememberMe);
			// Pending sign-in is never authenticated by a previous active cookie.
			if (tokenFrom(request.headers)) {
				writeCookie(headers, sessionCookie, "", 0);
				writeCookie(headers, `${prefix}session_data`, "", 0);
			}
			if (callback) return redirect(headers, mfaContinuation(callback));
			return json(
				{
					twoFactorRedirect: true,
					twoFactorMethods: challenge.twoFactorMethods,
				},
				200,
				headers,
			);
		}
		const {
			headers,
			session,
			token,
			user: value,
		} = await createSession(client, user, request, rememberMe, path);
		if (device?.setCookie) headers.append("Set-Cookie", device.setCookie);
		if (path === "/sign-in/email" || path === "/sign-in/username") {
			if (callback) headers.set("Location", callback);
			return json(
				{
					redirect: Boolean(callback),
					...(callback ? { url: callback } : {}),
					user: value,
				},
				200,
				headers,
			);
		}
		if (path === "/sign-in/email-otp")
			return json({ token, user: value }, 200, headers);
		if (path === "/magic-link/verify")
			return json(
				{ token, user: value, session: { ...session, token } },
				200,
				headers,
			);
		if (path === "/verify-email") {
			return callback
				? redirect(headers, callback)
				: json({ status: true, user: null }, 200, headers);
		}
		return json({ session, user: value }, 200, headers);
	}

	async function factorAdmission(request: Request, operation: string) {
		const ip = options.trustedIP(request);
		if (!ip || !isIP(ip)) return forbidden();
		const key = createHmac("sha256", options.signingSecret)
			.update(`owned-mfa:v1:${operation}\0${ip}`)
			.digest("hex");
		const admission = await store.transaction((client) =>
			consumeProxySessionCheck(client, `owned-mfa:v1:${key}`, {
				max: 30,
				window: 60,
				burst: 10,
			}),
		);
		return admission.allowed
			? null
			: failure(
					429,
					"TOO_MANY_REQUESTS",
					"Too many requests.",
					new Headers({ "Retry-After": String(admission.retryAfter) }),
				);
	}

	const mfaEnrollment = createOwnedMfaEnrollment({
		database: options.database,
		project: options.project,
		keys: options.mfaKeys ?? { secret: options.signingSecret },
		issuer: options.appName ?? options.passkeys?.name ?? "AllAuth",
		secureCookies: secure,
		mfaRequired: policy.mfaMode === "required",
		async lockAuthority(client, request, { fresh }) {
			const current = await currentSession(request.headers, client);
			if (!current) return null;
			const user = await store.lockUser(client, current.user.id);
			if (
				!activeUser(user) ||
				!verifiedUser(user) ||
				!(await store.lockSession(client, current.token, user.id, fresh))
			)
				return null;
			const locked = await store.session(current.token, refreshWindow, client);
			if (!locked) return null;
			return { user, session: locked.session };
		},
		async rotateSession(client, request, authority, path) {
			const user = await store.lockUser(client, authority.user.id);
			if (!activeUser(user)) throw changedMfaOwner;
			const value = await createSession(
				client,
				user,
				request,
				!tokenFrom(request.headers, rememberCookie),
				path,
				authority.session,
			);
			const previous = tokenFrom(request.headers);
			if (previous)
				writeCookie(
					value.headers,
					`${multiCookiePrefix}${previous.toLowerCase()}`,
					"",
					0,
				);
			return { sessionId: value.session.id, value };
		},
	});

	async function manageMfa(
		request: Request,
		operation: "enable" | "disable" | "get-totp-uri" | "generate-backup-codes",
	) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		const refused = await factorAdmission(request, operation);
		if (refused) return refused;
		const input = z
			.object({
				password: z.string().max(128).optional(),
				issuer: z.string().max(128).optional(),
				method: z.enum(["totp", "otp"]).optional(),
			})
			.safeParse(await requestBody(request));
		if (!input.success)
			return failure(400, "INVALID_BODY", "Invalid two-factor request.");
		const result = await {
			enable: mfaEnrollment.enable,
			disable: mfaEnrollment.disable,
			"get-totp-uri": mfaEnrollment.readTotp,
			"generate-backup-codes": mfaEnrollment.rotateBackupCodes,
		}[operation](request, input.data);
		if (result.status === "rejected")
			return failure(result.httpStatus, result.code, result.message);
		if (result.status === "setup")
			return json({
				totpURI: result.totpURI,
				backupCodes: result.backupCodes,
				method: result.method,
			});
		if (result.status === "uri") return json({ totpURI: result.totpURI });
		if (result.status === "codes")
			return json({ status: true, backupCodes: result.backupCodes });
		for (const cookie of result.setCookies)
			result.value.headers.append("Set-Cookie", cookie);
		return json({ status: true }, 200, result.value.headers);
	}

	async function completeMfa(request: Request, method: "totp" | "backup") {
		if (!trustedRequest(request.headers, true)) return forbidden();
		const body = z
			.object({
				code: z.string().min(1).max(128),
				trustDevice: z.boolean().optional(),
				disableSession: z.boolean().optional(),
			})
			.safeParse(await requestBody(request));
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a verification code.");
		const path =
			method === "totp"
				? "/two-factor/verify-totp"
				: "/two-factor/verify-backup-code";
		if (await store.transaction((client) => security.admit(client, request)))
			return securityBlocked();
		const refused = await factorAdmission(request, method);
		if (refused) return refused;
		if (await currentSession(request.headers)) {
			const result = await mfaEnrollment.verify(request, {
				method,
				code: body.data.code,
			});
			if (result.status === "rejected") {
				await store.transaction((client) =>
					security.failed(client, request, path),
				);
				return failure(result.httpStatus, result.code, result.message);
			}
			if (result.status === "rotated") {
				for (const cookie of result.setCookies)
					result.value.headers.append("Set-Cookie", cookie);
				return json(
					{ session: result.value.session, user: result.value.user },
					200,
					result.value.headers,
				);
			}
			return body.data.disableSession
				? json({ status: true })
				: json({
						session: result.authority.session,
						user: projectUserResponse(result.authority.user),
					});
		}
		if (body.data.disableSession) return unsupported();
		try {
			const result = await mfa.complete(
				request.headers,
				{ method, ...body.data },
				async (client, pending) => {
					const user = await store.lockUser(client, pending.userId);
					if (
						!activeUser(user) ||
						(policy.mfaMode === "required" && !user.emailVerified) ||
						!user.twoFactorEnabled ||
						policy.supportAccess?.enabled
					)
						throw changedMfaOwner;
					if (await security.denySession(client, request, user.email))
						throw deniedMfa;
					return createSession(
						client,
						user,
						request,
						!pending.dontRememberMe,
						path,
					);
				},
			);
			if (result.status === "rejected") {
				await store.transaction((client) =>
					security.failed(client, request, path),
				);
				const headers = new Headers();
				for (const cookie of result.setCookies)
					headers.append("Set-Cookie", cookie);
				return failure(result.httpStatus, result.code, result.message, headers);
			}
			const { session, user, headers } = result.session;
			for (const cookie of result.setCookies)
				headers.append("Set-Cookie", cookie);
			return json({ session, user }, 200, headers);
		} catch (error) {
			if (error === deniedMfa) return securityBlocked();
			if (error === changedMfaOwner) return forbidden();
			throw error;
		}
	}

	async function signIn(
		request: Request,
		field: "email" | "username" = "email",
	) {
		const path = `/sign-in/${field}`;
		const invalidCode =
			field === "email"
				? "INVALID_EMAIL_OR_PASSWORD"
				: "INVALID_USERNAME_OR_PASSWORD";
		const invalidMessage =
			field === "email"
				? "Invalid email or password"
				: "Invalid username or password";
		if (!trustedRequest(request.headers, true)) return forbidden();
		if (!policy.emailAndPasswordEnabled)
			return failure(
				400,
				"EMAIL_PASSWORD_DISABLED",
				"Email and password is not enabled",
			);
		if (policy.supportAccess?.enabled) return unsupported();
		const raw = await requestBody(request);
		const body =
			field === "email"
				? emailInput.safeParse(raw)
				: usernameInput.safeParse(raw);
		if (!body.success)
			return failure(
				400,
				"INVALID_BODY",
				"Supply a valid identifier and password.",
			);
		const callback = callbackURL(body.data.callbackURL, request);
		if (callback === null) return forbidden();

		const login = (
			"email" in body.data ? body.data.email : body.data.username
		).toLowerCase();
		const identity = field === "email" ? { email: login } : { username: login };
		if (
			await store.transaction((client) =>
				security.admit(client, request, identity),
			)
		)
			return securityBlocked();

		const ip = security.trustedIP(request);
		if (!ip) return forbidden();
		const bucket = createHmac("sha256", options.signingSecret)
			.update(`owned-password:v1\0${ip}`)
			.digest("hex");
		const admission = await store.transaction((client) =>
			consumeProxySessionCheck(
				client,
				`owned-password:v1:${bucket}`,
				passwordLimit,
			),
		);
		if (!admission.allowed)
			return failure(
				429,
				"TOO_MANY_REQUESTS",
				"Too many requests.",
				new Headers({ "Retry-After": String(admission.retryAfter) }),
			);

		const credential = await store.credential(login, undefined, field);
		const hash = credential?.password;
		if (
			!credential ||
			!hash ||
			!(await clerkCompatiblePasswords.verify({
				hash,
				password: body.data.password,
			}))
		) {
			if (!hash) await clerkCompatiblePasswords.hash(body.data.password);
			await store.transaction(async (client) => {
				await security.failed(client, request, path, identity);
				await store.record(client, "auth.sign-in", "failure", path);
			});
			return failure(401, invalidCode, invalidMessage);
		}

		return store.transaction(async (client) => {
			const current = await store.credential(login, client, field);
			if (
				!current ||
				current.id !== credential.id ||
				current.password !== hash
			) {
				await security.failed(client, request, path, identity);
				return failure(401, invalidCode, invalidMessage);
			}
			const result = await primaryResult(
				client,
				current,
				request,
				body.data.rememberMe !== false,
				path,
				callback,
			);
			if (result.status >= 400 && result.status < 500 && result.status !== 429)
				await security.failed(client, request, path, identity);
			return result;
		});
	}

	async function readSession(request: Request) {
		if (!trustedRequest(request.headers, false)) return forbidden();
		const headers = new Headers();
		const token = tokenFrom(request.headers);
		const observed = token ? await store.session(token, refreshWindow) : null;
		if (support && observed?.session.impersonatedBy) {
			const url = new URL(request.url);
			if (
				request.method !== "GET" ||
				url.origin !== origin ||
				url.pathname !== `${options.basePath}/get-session`
			)
				return forbidden();
			return (await support.readBrowserSession(request)) ?? json(null);
		}
		let current = ordinarySession(token, observed);
		if (!current) {
			if (token) clearSessionCookies(headers);
			return json(null, 200, headers);
		}
		const query = new URL(request.url).searchParams;
		if (
			current.refreshDue &&
			query.get("disableRefresh") !== "true" &&
			!tokenFrom(request.headers, rememberCookie)
		) {
			const renewed = await store.refresh(
				current.token,
				policy.sessionExpiresInSeconds,
				updateAge,
			);
			if (renewed) {
				current = { ...current, session: { ...current.session, ...renewed } };
				writeCookie(
					headers,
					sessionCookie,
					current.token,
					policy.sessionExpiresInSeconds,
				);
			} else {
				current = await currentSession(request.headers);
				if (!current) {
					clearSessionCookies(headers);
					return json(null, 200, headers);
				}
			}
		}
		return json(
			{ session: current.session, user: projectUserResponse(current.user) },
			200,
			headers,
		);
	}

	async function signOut(request: Request) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		if (!emptyInput.safeParse(await requestBody(request)).success)
			return unsupported();
		const token = tokenFrom(request.headers);
		const valid = multiSessionTokens(request.headers);
		const tokens = [
			...new Set([
				...(token ? [token] : []),
				...valid.map((entry) => entry.token),
			]),
		];
		if (tokens.length) {
			const removed = await store.revoke(
				{ tokens },
				"/sign-out",
				Boolean(backchannel),
			);
			if (!removed) return unsupported();
			await backchannel?.(removed.targets);
		}
		const headers = new Headers();
		clearSessionCookies(headers);
		for (const { name } of valid) writeCookie(headers, name, "", 0);
		return json({ success: true }, 200, headers);
	}

	function publicDeviceSession(
		current: NonNullable<Awaited<ReturnType<typeof eligibleSession>>>,
	) {
		return {
			session: { ...current.session, token: current.token },
			user: projectUserResponse(current.user),
		};
	}

	async function listDeviceSessions(request: Request) {
		if (!trustedRequest(request.headers, false)) return forbidden();
		const sessions = [];
		const users = new Set<string>();
		for (const { token } of multiSessionTokens(request.headers)) {
			const current = await eligibleSession(token);
			if (!current || users.has(current.user.id)) continue;
			users.add(current.user.id);
			sessions.push(publicDeviceSession(current));
		}
		return json(sessions);
	}

	function setActiveDeviceCookie(
		headers: Headers,
		request: Request,
		token: string,
	) {
		const maxAge = tokenFrom(request.headers, rememberCookie)
			? undefined
			: policy.sessionExpiresInSeconds;
		writeCookie(headers, `${prefix}session_data`, "", 0);
		writeCookie(headers, sessionCookie, token, maxAge);
	}

	async function deviceSessionAction(request: Request, revoke: boolean) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		const body = deviceSessionInput.safeParse(await requestBody(request));
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a session token.");
		const token = body.data.sessionToken;
		const name = `${multiCookiePrefix}${token.toLowerCase()}`;
		const headers = new Headers();
		const invalid = () =>
			failure(401, "INVALID_SESSION_TOKEN", "Invalid session token", headers);
		if (tokenFrom(request.headers, name) !== token) return invalid();
		if (!revoke) {
			const current = await eligibleSession(token);
			if (!current) {
				writeCookie(headers, name, "", 0);
				return invalid();
			}
			setActiveDeviceCookie(headers, request, token);
			return json(publicDeviceSession(current), 200, headers);
		}

		const current = await currentSession(request.headers);
		if (!current)
			return failure(401, "UNAUTHORIZED", "Authentication required.");
		const removed = await store.revoke(
			{ tokens: [token] },
			"/multi-session/revoke",
			Boolean(backchannel),
		);
		if (!removed) return unsupported();
		await backchannel?.(removed.targets);
		writeCookie(headers, name, "", 0);
		if (current.token === token) {
			let replacement: string | undefined;
			for (const candidate of multiSessionTokens(request.headers)) {
				if (
					candidate.token !== token &&
					(await eligibleSession(candidate.token))
				) {
					replacement = candidate.token;
					break;
				}
			}
			if (replacement) setActiveDeviceCookie(headers, request, replacement);
			else clearSessionCookies(headers);
		}
		return json({ status: true }, 200, headers);
	}

	async function listAccountSessions(headers: Headers) {
		if (!trustedRequest(headers, false)) return forbidden();
		const current = await currentSession(headers);
		if (!current)
			return failure(401, "UNAUTHORIZED", "Authentication required.");
		if (!current.user.emailVerified) return forbidden();
		return json({
			sessions: await store.list(current.user.id),
			currentSessionId: current.session.id,
		});
	}

	async function revokeAccountSession(headers: Headers, value: { id: string }) {
		if (!trustedRequest(headers, true, revocationOrigins)) return forbidden();
		const body = sessionIdInput.safeParse(value);
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a session ID.");
		const current = await currentSession(headers);
		if (!current)
			return failure(401, "UNAUTHORIZED", "Authentication required.");
		if (!current.user.emailVerified) return forbidden();
		const removed = await store.revoke(
			{
				id: body.data.id,
				userId: current.user.id,
				currentToken: current.token,
			},
			"/account/sessions/revoke",
			Boolean(backchannel),
		);
		if (!removed) return unsupported();
		if (!removed.ids.length)
			return failure(404, "NOT_FOUND", "This session no longer exists.");
		await backchannel?.(removed.targets);
		const responseHeaders = new Headers();
		if (body.data.id === current.session.id)
			clearSessionCookies(responseHeaders);
		return json({ success: true }, 200, responseHeaders);
	}

	const passkeyHttp =
		options.passkeys &&
		createOwnedProjectPasskeyHttp({
			database: options.database,
			schemaName: options.project.schemaName,
			cookiePrefix: prefix,
			signingSecret: options.signingSecret,
			rp: options.passkeys,
			readBody: requestBody,
			writeCookie,
			async readSession(request, fresh) {
				const current = await currentSession(request.headers);
				if (
					!current ||
					(fresh &&
						Date.now() - new Date(current.session.createdAt).getTime() >=
							86400000)
				)
					return null;
				return { userId: current.user.id, email: current.user.email };
			},
			async withSession(request, userId, fresh, work) {
				const token = tokenFrom(request.headers);
				if (!token) return null;
				return store.transaction(async (client) => {
					const user = await store.lockUser(client, userId);
					if (
						!activeUser(user) ||
						!verifiedUser(user) ||
						!(await store.lockSession(client, token, userId, fresh))
					)
						return null;
					return work(client);
				});
			},
			async admit(request, operation) {
				const path = new URL(request.url).pathname.slice(
					options.basePath.length,
				);
				if (
					path === "/passkey/generate-authenticate-options" ||
					path === "/passkey/verify-authentication"
				) {
					const denied = await store.transaction((client) =>
						security.admit(client, request, {
							message: operation === "options",
						}),
					);
					if (denied) return securityBlocked();
				}
				const ip = security.trustedIP(request);
				if (!ip || !isIP(ip)) return forbidden();
				const key = createHmac("sha256", options.signingSecret)
					.update(`owned-passkey:v1:${operation}\0${ip}`)
					.digest("hex");
				const admission = await store.transaction((client) =>
					consumeProxySessionCheck(
						client,
						`owned-passkey:v1:${operation}:${key}`,
						{ max: 30, window: 60, burst: 10 },
					),
				);
				return admission.allowed
					? null
					: failure(
							429,
							"TOO_MANY_REQUESTS",
							"Too many requests.",
							new Headers({ "Retry-After": String(admission.retryAfter) }),
						);
			},
			async completeSignIn(request, userId, record) {
				return store.transaction(async (client) => {
					const user = await store.lockUser(client, userId);
					if (!activeUser(user) || user.directoryManaged || !verifiedUser(user))
						return null;
					if (!(await record(client))) return null;
					return primaryResult(
						client,
						user,
						request,
						true,
						"/passkey/verify-authentication",
					);
				});
			},
			async completeRegistration(client, request, userId) {
				return primaryResult(
					client,
					await store.lockUser(client, userId),
					request,
					true,
					"/passkey/verify-registration",
				);
			},
		});

	const signUp = options.signUp;
	const signUpHttp =
		signUp &&
		createOwnedSignUpHttp({
			...signUp,
			database: options.database,
			project: options.project,
			policy,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			async admit(request, operation, identity) {
				if (operation === "sign-up/email") {
					const denied = await store.transaction((client) =>
						security.admit(client, request, { email: identity, signup: true }),
					);
					if (denied) return securityBlocked();
				}
				return signUp.admit(request, operation, identity);
			},
		});
	const emailSignIn = options.emailSignIn;
	const emailSignInHttp =
		emailSignIn &&
		createOwnedProjectEmailSignIn({
			...emailSignIn,
			database: options.database,
			project: options.project,
			policy,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			async admit(request, operation, email) {
				const denied = await store.transaction((client) =>
					security.admit(client, request, {
						email,
						message:
							operation === "sign-in/magic-link" ||
							operation === "email-otp/send-verification-otp",
					}),
				);
				return denied
					? securityBlocked()
					: emailSignIn.admit(request, operation, email);
			},
			async completeSignIn({
				client,
				user,
				request,
				path,
				callbackURL: callback,
			}) {
				return primaryResult(
					client,
					await store.lockUser(client, user.id),
					request,
					true,
					path,
					callback,
				);
			},
		});
	const recoveryOptions = options.recovery;
	const recoveryHttp =
		recoveryOptions &&
		createOwnedRecoveryHttp({
			...recoveryOptions,
			database: options.database,
			project: options.project,
			policy,
			signingSecret: options.signingSecret,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			async admit(request, operation, email) {
				if (
					operation === "request-password-reset" ||
					operation === "send-verification-email"
				) {
					const denied = await store.transaction((client) =>
						security.admit(client, request, { email, message: true }),
					);
					if (denied) return securityBlocked();
				}
				return recoveryOptions.admit(request, operation, email);
			},
			async completeVerification({
				client,
				user,
				request,
				callbackURL: callback,
			}) {
				const active = await currentSession(request.headers, client);
				if (active?.user.id === user.id) return undefined;
				return primaryResult(
					client,
					await store.lockUser(client, user.id),
					request,
					true,
					"/verify-email",
					callback,
				);
			},
		});

	const oauth =
		options.oauth &&
		createOwnedProjectOAuth({
			...options.oauth,
			database: options.database,
			project: options.project,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			signingSecret: options.signingSecret,
			signUpEnabled: policy.signUpEnabled,
			requireEmailVerification: policy.requireEmailVerification,
			async authorizeLinkedAccounts(client, { request, user }) {
				const active = await currentSession(request.headers, client);
				return active?.user.id === user.id;
			},
			async complete(client, { user, request, provider, destination }) {
				const result = await primaryResult(
					client,
					await store.lockUser(client, user.id),
					request,
					true,
					`/callback/${provider}`,
					destination,
					{
						allowUnverifiedEmail:
							provider === "microsoft" || provider === "apple",
					},
				);
				return result.status === 200
					? redirect(new Headers(result.headers), destination)
					: result;
			},
		});
	const directory =
		options.serviceDirectory &&
		createOwnedProjectServiceDirectory({
			...options.serviceDirectory,
			database: options.database,
			schemaName: options.project.schemaName,
			project: options.project.slug,
		});
	const passwordSafety =
		options.passwordChange?.checkPasswordSafety ??
		options.recovery?.checkPasswordSafety ??
		options.signUp?.checkPasswordSafety;
	const passwordChange =
		passwordSafety &&
		createOwnedProjectPasswordChange({
			database: options.database,
			project: options.project,
			policy,
			checkPasswordSafety: passwordSafety,
			readAuthority(request) {
				return currentSession(request.headers);
			},
			async lockAuthority(client, request) {
				const current = await currentSession(request.headers, client);
				if (
					!current ||
					!(await store.lockUser(client, current.user.id)) ||
					!(await store.lockSession(
						client,
						current.token,
						current.user.id,
						false,
					))
				)
					return null;
				return currentSession(request.headers, client);
			},
			async rotateSession(client, request, { user, session }) {
				const path = "/change-password";
				const { rows } = await client.query<{ token: string }>(
					'SELECT token FROM "session" WHERE "userId" = $1 ORDER BY id',
					[user.id],
				);
				const tokens = rows.map(({ token }) => token);
				const removed = await store.revoke(
					{ tokens },
					path,
					Boolean(backchannel),
					client,
				);
				if (!removed) throw unavailableLogout;
				deliverLogoutAfterCommit(client, request, removed.targets);
				const replacement = await createSession(
					client,
					user,
					request,
					!tokenFrom(request.headers, rememberCookie),
					path,
					session,
				);
				for (const cookie of multiSessionTokens(request.headers)) {
					if (tokens.includes(cookie.token))
						writeCookie(replacement.headers, cookie.name, "", 0);
				}
				return replacement;
			},
		});
	const sso =
		options.sso &&
		createOwnedProjectSso({
			...options.sso,
			database: options.database,
			project: options.project,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			signingSecret: options.signingSecret,
			signUpEnabled: policy.signUpEnabled,
			async complete(
				client,
				{ user, request, providerId, destination, managed, protocol },
			) {
				const result = await primaryResult(
					client,
					await store.lockUser(client, user.id),
					request,
					true,
					protocol === "saml"
						? `/sso/saml2/sp/acs/${providerId}`
						: `/sso/callback/${providerId}`,
					destination,
					{ managed, allowUnverifiedEmail: true },
				);
				return result.status === 200
					? redirect(new Headers(result.headers), destination)
					: result;
			},
		});
	const scimDiscovery =
		options.scim &&
		createOwnedProjectSCIMDiscovery(`${origin}${options.basePath}`);
	const scimResources =
		options.scim &&
		createOwnedProjectSCIMResources({
			database: options.database,
			schemaName: options.project.schemaName,
			baseURL: `${origin}${options.basePath}`,
			credentialHashSecret: options.scim.credentialHashSecret,
		});
	const scimGroupWrites =
		options.scim &&
		createOwnedProjectSCIMGroupWrites({
			database: options.database,
			schemaName: options.project.schemaName,
			baseURL: `${origin}${options.basePath}`,
			credentialHashSecret: options.scim.credentialHashSecret,
		});
	const scimUserWrites =
		options.scim &&
		createOwnedProjectSCIMUserWrites({
			database: options.database,
			schemaName: options.project.schemaName,
			baseURL: `${origin}${options.basePath}`,
			credentialHashSecret: options.scim.credentialHashSecret,
			async admitProfile({ client, request, email }) {
				return (await security.admit(client, request, {
					email,
					signup: true,
				}))
					? ownedSCIMError(
							429,
							"This authentication request is temporarily unavailable. Try again later.",
						)
					: null;
			},
		});
	const support =
		options.support &&
		createOwnedProjectSupportHttp({
			...options.support,
			database: options.database,
			project: {
				...options.project,
				id: options.support.projectId,
				workspaceId: options.support.workspaceId,
			},
			baseURL: origin,
			signingSecret: options.signingSecret,
			readBody: requestBody,
			trustedIP: security.trustedIP,
			async revokeSession(client, current, request) {
				const path = new URL(request.url).pathname.slice(
					options.basePath.length,
				);
				const removed = await store.revoke(
					{ tokens: [current.token] },
					path,
					Boolean(backchannel),
					client,
				);
				if (!removed) throw unavailableLogout;
				deliverLogoutAfterCommit(client, request, removed.targets);
				return removed.ids.length > 0;
			},
		});
	const organization = createOwnedProjectOrganizationHttp({
		database: options.database,
		project: options.project,
		policy,
		currentSession,
		trustedRequest,
		readBody: requestBody,
		membershipLimit: options.organization?.membershipLimit,
		invitationEmail: options.organization?.invitationEmail,
		sessionCookies(request, principal) {
			const headers = new Headers();
			const remember = !tokenFrom(request.headers, rememberCookie);
			writeCookie(
				headers,
				sessionCookie,
				principal.token,
				remember ? policy.sessionExpiresInSeconds : undefined,
			);
			return headers;
		},
	});

	async function publicSDKConfiguration() {
		const providerOptions = options.oauth;
		const googleProvider = providerOptions?.google
			? "google"
			: providerOptions?.broker.hintGoogle
				? "allauth"
				: null;
		const apple = Boolean(providerOptions?.apple);
		const microsoft = Boolean(providerOptions?.microsoft);
		return json({
			nativePasskeys: (options.passkeys && options.sdk?.nativePasskeys) || {
				enabled: false,
				ios: false,
				android: false,
			},
			emailPassword: policy.emailAndPasswordEnabled,
			signUpEnabled: policy.signUpEnabled,
			emailVerificationRequired: policy.requireEmailVerification,
			passwordPolicy: policy.passwordPolicy,
			google: googleProvider !== null,
			googleProvider,
			apple,
			appleProvider: apple ? "apple" : null,
			microsoft,
			microsoftProvider: microsoft ? "microsoft" : null,
			organizations: true,
			twoFactor: true,
			profileImageUpload: false,
			profileImageOwnershipAndDeletion: false,
			...(options.sdk?.getBranding
				? { branding: await options.sdk.getBranding() }
				: {}),
		});
	}

	async function route(request: Request) {
		const url = new URL(request.url);
		if (
			url.origin !== origin ||
			!url.pathname.startsWith(`${options.basePath}/`)
		)
			return forbidden();
		const path = url.pathname.slice(options.basePath.length);
		const directoryResponse = await directory?.dispatch(path, request);
		if (directoryResponse) return directoryResponse;
		if (path === "/sdk/config" && request.method === "GET") {
			if (!trustedRequest(request.headers, false)) return forbidden();
			return publicSDKConfiguration();
		}
		if (path.startsWith("/scim/v2/")) {
			const response =
				scimDiscovery?.(request) ??
				(await scimResources?.(request)) ??
				(await scimUserWrites?.(request)) ??
				(await scimGroupWrites?.(request));
			if (response) return response;
		}
		const supportResponse = await support?.(path, request);
		if (supportResponse) return supportResponse;
		if (sso && request.method === "POST" && path === "/sign-in/sso") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const body = ownedProjectSsoInput.safeParse(await requestBody(request));
			if (!body.success)
				return failure(
					400,
					"INVALID_BODY",
					"Invalid enterprise sign-in request.",
				);
			const denied = await store.transaction((client) =>
				security.admit(client, request, {
					email: body.data.email?.toLowerCase(),
				}),
			);
			if (denied) return securityBlocked();
			return sso.start(request, body.data);
		}
		if (sso && request.method === "GET" && path.startsWith("/sso/callback/")) {
			const provider = path.slice("/sso/callback/".length);
			if (!provider || provider.includes("/")) return forbidden();
			const denied = await store.transaction((client) =>
				security.admit(client, request),
			);
			if (denied) return securityBlocked();
			return sso.callback(request, provider);
		}
		const samlCallbackPath = "/sso/saml2/sp/acs/";
		if (
			sso &&
			options.sso?.saml &&
			request.method === "POST" &&
			path.startsWith(samlCallbackPath)
		) {
			const provider = path.slice(samlCallbackPath.length);
			if (!provider || provider.includes("/")) return forbidden();
			const denied = await store.transaction((client) =>
				security.admit(client, request),
			);
			if (denied) return securityBlocked();
			// The IdP posts cross-site. The SAML service validates the signed response
			// against the stored, single-use request for this realm and provider.
			return sso.samlCallback(request, provider);
		}
		const recovery = await recoveryHttp?.(request);
		if (recovery) return recovery;
		const registration = await signUpHttp?.(request);
		if (registration) return registration;
		const emailSignIn = await emailSignInHttp?.(request);
		if (emailSignIn) return emailSignIn;
		const organizationResponse = await organization(path, request);
		if (organizationResponse) return organizationResponse;
		if (oauth && path === "/list-accounts" && request.method === "GET")
			return oauth.listAccounts(request);
		if (oauth && path === "/unlink-account" && request.method === "POST") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const body = ownedProjectOAuthUnlinkInput.safeParse(
				await requestBody(request),
			);
			return body.success
				? oauth.unlinkAccount(request, body.data)
				: failure(400, "INVALID_BODY", "Invalid linked-account request.");
		}
		if (
			oauth &&
			(path === "/sign-in/social" || path === "/link-social") &&
			request.method === "POST"
		) {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const body = ownedProjectOAuthStartInput.safeParse(
				await requestBody(request),
			);
			if (!body.success)
				return failure(
					400,
					"INVALID_BODY",
					"Invalid provider sign-in request.",
				);
			if (path === "/link-social") return oauth.startLink(request, body.data);
			const denied = await store.transaction((client) =>
				security.admit(client, request),
			);
			if (denied) return securityBlocked();
			return oauth.start(request, body.data);
		}
		if (oauth && path.startsWith("/callback/")) {
			const provider = projectOAuthProvider.safeParse(
				path.slice("/callback/".length),
			);
			if (
				provider.success &&
				(request.method === "GET" ||
					(provider.data === "apple" && request.method === "POST"))
			) {
				const denied = await store.transaction((client) =>
					security.admit(client, request),
				);
				if (denied) return securityBlocked();
				return oauth.callback(request, provider.data);
			}
		}
		if (passkeyHttp && path.startsWith("/passkey/")) {
			if (!trustedRequest(request.headers, request.method !== "GET"))
				return forbidden();
			const response = await passkeyHttp(path, request);
			if (response) {
				if (
					path === "/passkey/verify-authentication" &&
					response.status >= 400 &&
					response.status < 500 &&
					response.status !== 429
				)
					await store.transaction((client) =>
						security.failed(client, request, path),
					);
				return response;
			}
		}
		if (request.method === "POST" && path === "/two-factor/enable")
			return manageMfa(request, "enable");
		if (request.method === "POST" && path === "/two-factor/disable")
			return manageMfa(request, "disable");
		if (request.method === "POST" && path === "/two-factor/get-totp-uri")
			return manageMfa(request, "get-totp-uri");
		if (
			request.method === "POST" &&
			path === "/two-factor/generate-backup-codes"
		)
			return manageMfa(request, "generate-backup-codes");
		if (request.method === "POST" && path === "/two-factor/verify-totp")
			return completeMfa(request, "totp");
		if (request.method === "POST" && path === "/two-factor/verify-backup-code")
			return completeMfa(request, "backup");
		if (
			passwordChange &&
			request.method === "POST" &&
			path === "/change-password"
		) {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const denied = await factorAdmission(request, "change-password");
			if (denied) return denied;
			return passwordChange.change(request, await requestBody(request));
		}
		if (request.method === "POST" && path === "/update-user") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const current = await currentSession(request.headers);
			if (!current) return failure(401, "UNAUTHORIZED", "Unauthorized");
			const result = await updateProfile(await requestBody(request), {
				userId: current.user.id,
				token: current.token,
			});
			if (result.status !== 200)
				return failure(result.status, result.code, result.message);
			const headers = new Headers();
			writeCookie(
				headers,
				sessionCookie,
				current.token,
				tokenFrom(request.headers, rememberCookie)
					? undefined
					: policy.sessionExpiresInSeconds,
			);
			return json({ status: true }, 200, headers);
		}
		if (request.method === "POST" && path === "/sign-in/email")
			return signIn(request);
		if (request.method === "POST" && path === "/sign-in/username")
			return signIn(request, "username");
		if (request.method === "GET" && path === "/get-session")
			return readSession(request);
		if (request.method === "POST" && path === "/get-session")
			return failure(
				405,
				"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
				"POST method requires deferSessionRefresh to be enabled in session config",
			);
		if (request.method === "POST" && path === "/sign-out")
			return signOut(request);
		if (
			request.method === "GET" &&
			path === "/multi-session/list-device-sessions"
		)
			return listDeviceSessions(request);
		if (request.method === "POST" && path === "/multi-session/set-active")
			return deviceSessionAction(request, false);
		if (request.method === "POST" && path === "/multi-session/revoke")
			return deviceSessionAction(request, true);
		if (request.method === "GET" && path === "/account/sessions")
			return listAccountSessions(request.headers);
		if (request.method === "POST" && path === "/account/sessions/revoke") {
			const body = sessionIdInput.safeParse(await requestBody(request));
			return body.success
				? revokeAccountSession(request.headers, body.data)
				: failure(400, "INVALID_BODY", "Supply a session ID.");
		}
		return unsupported();
	}

	async function deliverCommittedLogout(request: Request) {
		const targets = committedLogoutTargets.get(request);
		committedLogoutTargets.delete(request);
		if (targets) await backchannel?.(targets);
	}

	return {
		async dispatch(request) {
			try {
				const response = await route(request);
				const notify = notifications.get(request);
				if (response.status < 400 && notify && newDevice)
					newDevice.defer(notify);
				return response;
			} catch (error) {
				if (error === unavailableLogout) return unsupported();
				throw error;
			} finally {
				notifications.delete(request);
				await deliverCommittedLogout(request);
			}
		},
		async readSession(request) {
			try {
				return await readSession(request);
			} catch (error) {
				if (error === unavailableLogout) return unsupported();
				throw error;
			} finally {
				await deliverCommittedLogout(request);
			}
		},
		listAccountSessions,
		revokeAccountSession,
		readDirectory: async (operation, headers, query) =>
			directory ? directory.read(operation, headers, query) : unsupported(),
		async readPrincipal(headers) {
			if (!trustedRequest(headers, false)) return null;
			const current = await currentSession(headers);
			if (!current) return null;
			const { session, user } = current;
			return {
				session: { id: session.id, userId: session.userId },
				user: {
					id: user.id,
					name: user.name,
					email: user.email,
					emailVerified: user.emailVerified,
					role: user.role ?? undefined,
					banned: user.banned ?? undefined,
				},
			};
		},
	};
}
