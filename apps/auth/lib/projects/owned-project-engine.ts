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
import { isPlatformAdmin } from "../configuration";
import type { ActivitySource } from "../control/analytics-activity";
import {
	controlResponseFailure,
	isPrimaryAuthenticationPath,
} from "../control/event-contract";
import { discoveryHeaders } from "../discovery";
import { verifiedHostedOAuthContinuation } from "../domains/hosted-oauth-continuation";
import {
	hostedPasswordSignInRequests,
	hostedSocialSignInRequests,
} from "../domains/hosted-oauth-requests";
import { emailConfigured } from "../email/send";
import { freshFeatureSession, isServerTokenRequest } from "../features/helpers";
import { applicationMfaCallback } from "../mfa-continuation";
import { oauthBrowserReturnPath } from "../oauth-browser";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { reservedProjectEmailError } from "../project-email-alias-config";
import type { NativePasskeyCapability } from "../project-native-passkeys";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import {
	readLegacyServerSessionBearer,
	readLegacySessionCookie,
} from "./legacy-session-cookie";
import { createOwnedProjectMfa } from "./owned-mfa";
import { createOwnedMfaEnrollment } from "./owned-mfa-enrollment";
import { createOwnedProjectPasskeyHttp } from "./owned-passkey-http";
import { ownedCallbackFailureCode } from "./owned-project-callback-failure";
import type { OwnedProjectAccountDeletionOptions } from "./owned-project-account-deletion";
import { createOwnedProjectAccountDeletion } from "./owned-project-account-deletion";
import type { ProjectAccountLinkOptions } from "./owned-project-account-links";
import type { OwnedProjectAdminDeletionOptions } from "./owned-project-admin-deletion";
import { createOwnedProjectAdminDeletion } from "./owned-project-admin-deletion";
import { createOwnedProjectAdminUsers } from "./owned-project-admin-users";
import {
	createOwnedProjectAnalytics,
	isOwnedProjectActivityMutation,
} from "./owned-project-analytics";
import { createOwnedProjectControl } from "./owned-project-control";
import { createOwnedProjectAgentHosts } from "./owned-project-agent-hosts";
import type { ProjectBackchannelTarget } from "./owned-project-backchannel-logout";
import { createOwnedProjectBackchannelLogout } from "./owned-project-backchannel-logout";
import type { AuthorizeProjectBrokerMfa } from "./owned-project-broker-mfa";
import { verifyOwnedProjectBrokerMfa } from "./owned-project-broker-mfa";
import {
	admitOwnedProjectBrokerMfa,
	projectBrokerMfaPath,
} from "./owned-project-broker-mfa-admission";
import { createOwnedProjectClerkImport } from "./owned-project-clerk-import";
import { createOwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { createOwnedProjectEmailChange } from "./owned-project-email-change";
import { createOwnedProjectEmailOtpVerification } from "./owned-project-email-otp-verification";
import type { OwnedProjectEmailSignInOptions } from "./owned-project-email-sign-in";
import { createOwnedProjectEmailSignIn } from "./owned-project-email-sign-in";
import type { ProjectSession, ProjectUser } from "./owned-project-engine-store";
import {
	afterOwnedProjectCommit,
	createProjectEngineStore,
	projectUserResponse,
} from "./owned-project-engine-store";
import type { ProjectGuestProof } from "./owned-project-guest";
import { createOwnedProjectGuest } from "./owned-project-guest";
import { createOwnedProjectInvitationImport } from "./owned-project-invitation-import";
import { createOwnedProjectIssuer } from "./owned-project-issuer";
import {
	maximumProjectAuthorizationQueryLength,
	readSignedProjectIssuerQuery,
} from "./owned-project-issuer-authorization-query";
import { ProjectOAuthError } from "./owned-project-issuer-http";
import { ownedProjectIssuerMetadata } from "./owned-project-issuer-metadata";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { OwnedProjectOAuthOptions } from "./owned-project-oauth";
import {
	createOwnedProjectOAuth,
	maximumHostedSocialContinuationBodyBytes,
	ownedProjectHostedSocialContinuationInput,
	ownedProjectOAuthStartInput,
	ownedProjectOAuthUnlinkInput,
	projectOAuthProvider,
} from "./owned-project-oauth";
import {
	maximumProjectOAuthReturnLength,
	standardProjectOAuthReturnLength,
} from "./owned-project-oauth-store";
import {
	ownedProjectOpenApi,
	projectOpenApiPath,
} from "./owned-project-openapi";
import type { OwnedProjectOrganizationOptions } from "./owned-project-organization";
import { createOwnedProjectOrganizationHttp } from "./owned-project-organization";
import { createOwnedProjectOneTimeToken } from "./owned-project-one-time-token";
import type { OwnedProjectPasswordChangeOptions } from "./owned-project-password-change";
import { createOwnedProjectPasswordChange } from "./owned-project-password-change";
import { createOwnedProjectPersonalKeys } from "./owned-project-personal-keys";
import { createOwnedProjectRealmAdminMutations } from "./owned-project-realm-admin-mutations";
import { createOwnedProjectRealmAdminRead } from "./owned-project-realm-admin-read";
import { createOwnedProjectRealmImpersonation } from "./owned-project-realm-impersonation";
import {
	createOwnedProjectProfile,
	ownedProjectProfileBody,
} from "./owned-project-profile";
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
	projectSecurityBlockedMessage,
} from "./owned-project-security";
import { createOwnedProjectSecurityManagement } from "./owned-project-security-management";
import { createOwnedProjectServiceDirectory } from "./owned-project-service-directory";
import type { OwnedProjectSsoOptions } from "./owned-project-sso";
import {
	createOwnedProjectSso,
	ownedProjectSsoInput,
} from "./owned-project-sso";
import { createOwnedProjectSsoManagement } from "./owned-project-sso-management";
import type { OwnedProjectSupportOptions } from "./owned-project-support";
import { createOwnedProjectSupportHttp } from "./owned-project-support";
import { createOwnedProjectWallet } from "./owned-project-wallet";
import { createOwnedProjectWebhookManagement } from "./owned-project-webhook-management";
import { createOwnedRecoveryHttp } from "./owned-recovery-http";
import {
	createOwnedSignUpHttp,
	scheduleOwnedSignUpVerification,
} from "./owned-sign-up";
import type { ProjectAvatarStorage } from "./project-avatar-upload";
import { uploadProjectAvatar } from "./project-avatar-upload";
import type { Project } from "./registry";
import { consumeProxySessionCheck } from "./session-introspection-admission";
import { projectOrigin, projectSlug } from "./validation";

const passwordFields = {
	password: z.string().min(1).max(defaultPasswordPolicy.maxLength),
	callbackURL: z.string().max(standardProjectOAuthReturnLength).optional(),
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
const maximumHostedPasswordCallbackLength =
	maximumProjectOAuthReturnLength + "https://".length + 253;
const hostedPasswordCallback = z
	.string()
	.min(standardProjectOAuthReturnLength + 1)
	.max(maximumHostedPasswordCallbackLength);
const hostedEmailInput = emailInput.extend({
	callbackURL: hostedPasswordCallback,
});
const hostedUsernameInput = usernameInput.extend({
	callbackURL: hostedPasswordCallback,
});
const sessionIdInput = z.object({ id: z.string().min(1).max(160) }).strict();
const sessionTokenInput = z.object({ token: z.string() });
const deviceSessionInput = z.object({
	sessionToken: z.string().regex(/^[a-z0-9_-]{1,64}$/i),
});
const emptyInput = z.object({}).strict();
const mfaPasswordInput = z.object({ password: z.string().optional() });
const mfaEnableInput = mfaPasswordInput.extend({
	issuer: z.string().optional(),
	method: z.enum(["totp", "otp"]).optional(),
});
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
	accountLinks?: Pick<
		ProjectAccountLinkOptions,
		"publicLinkBaseURL" | "defer" | "deliver" | "onDeliveryFailure"
	> & {
		emailChange?: boolean;
		beforeDelete?: OwnedProjectAccountDeletionOptions["beforeDelete"];
	};
	adminDeletion?: Pick<
		OwnedProjectAdminDeletionOptions,
		"platformOrigin" | "readWorkspacePrincipal"
	> &
		Pick<Project, "id" | "workspaceId">;
	passwordChange?: Pick<
		OwnedProjectPasswordChangeOptions,
		"checkPasswordSafety"
	>;
	serviceDirectory?: Pick<
		Parameters<typeof createOwnedProjectServiceDirectory>[0],
		"projectId" | "environment" | "authorize"
	>;
	sdk?: {
		avatar?: ProjectAvatarStorage;
		nativePasskeys?: NativePasskeyCapability;
		personalApiKeys?: boolean;
		getBranding?(): Promise<ApplicationBranding>;
	};
	appName?: string;
	/** Enable the project issuer candidate in the isolated compatibility fixture. */
	issuer?: boolean | { errorURL?: string; platformOrigin?: string };
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
		| "reservedEmail"
		| "authorizeLinkedAccounts"
		| "missingBrowserSessionHeaders"
		| "auditContext"
		| "passwordSignIn"
		| "passkeySignIn"
		| "otherLinkedSignIn"
		| "readGuestUserId"
		| "denyProviderProfile"
	| "prepareProviderSignup"
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
		| "emailAliases"
		| "denyProviderProfile"
		| "prepareProviderSignup"
		| "cleanupExpiredPrimary"
		| "complete"
	>;
	scim?: { credentialHashSecret: string };
	manageSCIMConsole?: AuthEngine["manageSCIMConsole"];
	manageOrganizationConsole?: AuthEngine["manageOrganizationConsole"];
	manageUserConsole?: AuthEngine["manageUserConsole"];
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
	brokerTwoFactor?: AuthorizeProjectBrokerMfa;
	security?: {
		secret?: string;
		requireTrustedIP?: boolean;
		management?: boolean;
		newDevice?: {
			defer(delivery: () => Promise<void>): void;
			notify(
				user: Pick<ProjectUser, "id" | "email" | "name">,
				context: { ipAddress?: string; userAgent?: string },
			): Promise<void>;
		};
	};
	passkeys?: Parameters<typeof createOwnedProjectPasskeyHttp>[0]["rp"];
	walletOrigin?: string;
	agentHosts?: boolean;
	openApi?: boolean;
	analytics?: boolean;
	webhookManagement?: Pick<
		Parameters<typeof createOwnedProjectWebhookManagement>[0],
		"resolver" | "encryptionSecret" | "supportedEventTypes"
	>;
	recovery?: Omit<
		Parameters<typeof createOwnedRecoveryHttp>[0],
		| "database"
		| "project"
		| "policy"
		| "signingSecret"
		| "baseURL"
		| "basePath"
		| "trustedOrigins"
		| "auditContext"
		| "completeVerification"
		| "prepareEmailOtpReset"
		| "verifyHostedVerificationContinuation"
	>;
	emailAliases?: ProjectEmailAliasMap;
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
	return failure(429, projectSecurityBlockedCode, projectSecurityBlockedMessage);
}

function forbidden() {
	return failure(
		403,
		"FORBIDDEN",
		"This authentication request is not permitted.",
	);
}

async function requestBody(
	request: Pick<Request, "headers" | "body">,
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
	const missingSupportAdapter =
		policy.supportAccess?.enabled && !options.support;
	const slug = projectSlug.parse(options.project.slug);
	const origin = projectOrigin.parse(options.baseURL);
	const secure = origin.startsWith("https://");
	const securitySecret = options.security?.secret ?? options.signingSecret;
	const acceptedOrigins = new Set([
		origin,
		...options.trustedOrigins.map((item) => projectOrigin.parse(item)),
	]);
	if (
		!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath) ||
		options.signingSecret.length < 32 ||
		securitySecret.length < 32
	)
		throw new Error("Invalid owned project engine configuration.");
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);

	const emailAliases = createOwnedProjectEmailAliases(
		options.database, options.project.schemaName, options.emailAliases,
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
	const issuer =
		options.issuer &&
		createOwnedProjectIssuer({
			database: options.database,
			schemaName: options.project.schemaName,
			issuer: `${origin}${options.basePath}`,
			signingSecret: options.signingSecret,
			managementOrigins: acceptedOrigins,
			trustedIP: options.trustedIP,
			projectSlug: slug,
			platformOrigin:
				(typeof options.issuer === "object" && options.issuer.platformOrigin) ||
				origin,
			errorURL:
				typeof options.issuer === "object"
					? options.issuer.errorURL
					: undefined,
			readBody: requestBody,
			async readHostedBrowserActionBody(request) {
				const body = await requestBody(
					request,
					maximumProjectAuthorizationQueryLength + 128,
				);
				return body !== undefined &&
					Buffer.byteLength(JSON.stringify(body)) > maximumBodyBytes
					? body
					: undefined;
			},
			logout: {
				sessionCookie,
				requireMfa: policy.mfaMode === "required",
				clearBrowserSession: clearSessionCookies,
				async revokeSession(client, request, target, path, actorId) {
					const removed = await store.revoke(
						{ tokens: [target.token], userId: target.userId },
						path,
						Boolean(backchannel),
						client,
						actorId,
					);
					if (!removed)
						throw new ProjectOAuthError(
							"server_error",
							"Unable to complete logout",
							503,
						);
					deliverLogoutAfterCommit(client, request, removed.targets);
				},
			},
			readSession: (request, client) => currentSession(request.headers, client),
			async readAuthorizationSession(request, client, responseHeaders) {
				const current = await readBrowserRouteSession(
					client,
					request,
					"/oauth2/authorize",
					responseHeaders,
				);
				return ordinarySession(current?.token ?? null, current);
			},
			async readManagementUser(client, request, write) {
				const bearer = serverSessionBearer(request.headers);
				if (!bearer && !trustedRequest(request.headers, write)) return null;
				const current = await eligibleSession(
					bearer ?? tokenFrom(request.headers),
					client,
				);
				if (!current) return null;
				if (!write) return current.user;
				const user = await store.lockUser(client, current.user.id);
				if (
					!user ||
					user.banned ||
					user.directoryDisabled ||
					(policy.mfaMode === "required" &&
						(!user.emailVerified || !user.twoFactorEnabled)) ||
					!(await store.lockSession(client, current.token, user.id, false))
				)
					return null;
				return user;
			},
			async readConsoleOAuthSession(request, client) {
				return (
					(await support?.readConsoleOAuthSession(request, client)) ?? null
				);
			},
			keys: options.oauth?.tokenKeys ??
				options.mfaKeys ?? { secret: options.signingSecret },
		});
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
		secret: securitySecret,
		trustedIP: options.trustedIP,
		requireTrustedIP: options.security?.requireTrustedIP,
	});
	const newDevice = options.security?.newDevice;
	const notifications = new WeakMap<Request, () => Promise<void>>();
	const analyticsSessions = new WeakMap<
		Request,
		{ session: ProjectSession; source: ActivitySource }
	>();
	const providerSessionRenewals = new WeakMap<Request, Headers>();
	const committedLogoutTargets = new WeakMap<
		Request,
		ProjectBackchannelTarget[]
	>();
	const completedGuestUpgrades = new WeakMap<
		Request,
		{ proof: ProjectGuestProof; path: string }
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
		secret = options.signingSecret,
	) {
		const signed = value
			? `${value}.${createHmac("sha256", secret).update(value).digest("base64")}`
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
			current.expired ||
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

	function mfaEligibleUser(user: ProjectUser | null): user is ProjectUser {
		if (!user || user.banned || user.directoryDisabled) return false;
		if (!user.isAnonymous) return verifiedUser(user);
		return (
			policy.mfaMode === "optional" &&
			!policy.requireEmailVerification &&
			!user.directoryManaged
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

	function primaryAuditMetadata(path: string) {
		const callback =
			/^(\/(?:callback|oauth2\/callback|sso\/callback|sso\/saml2\/sp\/acs))\/([^/]+)$/.exec(
				path,
			);
		if (!callback) return { path, method: path.split("/").pop() };
		const enterprise = path.startsWith("/sso/");
		return {
			path: `${callback[1]}/:${enterprise ? "providerId" : "id"}`,
			method: enterprise ? "sso" : "social",
			provider: callback[2],
		};
	}

	async function insertAuditedSession(
		client: PoolClient,
		userId: string,
		request: Request,
		rememberMe: boolean,
		path: string,
		prior?: ProjectSession,
	) {
		const id = randomUUID();
		const token = btoa(
			String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))),
		)
			.replaceAll("+", "-")
			.replaceAll("/", "_");
		const session = await store.createSession(client, {
			id,
			token,
			userId,
			expiresIn: rememberMe || prior ? policy.sessionExpiresInSeconds : 86400,
			ip: security.trustedIP(request) ?? "",
			userAgent: request.headers.get("user-agent")?.slice(0, 512) ?? "",
			activeOrganizationId: prior?.activeOrganizationId,
			activeTeamId: prior?.activeTeamId,
		});
		await store.recordEvent(client, {
			type: "session.created",
			outcome: "success",
			userId,
			targetId: id,
			metadata: { path },
		});
		return { session, token };
	}

	async function createSession(
		client: PoolClient,
		user: ProjectUser,
		request: Request,
		rememberMe: boolean,
		path: string,
		prior?: ProjectSession,
	) {
		const eventMetadata = primaryAuditMetadata(path);
		const headers = new Headers();
		const existing = multiSessionTokens(request.headers);
		const mfaPolicyReadsBrowser =
			eventMetadata.path === "/sso/callback/:providerId" ||
			eventMetadata.path === "/sso/saml2/sp/acs/:providerId" ||
			path === "/siwe/verify";
		const readsIncomingBrowser =
			path === "/sign-in/email" ||
			path === "/sign-in/username" ||
			path === "/sign-in/social" ||
			eventMetadata.path === "/callback/:id" ||
			path === "/verify-email" ||
			path === "/email-otp/verify-email" ||
			path === "/magic-link/verify" ||
			path === "/sign-in/email-otp" ||
			path === "/passkey/verify-authentication";
		const owned = [];
		if (!prior) {
			const signedPrimary =
				readsIncomingBrowser && path !== "/sign-in/social"
					? tokenFrom(request.headers)
					: null;
			if (signedPrimary) {
				const browser = await store.session(
					signedPrimary,
					refreshWindow,
					client,
					{ includeExpired: true },
				);
				if (browser?.expired) {
					// Lock both kinds of signed session in one order when the primary belongs to another account.
					await client.query(
						`SELECT id FROM "session"
						 WHERE (token=$1 AND "expiresAt"<=statement_timestamp())
						    OR (token=ANY($2::text[]) AND "userId"=$3)
						 ORDER BY id FOR UPDATE`,
						[signedPrimary, existing.map(({ token }) => token), user.id],
					);
					// The installed anonymous after-hook cleans up the old primary before device replacement.
					await cleanupExpiredSession(
						client,
						request,
						signedPrimary,
						eventMetadata.path,
					);
				}
			}
			for (const item of existing) {
				// Device replacement removes stored same-account sessions, including expired rows.
				const previous = await store.session(
					item.token,
					refreshWindow,
					client,
					{ includeExpired: true },
				);
				if (previous?.user.id === user.id) owned.push(item);
			}
		}
		if (owned.length) {
			let actorId: string | null | undefined;
			if (
				path === "/two-factor/verify-totp" ||
				path === "/two-factor/verify-backup-code" ||
				(mfaPolicyReadsBrowser && policy.mfaMode !== "required")
			) {
				// Pending MFA and these optional-MFA flows leave the browser actor unset.
				actorId = null;
			} else if (mfaPolicyReadsBrowser || readsIncomingBrowser) {
				// The legacy policy or anonymous hook reads the incoming browser session before cleanup.
				const browserToken = tokenFrom(request.headers);
				const browser = browserToken
					? await store.session(browserToken, refreshWindow, client)
					: null;
				actorId = browser?.user.id ?? null;
			}
			const removed = await store.revoke(
				{ tokens: owned.map((item) => item.token), userId: user.id },
				eventMetadata.path,
				Boolean(backchannel),
				client,
				actorId,
			);
			if (!removed) throw unavailableLogout;
			deliverLogoutAfterCommit(client, request, removed.targets);
			for (const item of owned) writeCookie(headers, item.name, "", 0);
		}
		const { session, token } = await insertAuditedSession(
			client,
			user.id,
			request,
			rememberMe,
			eventMetadata.path,
			prior,
		);
		const id = session.id;
		const primaryPath = isPrimaryAuthenticationPath(path);
		if (!prior && primaryPath) {
			await store.recordEvent(client, {
				type: "auth.sign-in",
				outcome: "success",
				actorId: user.id,
				userId: user.id,
				targetId: id,
				...browserEventContext(request),
				metadata: eventMetadata,
			});
		}
		// The audit trigger records ordinary primary sign-ins. Rotation and
		// organization attribution use the surviving replacement session.
		if (
			analytics &&
			!user.isAnonymous &&
			(prior || (primaryPath && session.activeOrganizationId))
		) {
			const source = primaryPath ? 1 : 4;
			afterOwnedProjectCommit(client, () =>
				analyticsSessions.set(request, { session, source }),
			);
		}
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
		if (!prior && primaryPath && user.emailVerified) {
			const name = `${prefix}control_device`;
			const known = await security.registerDevice(
				client,
				request,
				user.id,
				readLegacySessionCookie(request.headers, name, securitySecret),
			);
			writeCookie(headers, name, known.token, 180 * 86400, securitySecret);
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
		const callbackURL = new URL(callback);
		const callbackOrigin = callbackURL.origin;
		const projectProxy = options.basePath !== "/api/auth";
		const target = new URL(
			projectProxy ? "/sign-in?challenge=two-factor" : "/two-factor",
			callbackOrigin,
		);
		if (
			issuer &&
			!projectProxy &&
			callbackOrigin === origin &&
			!callbackURL.hash
		) {
			const signedPath = oauthBrowserReturnPath(
				callbackURL.pathname + callbackURL.search,
			);
			const query =
				signedPath && new URL(signedPath, origin).searchParams.toString();
			if (query && readSignedProjectIssuerQuery(query, options.signingSecret)) {
				target.searchParams.set("callbackUrl", signedPath);
				return target.href;
			}
		}
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
		providerProof?: {
			managed?: boolean;
			allowUnverifiedEmail: boolean;
			anonymousUserId?: string;
			wallet?: { address: string; chainId: number };
		},
	): Promise<Response> {
		const passkeyPath =
			path === "/passkey/verify-registration" ||
			path === "/passkey/verify-authentication";
		if (
			(!activeUser(user) && !(passkeyPath && passkeyAnonymousOwner(user))) ||
			(user.directoryManaged && !providerProof?.managed)
		)
			return forbidden();
		if (
			!verifiedUser(user) &&
			(!providerProof?.allowUnverifiedEmail || policy.mfaMode === "required")
		)
			return failure(403, "EMAIL_NOT_VERIFIED", "Email not verified");
		if (missingSupportAdapter) return unsupported();
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
			const auditPath = primaryAuditMetadata(path).path;
			// Native records the temporary session and its removal while starting MFA.
			// Both events commit with the challenge, without exposing a live session.
			const { session: pending } = await insertAuditedSession(
				client,
				user.id,
				request,
				rememberMe,
				auditPath,
			);
			const discarded = await client.query('DELETE FROM "session" WHERE id=$1', [
				pending.id,
			]);
			if (discarded.rowCount !== 1)
				throw new Error("The temporary MFA session was not removed.");
			const actorId =
				policy.mfaMode === "required" || path === "/passkey/verify-registration"
					? (await currentSession(request.headers, client))?.user.id
					: undefined;
			await store.recordEvent(client, {
				type: "session.deleted",
				outcome: "success",
				actorId,
				userId: user.id,
				targetId: pending.id,
				metadata: { path: auditPath },
			});
			if (isPrimaryAuthenticationPath(path))
				await store.recordEvent(client, {
					type: "auth.mfa-required",
					outcome: "success",
					...browserEventContext(request),
					metadata: { path: auditPath },
				});
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
		if (
			guest &&
			!user.isAnonymous &&
			(path.startsWith("/sign-in/") ||
				path.startsWith("/callback/") ||
				path === "/verify-email" ||
				path === "/email-otp/verify-email" ||
				path === "/magic-link/verify" ||
				path === "/passkey/verify-authentication")
		) {
			const proof = await currentGuestProof(
				request.headers,
				client,
				providerProof?.anonymousUserId,
				user.id,
			);
			if (proof)
				afterOwnedProjectCommit(client, () =>
					completedGuestUpgrades.set(request, {
						proof,
						path:
							path === "/sign-in/email" ? path : "/guest/account-upgraded",
					}),
				);
		}
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
		if (path === "/email-otp/verify-email")
			return json({ status: true, token, user: value }, 200, headers);
		if (path === "/sign-in/social")
			return json({ redirect: false, token, user: value }, 200, headers);
		if (providerProof?.wallet)
			return json(
				{
					token,
					success: true,
					user: {
						id: user.id,
						walletAddress: providerProof.wallet.address,
						chainId: providerProof.wallet.chainId,
					},
				},
				200,
				headers,
			);
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
		auditContext: browserEventContext,
		async lockAuthority(client, request, { fresh }) {
			const current = await currentSession(request.headers, client);
			if (!current) return null;
			const user = await store.lockUser(client, current.user.id);
			if (
				!mfaEligibleUser(user) ||
				!(await store.lockSession(client, current.token, user.id, fresh))
			)
				return null;
			const locked = await store.session(current.token, refreshWindow, client);
			if (!locked) return null;
			return { user, session: locked.session };
		},
		async rotateSession(client, request, authority, path) {
			const user = await store.lockUser(client, authority.user.id);
			if (!mfaEligibleUser(user)) throw changedMfaOwner;
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

	function admitTwoFactorRoute(request: Request, path: string) {
		const ip = options.trustedIP(request);
		if (!ip || !isIP(ip)) return forbidden();
		return store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, ip, path, {
				max: 3,
				windowMs: 10_000,
			}),
		);
	}

	async function manageMfa(
		request: Request,
		operation: "enable" | "disable" | "get-totp-uri" | "generate-backup-codes",
	) {
		if (!trustedRequest(request.headers, true)) return forbidden();
		const refused = await admitTwoFactorRoute(request, `/two-factor/${operation}`);
		if (refused) return refused;
		const token = tokenFrom(request.headers);
		const session = token ? await store.session(token, refreshWindow) : null;
		if (session?.session.impersonatedBy)
			return failure(
				403,
				"FORBIDDEN",
				"Authentication changes and account deletion are unavailable during impersonation.",
			);
		const body = await requestBody(request);
		const input = (
			operation === "enable" ? mfaEnableInput : mfaPasswordInput
		).safeParse(body);
		if (!input.success) {
			if (body === undefined)
				return failure(400, "INVALID_BODY", "Invalid two-factor request.");
			if (operation !== "get-totp-uri")
				await mfaEnrollment.recordMalformedMutation(
					request,
					`/two-factor/${operation}`,
				);
			const message = input.error.issues
				.map((issue) => `[${["body", ...issue.path].join(".")}] ${issue.message}`)
				.join("; ");
			return failure(400, "VALIDATION_ERROR", message);
		}
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
		const path =
			method === "totp"
				? "/two-factor/verify-totp"
				: "/two-factor/verify-backup-code";
		const refused = await admitTwoFactorRoute(request, path);
		if (refused) return refused;
		const body = z
			.object({
				code: z.string().min(1).max(128),
				trustDevice: z.boolean().optional(),
				disableSession: z.boolean().optional(),
			})
			.safeParse(await requestBody(request));
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a verification code.");
		if (await store.transaction((client) => security.admit(client, request)))
			return securityBlocked();
		const browserHeaders = new Headers();
		const browser = tokenFrom(request.headers)
			? await store.transaction((client) =>
					readBrowserRouteSession(client, request, path, browserHeaders),
				)
			: null;
		if (browser && ordinarySession(browser.token, browser)) {
			const result = await mfaEnrollment.verify(request, {
				method,
				code: body.data.code,
			});
			if (result.status === "rejected") {
				await store.transaction(async (client) => {
					await security.failed(client, request, path);
					await recordPrimaryFailure(client, request, path, result.code);
				});
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
		const verifyOnly = method === "backup" && body.data.disableSession === true;
		try {
			const result = await mfa.complete(
				request.headers,
				{ method, ...body.data },
				async (client, pending) => {
					const user = await store.lockUser(client, pending.userId);
					if (
						(!activeUser(user) && !passkeyAnonymousOwner(user)) ||
						(policy.mfaMode === "required" && !user.emailVerified) ||
						!user.twoFactorEnabled ||
						missingSupportAdapter
					)
						throw changedMfaOwner;
					if (verifyOnly) return { verifiedUser: projectUserResponse(user) };
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
				await store.transaction(async (client) => {
					await security.failed(client, request, path);
					await recordPrimaryFailure(client, request, path, result.code);
				});
				for (const cookie of result.setCookies)
					browserHeaders.append("Set-Cookie", cookie);
				return failure(
					result.httpStatus,
					result.code,
					result.message,
					browserHeaders,
				);
			}
			if ("verifiedUser" in result.session)
				return json({ user: result.session.verifiedUser }, 200, browserHeaders);
			const { session, user, headers } = result.session;
			// Expire the old primary before writing the newly authenticated session.
			const cookies = new Set([
				...browserHeaders.getSetCookie(),
				...headers.getSetCookie(),
				...result.setCookies,
			]);
			headers.delete("Set-Cookie");
			for (const cookie of cookies)
				headers.append("Set-Cookie", cookie);
			return json({ session, user }, 200, headers);
		} catch (error) {
			if (error !== deniedMfa && error !== changedMfaOwner) throw error;
			const response = error === deniedMfa ? securityBlocked() : forbidden();
			for (const cookie of browserHeaders.getSetCookie())
				response.headers.append("Set-Cookie", cookie);
			return response;
		}
	}

	function browserEventContext(request: Request) {
		return {
			ipAddress: security.trustedIP(request) ?? undefined,
			userAgent: request.headers.get("user-agent") ?? undefined,
		};
	}

	function recordPrimaryFailure(
		client: PoolClient,
		request: Request,
		path: string,
		errorCode: string,
	) {
		return store.recordEvent(client, {
			type: "auth.sign-in",
			outcome: "failure",
			...browserEventContext(request),
			metadata: { path, errorCode },
		});
	}

	async function providerCallback(
		request: Request,
		endpoint:
			| "/callback/:id"
			| "/sso/callback/:providerId"
			| "/sso/saml2/sp/acs/:providerId",
		handle: () => Promise<Response>,
	) {
		const response = await handle();
		if (controlResponseFailure(response, response.headers).failed)
			await store.transaction(async (client) => {
				await security.failed(client, request, endpoint);
				const code = ownedCallbackFailureCode(response);
				if (code) await recordPrimaryFailure(client, request, endpoint, code);
			});
		return response;
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
		const ip = security.trustedIP(request);
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, ip, path, {
				max: 3,
				windowMs: 10_000,
			}),
		);
		if (limited) return limited;
		if (!policy.emailAndPasswordEnabled)
			return failure(
				400,
				"EMAIL_PASSWORD_DISABLED",
				"Email and password is not enabled",
			);
		if (missingSupportAdapter) return unsupported();
		const hosted =
			issuer &&
			options.basePath === "/api/auth" &&
			request.headers.get("origin") === origin &&
			hostedPasswordSignInRequests.has(request);
		const parse = (raw: unknown, extended = false) =>
			field === "email"
				? (extended ? hostedEmailInput : emailInput).safeParse(
						emailAliases.normalizeInput(raw),
					)
				: (extended ? hostedUsernameInput : usernameInput).safeParse(raw);
		const raw = await requestBody(hosted ? request.clone() : request);
		const regular = parse(raw);
		const body =
			hosted && !regular.success
				? parse(
						raw === undefined
							? await requestBody(
									request,
									maximumHostedPasswordCallbackLength + 2048,
								)
							: raw,
						true,
					)
				: regular;
		const invalidBody = () =>
			failure(
				400,
				"INVALID_BODY",
				"Supply a valid identifier and password.",
			);
		if (!body.success) return invalidBody();
		const callback = callbackURL(body.data.callbackURL, request);
		if (callback === null) return forbidden();
		if (!regular.success) {
			if (!issuer || !callback) return invalidBody();
			const target = new URL(callback);
			const path = target.pathname + target.search;
			if (
				callback !== origin + path ||
				oauthBrowserReturnPath(path) !== path ||
				!(await verifiedHostedOAuthContinuation(
					{ readOAuthContext: issuer.readContext },
					target.hostname,
					target.search.slice(1),
				))
			)
				return invalidBody();
		}

		const login = (
			"email" in body.data ? body.data.email : body.data.username
		).toLowerCase();
		const address = field === "email" ? await emailAliases.resolve(login) : { email: login };
		if (!address) return failure(401, invalidCode, invalidMessage);
		const identity = field === "email" ? { email: address.email } : { username: login };
		const recordFailure = (client: PoolClient) =>
			recordPrimaryFailure(client, request, path, invalidCode);
		if (
			await store.transaction((client) =>
				security.admit(client, request, identity),
			)
		)
			return securityBlocked();

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

		const credential = await store.credential(address.email, undefined, field);
		const hash = credential?.password;
		if (
			!credential ||
			(address.userId && credential.id !== address.userId) ||
			!hash ||
			!(await clerkCompatiblePasswords.verify({
				hash,
				password: body.data.password,
			}))
		) {
			if (!hash) await clerkCompatiblePasswords.hash(body.data.password);
			await store.transaction(async (client) => {
				await security.failed(client, request, path, identity);
				await recordFailure(client);
			});
			return failure(401, invalidCode, invalidMessage);
		}

		return store.transaction(async (client) => {
			const bound = address.userId ? await emailAliases.resolve(login, client) : address;
			const current = bound ? await store.credential(bound.email, client, field) : null;
			if (
				!current ||
				(address.userId && bound?.userId !== address.userId) ||
				current.id !== credential.id ||
				current.password !== hash
			) {
				await security.failed(client, request, path, identity);
				await recordFailure(client);
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
			if (
				recoveryHttp &&
				result.status === 403 &&
				policy.requireEmailVerification &&
				!current.emailVerified &&
				activeUser(current) &&
				!current.directoryManaged
			)
				afterOwnedProjectCommit(client, () =>
					recoveryHttp.resendAfterPassword(current, callback, request),
				);
			if (result.status >= 400 && result.status < 500 && result.status !== 429)
				await security.failed(client, request, path, identity);
			return result;
		});
	}

	async function cleanupExpiredSession(
		client: PoolClient,
		request: Request,
		token: string,
		path: string,
	) {
		const removed = await store.revoke(
			{ tokens: [token], expiredOnly: true },
			path,
			Boolean(backchannel),
			client,
		);
		if (!removed) return null;
		deliverLogoutAfterCommit(client, request, removed.targets);
		// A concurrent renewal may have committed while the expiration check waited.
		return removed.ids.length === 0
			? store.session(token, refreshWindow, client)
			: null;
	}

	async function cleanupExpiredBrowserSession(request: Request, path: string) {
		const token = tokenFrom(request.headers);
		if (!token) return;
		await store.transaction(async (client) => {
			const observed = await store.session(token, refreshWindow, client, {
				includeExpired: true,
			});
			if (observed?.expired)
				await cleanupExpiredSession(client, request, token, path);
		});
	}

	async function readBrowserRouteSession(
		client: PoolClient,
		request: Request,
		path: string,
		headers: Headers,
		token = tokenFrom(request.headers),
	) {
		if (!token) return null;
		const row = await store.session(token, refreshWindow, client, {
			includeExpired: true,
		});
		const observed = row?.expired
			? await cleanupExpiredSession(client, request, token, path)
			: row;
		if (!observed) {
			clearSessionCookies(headers);
			return null;
		}
		return { token, ...observed };
	}

	async function missingBrowserSessionHeaders(request: Request, path: string) {
		const token = tokenFrom(request.headers);
		if (!token) return null;
		return store.transaction(async (client) => {
			const headers = new Headers({ "cache-control": "no-store" });
			const current = await readBrowserRouteSession(
				client,
				request,
				path,
				headers,
				token,
			);
			return current ? null : headers;
		});
	}

	async function readSession(request: Request) {
		if (!trustedRequest(request.headers, false)) return forbidden();
		let headers = new Headers();
		const token = tokenFrom(request.headers);
		let observed = token
			? await store.session(token, refreshWindow, undefined, {
					includeExpired: true,
				})
			: null;
		if (token && observed?.expired)
			observed = await store.transaction((client) =>
				cleanupExpiredSession(client, request, token, "/get-session"),
			);
		if (observed?.session.impersonatedBy) {
			const url = new URL(request.url);
			if (
				request.method !== "GET" ||
				url.origin !== origin ||
				url.pathname !== `${options.basePath}/get-session`
			)
				return forbidden();
			return (
				(await realmImpersonation.read(request)) ??
				(await support?.readBrowserSession(request)) ??
				json(null)
			);
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
			const { token, user } = current;
			const refreshed = await store.transaction(async (client) => {
				if (!(await store.lockUser(client, user.id))) return null;
				const selected = await lockExistingSession(client, token, user.id);
				if (!selected) return null;
				if (!selected.refreshDue) return { current: selected };
				const result = await reissueExistingSession(
					client,
					request,
					selected,
					"/get-session",
				);
				if (result instanceof Response) return result;
				return {
					current: { ...selected, session: result.session },
					headers: result.headers,
				};
			});
			if (refreshed instanceof Response) return refreshed;
			if (!refreshed) {
				clearSessionCookies(headers);
				return json(null, 200, headers);
			}
			current = refreshed.current;
			if (refreshed.headers) headers = refreshed.headers;
		}
		if (
			analytics &&
			!current.user.isAnonymous &&
			!request.headers.has("authorization") &&
			request.method === "GET" &&
			new URL(request.url).pathname === `${options.basePath}/get-session`
		)
			await analytics.session(current.session, 2);
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
		const logoutTargets = await store.transaction(async (client) => {
			const removed = tokens.length
				? await store.revoke(
						{ tokens },
						"/sign-out",
						Boolean(backchannel),
						client,
					)
				: { targets: [] };
			if (!removed) return null;
			await store.recordEvent(client, {
				type: "session.signed-out",
				outcome: "success",
				...browserEventContext(request),
				metadata: { path: "/sign-out" },
			});
			return removed.targets;
		});
		if (!logoutTargets) return unsupported();
		await backchannel?.(logoutTargets);
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
		if (!revoke) {
			if (tokenFrom(request.headers, name) !== token) return invalid();
			const current = await eligibleSession(token);
			if (!current) {
				writeCookie(headers, name, "", 0);
				return invalid();
			}
			setActiveDeviceCookie(headers, request, token);
			return json(publicDeviceSession(current), 200, headers);
		}

		const path = "/multi-session/revoke";
		return store.transaction(async (client) => {
			const observed = await readBrowserRouteSession(
				client,
				request,
				path,
				headers,
			);
			const current = ordinarySession(observed?.token ?? null, observed);
			if (!current)
				return failure(401, "UNAUTHORIZED", "Unauthorized", headers);
			if (tokenFrom(request.headers, name) !== token) return invalid();
			const removed = await store.revoke(
				{ tokens: [token] },
				path,
				Boolean(backchannel),
				client,
				current.user.id,
			);
			if (!removed) return unsupported();
			deliverLogoutAfterCommit(client, request, removed.targets);
			writeCookie(headers, name, "", 0);
			if (current.token === token) {
				let replacement: string | undefined;
				for (const candidate of multiSessionTokens(request.headers)) {
					if (
						candidate.token !== token &&
						(await eligibleSession(candidate.token, client))
					) {
						replacement = candidate.token;
						break;
					}
				}
				if (replacement) setActiveDeviceCookie(headers, request, replacement);
				else clearSessionCookies(headers);
			}
			return json({ status: true }, 200, headers);
		});
	}

	function serverSessionBearer(headers: Headers) {
		return readLegacyServerSessionBearer(headers, options.signingSecret);
	}

	function providerSessionBearer(request: Request) {
		return options.basePath === `/api/projects/${slug}/auth`
			? serverSessionBearer(request.headers)
			: null;
	}

	function sessionMutationOrigin(request: Request) {
		const { headers } = request;
		const from = headers.get("origin");
		const site = headers.get("sec-fetch-site");
		if (site === "cross-site")
			return failure(403, "INVALID_ORIGIN", "Invalid origin");
		if (!headers.has("cookie")) return null;
		const referrer = headers.get("referer");
		const resolved =
			from === "null" && site === "same-origin"
				? origin
				: from ||
					(referrer && URL.canParse(referrer)
						? new URL(referrer).origin
						: null);
		if (!resolved || resolved === "null")
			return failure(403, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin");
		return acceptedOrigins.has(resolved)
			? null
			: failure(403, "INVALID_ORIGIN", "Invalid origin");
	}

	async function renewAuthorizedSession(
		request: Request,
		current: { token: string; refreshDue: boolean },
		client: PoolClient,
		headers: Headers,
		allowServerToken = true,
	) {
		const token = current.token;
		if (
			current.refreshDue &&
			!new URL(request.url).searchParams.get("disableRefresh") &&
			!tokenFrom(request.headers, rememberCookie) &&
			(await store.refresh(
				token,
				policy.sessionExpiresInSeconds,
				updateAge,
				client,
			))
		) {
			writeCookie(
				headers,
				sessionCookie,
				token,
				policy.sessionExpiresInSeconds,
			);
			if (allowServerToken && isServerTokenRequest(request.headers)) {
				const value = headers
					.getSetCookie()[0]
					?.split(";", 1)[0]
					?.slice(sessionCookie.length + 1);
				if (value) {
					headers.set("set-auth-token", value);
					headers.set("access-control-expose-headers", "set-auth-token");
				}
			}
		}
	}

	async function revokeBrowserSessions(
		request: Request,
		path: "/revoke-other-sessions" | "/revoke-sessions" | "/revoke-session",
	) {
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		const originFailure = sessionMutationOrigin(request);
		if (originFailure) return originFailure;
		const target =
			path === "/revoke-session"
				? sessionTokenInput.safeParse(await requestBody(request))
				: null;
		if (target && !target.success)
			return failure(400, "VALIDATION_ERROR", "A session token is required.");

		const token =
			serverSessionBearer(request.headers) ?? tokenFrom(request.headers);
		const headers = new Headers();
		const event = {
			type:
				path === "/revoke-session"
					? "session.revoked"
					: path === "/revoke-other-sessions"
						? "session.revoked-others"
						: "session.revoked-all",
			...browserEventContext(request),
		};
		const unauthorized = async (client: PoolClient) => {
			await store.recordEvent(client, {
				...event,
				outcome: "failure",
				metadata: { path, errorCode: "UNAUTHORIZED" },
			});
			return failure(401, "UNAUTHORIZED", "Unauthorized", headers);
		};
		if (!token) return store.transaction(unauthorized);
		return store.transaction(async (client) => {
			const observed = await store.session(token, refreshWindow, client, {
				includeExpired: true,
			});
			if (!observed) {
				clearSessionCookies(headers);
				return unauthorized(client);
			}
			if (!observed.expired && !ordinarySession(token, observed))
				return unauthorized(client);
			// Serialize this user's sign-ins and authorization mutations before
			// locking the caller and the set of sessions it may revoke.
			const user = await store.lockUser(client, observed.user.id);
			if (!user) return unauthorized(client);
			if (
				observed.expired &&
				!(await cleanupExpiredSession(client, request, token, path))
			) {
				clearSessionCookies(headers);
				return unauthorized(client);
			}
			if (!(await store.lockSession(client, token, user.id, false)))
				return unauthorized(client);
			const current = await eligibleSession(token, client);
			if (!current || current.user.id !== user.id) return unauthorized(client);

			await renewAuthorizedSession(request, current, client, headers);
			const removed = await store.revoke(
				target
					? { userId: user.id, tokens: [target.data.token] }
					: {
							userId: user.id,
							...(path === "/revoke-other-sessions"
								? { exceptActiveToken: token }
								: {}),
						},
				path,
				Boolean(backchannel),
				client,
			);
			if (!removed) throw unavailableLogout;
			await store.recordEvent(client, {
				...event,
				outcome: "success",
				actorId: user.id,
				userId: user.id,
				metadata: { path },
			});
			deliverLogoutAfterCommit(client, request, removed.targets);
			return json({ status: true }, 200, headers);
		});
	}

	async function revokeSdkSession(request: Request) {
		const path = "/sdk/sessions/revoke";
		const originFailure = sessionMutationOrigin(request);
		if (originFailure) return originFailure;
		if (request.headers.has("authorization"))
			return json(
				{ message: "Use your signed-in browser session for this action." },
				403,
			);
		if (!trustedRequest(request.headers, true))
			return json(
				{ message: "Use a trusted application origin for account changes." },
				403,
			);
		const body = sessionIdInput.safeParse(await requestBody(request));
		if (!body.success)
			return failure(400, "VALIDATION_ERROR", "A session ID is required.");
		const headers = new Headers({
			"cache-control": "no-store",
			pragma: "no-cache",
		});
		return store.transaction(async (client) => {
			const browser = await readBrowserRouteSession(
				client,
				request,
				path,
				headers,
			);
			const observed = ordinarySession(browser?.token ?? null, browser);
			if (
				!observed ||
				!(await store.lockUser(client, observed.user.id)) ||
				!(await store.lockSession(client, observed.token, observed.user.id, false))
			)
				return new Response(null, { status: 401, headers });
			const current = await currentSession(request.headers, client);
			if (!current) return new Response(null, { status: 401, headers });
			if (!current.user.emailVerified)
				return json(
					{ message: "A verified, active project account is required." },
					403,
					headers,
				);
			const { user, session, token } = current;
			await renewAuthorizedSession(request, current, client, headers, false);
			const removed = await store.revoke(
				{ id: body.data.id, userId: user.id, currentToken: token },
				path,
				Boolean(backchannel),
				client,
			);
			if (!removed) throw unavailableLogout;
			if (!removed.ids.length)
				return json(
					{ message: "This session does not belong to your project account." },
					404,
					headers,
				);
			// The legacy SDK route also invalidates this account's other grants and challenges.
			await clearUserAuthentication(client, user.id);
			await store.recordEvent(client, {
				type: "session.revoked",
				outcome: "success",
				actorId: user.id,
				userId: user.id,
				targetId: body.data.id,
				userAgent: request.headers.get("user-agent") ?? undefined,
			});
			if (body.data.id === session.id) clearSessionCookies(headers);
			deliverLogoutAfterCommit(client, request, removed.targets);
			return json({ success: true }, 200, headers);
		});
	}

	async function confirmSessionListAuthority(
		request: Request,
		client: PoolClient,
		current: NonNullable<Awaited<ReturnType<typeof store.session>>>,
		headers: Headers,
	) {
		if (!current.session.impersonatedBy) return current;
		const administrator = await realmImpersonation.readAuthority(
			request,
			client,
		);
		const proof =
			administrator === undefined
				? await support?.readBrowserAuthority(request, client)
				: administrator;
		if (proof === "clear") clearSessionCookies(headers);
		return proof &&
			typeof proof !== "string" &&
			proof.session.id === current.session.id &&
			proof.user.id === current.user.id
			? proof
			: null;
	}

	async function listNativeSessions(request: Request) {
		const path = "/list-sessions";
		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		const caller = request.headers.get("origin");
		if (
			request.headers.get("sec-fetch-site") === "cross-site" ||
			(caller !== null && !acceptedOrigins.has(caller))
		)
			return forbidden();
		const direct = options.basePath !== "/api/auth";
		const token =
			(direct ? serverSessionBearer(request.headers) : null) ??
			tokenFrom(request.headers);
		const headers = new Headers();
		const unauthorized = () =>
			failure(401, "UNAUTHORIZED", "Unauthorized", headers);
		if (!token) return unauthorized();
		return store.transaction(async (client) => {
			let observed: Awaited<ReturnType<typeof store.session>> | null =
				await store.session(token, refreshWindow, client, { includeExpired: true });
			if (observed?.expired)
				observed = await cleanupExpiredSession(client, request, token, path);
			if (!observed) {
				clearSessionCookies(headers);
				return unauthorized();
			}
			if (observed.user.banned || observed.user.directoryDisabled)
				return unauthorized();
			const current = await confirmSessionListAuthority(
				request,
				client,
				observed,
				headers,
			);
			if (!current) return unauthorized();
			const { session, user } = current;
			if (!session.impersonatedBy) {
				await renewAuthorizedSession(
					request,
					{ ...current, token },
					client,
					headers,
					direct,
				);
				const renewedBearer = headers.get("set-auth-token");
				if (renewedBearer)
					headers.set("set-auth-token", decodeURIComponent(renewedBearer));
				if (
					policy.mfaMode === "required" &&
					(!user.emailVerified || !user.twoFactorEnabled)
				)
					return json(
						{ message: "This application requires an already verified account enrolled in MFA." },
						403,
						headers,
					);
			}
			if (Date.now() - Date.parse(session.createdAt) >= 86_400_000)
				return failure(403, "SESSION_NOT_FRESH", "Session is not fresh", headers);
			return json(await store.listNativeSessions(user.id, client), 200, headers);
		});
	}

	async function listSdkSessions(request: Request) {
		if (request.headers.has("authorization"))
			return json(
				{ message: "Use your signed-in browser session for this action." },
				403,
			);
		if (!trustedRequest(request.headers, false)) return forbidden();
		const headers = new Headers({
			"cache-control": "no-store",
			pragma: "no-cache",
		});
		const unauthorized = () => new Response(null, { status: 401, headers });
		if (!tokenFrom(request.headers)) return unauthorized();
		return store.transaction(async (client) => {
			const observed = await readBrowserRouteSession(
				client,
				request,
				"/sdk/sessions",
				headers,
			);
			if (!observed || observed.user.directoryDisabled) return unauthorized();
			const current = await confirmSessionListAuthority(
				request,
				client,
				observed,
				headers,
			);
			if (!current) return unauthorized();
			const { session, user } = current;
			if (
				policy.mfaMode === "required" &&
				!session.impersonatedBy &&
				(!user.emailVerified || !user.twoFactorEnabled)
			)
				return json(
					{ message: "This application requires an already verified account enrolled in MFA." },
					403,
					headers,
				);
			if (!user.emailVerified || user.banned)
				return json(
					{ message: "A verified, active project account is required." },
					403,
					headers,
				);
			if (!session.impersonatedBy)
				await renewAuthorizedSession(
					request,
					{ ...current, token: observed.token },
					client,
					headers,
					false,
				);
			const sessions = await store.list(user.id, client);
			return json(
				{
					sessions: sessions.map(({ id, createdAt, expiresAt, ipAddress, userAgent }) => ({
						id,
						createdAt,
						expiresAt,
						...(ipAddress ? { ipAddress } : {}),
						...(userAgent ? { userAgent } : {}),
					})),
					currentSessionId: session.id,
				},
				200,
				headers,
			);
		});
	}

	async function listAccountSessions(request: Request) {
		if (!trustedRequest(request.headers, false)) return forbidden();
		const headers = new Headers({ "cache-control": "no-store" });
		const response = await store.transaction(async (client) => {
			const observed = await readBrowserRouteSession(
				client,
				request,
				"/account/sessions",
				headers,
			);
			const current = ordinarySession(observed?.token ?? null, observed);
			if (!current) return new Response(null, { status: 401, headers });
			if (!current.user.emailVerified) return forbidden();
			return json({
				sessions: await store.list(current.user.id, client),
				currentSessionId: current.session.id,
			});
		});
		await deliverCommittedLogout(request);
		return response;
	}

	async function revokeAccountSession(request: Request, value: { id: string }) {
		if (!trustedRequest(request.headers, true, revocationOrigins))
			return forbidden();
		const body = sessionIdInput.safeParse(value);
		if (!body.success)
			return failure(400, "INVALID_BODY", "Supply a session ID.");
		const path = "/account/sessions/revoke";
		const headers = new Headers({ "cache-control": "no-store" });
		const response = await store.transaction(async (client) => {
			const observed = await readBrowserRouteSession(
				client,
				request,
				path,
				headers,
			);
			const current = ordinarySession(observed?.token ?? null, observed);
			if (!current) return new Response(null, { status: 401, headers });
			if (!current.user.emailVerified) return forbidden();
			const removed = await store.revoke(
				{
					id: body.data.id,
					userId: current.user.id,
					currentToken: current.token,
				},
				path,
				Boolean(backchannel),
				client,
			);
			if (!removed) return unsupported();
			if (!removed.ids.length)
				return failure(404, "NOT_FOUND", "This session no longer exists.");
			deliverLogoutAfterCommit(client, request, removed.targets);
			if (body.data.id === current.session.id) clearSessionCookies(headers);
			return json({ success: true }, 200, headers);
		});
		await deliverCommittedLogout(request);
		return response;
	}

	const agentHosts =
		options.agentHosts &&
		createOwnedProjectAgentHosts({
			store,
			trustedRequest,
			trustedIP: options.trustedIP,
			readBody: requestBody,
			async authorizeBrowser(client, request, mode) {
				const current = await currentSession(request.headers, client);
				if (!current) return null;
				if (mode === "read") return current.user.id;
				const fresh = mode === "fresh";
				if (fresh && !freshFeatureSession(current)) return null;
				const user = await store.lockUser(client, current.user.id);
				if (
					!user ||
					!(await store.lockSession(client, current.token, user.id, false))
				)
					return null;
				const locked = await eligibleSession(current.token, client);
				return locked?.user.id === user.id &&
					(!fresh || freshFeatureSession(locked))
					? user.id
					: null;
			},
		});

	// A locked owner session or verified credential binds the exact anonymous
	// identity. Its current role and verification flag are stored authority.
	function passkeyAnonymousOwner(
		user: ProjectUser | null,
	): user is ProjectUser & { isAnonymous: true } {
		return Boolean(
			user?.isAnonymous === true &&
				!user.banned &&
				!user.directoryManaged &&
				!user.directoryDisabled &&
				policy.mfaMode === "optional" &&
				!policy.requireEmailVerification,
		);
	}

	function passkeyOwner(user: ProjectUser | null): user is ProjectUser {
		return (
			(activeUser(user) && verifiedUser(user)) || passkeyAnonymousOwner(user)
		);
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
			auditContext: browserEventContext,
			writeCookie,
			recordFailedAuthentication: (request) =>
				store.transaction((client) =>
					security.failed(client, request, "/passkey/verify-authentication"),
				),
			async readSession(request) {
				const current = await currentSession(request.headers);
				if (!current) return null;
				return {
					userId: current.user.id,
					email: current.user.email,
					fresh:
						Date.now() - new Date(current.session.createdAt).getTime() < 86_400_000,
				};
			},
			async withSession(request, userId, fresh, work) {
				const token = tokenFrom(request.headers);
				if (!token) return null;
				return store.transaction(async (client) => {
					const user = await store.lockUser(client, userId);
					if (
						!passkeyOwner(user) ||
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
					if (!passkeyOwner(user) || user.directoryManaged)
						return null;
					if (
						user.isAnonymous &&
						user.twoFactorEnabled &&
						!(await mfa.hasEnrolledFactor(client, user.id))
					)
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
			emailAliases,
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
			emailAliases,
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
	const emailOtpVerification =
		emailSignIn &&
		createOwnedProjectEmailOtpVerification({
			database: options.database,
			project: options.project,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			emailAliases,
			email: emailSignIn.email,
			defer: emailSignIn.defer,
			onDeliveryFailure: () =>
				emailSignIn.onDeliveryFailure?.("email-otp/send-verification-otp"),
			auditContext: browserEventContext,
			async admit(request, operation, email) {
				if (operation !== "email-otp/check-verification-otp") {
					const denied = await store.transaction((client) =>
						security.admit(client, request, {
							email,
							message: operation === "email-otp/send-verification-otp",
						}),
					);
					if (denied) return securityBlocked();
				}
				return emailSignIn.admit(request, operation, email);
			},
			completeVerification({ client, user, request }) {
				return primaryResult(
					client,
					user,
					request,
					true,
					"/email-otp/verify-email",
				);
			},
			onVerificationFailure({ client, request, email }) {
				return security.failed(client, request, "/email-otp/verify-email", {
					email,
				});
			},
		});

	async function lockExistingSession(
		client: PoolClient,
		token: string,
		userId: string,
	) {
		if (!(await store.lockSession(client, token, userId, false))) return null;
		return eligibleSession(token, client);
	}

	async function reissueExistingSession(
		client: PoolClient,
		request: Request,
		current: NonNullable<Awaited<ReturnType<typeof eligibleSession>>>,
		path: "/verify-email" | "/get-session",
		callback?: string,
	) {
		const { token, user } = current;
		const remember = !tokenFrom(request.headers, rememberCookie);
		const device = user.twoFactorEnabled
			? await mfa.rotateTrustedDevice(client, user.id, request.headers)
			: null;
		const headers = new Headers();
		if (device?.setCookie) headers.append("Set-Cookie", device.setCookie);
		if (!remember) rememberPreference(headers, false);
		if (user.twoFactorEnabled && !device?.trusted) {
			const challenge = await mfa.issue(client, user.id);
			if (!challenge) return unsupported();
			const removed = await store.revoke(
				{ tokens: [token] },
				path,
				Boolean(backchannel),
				client,
				user.id,
			);
			if (!removed || removed.ids.length !== 1) throw unavailableLogout;
			deliverLogoutAfterCommit(client, request, removed.targets);
			// Reissuing an existing cookie creates no new session before MFA.
			headers.append("Set-Cookie", challenge.setCookie);
			writeCookie(headers, sessionCookie, "", 0);
			writeCookie(headers, `${prefix}session_data`, "", 0);
			return callback
				? redirect(headers, mfaContinuation(callback))
				: json(
						{
							twoFactorRedirect: true,
							twoFactorMethods: challenge.twoFactorMethods,
						},
						200,
						headers,
					);
		}
		let session = current.session;
		if (current.refreshDue && remember) {
			const renewed = await store.refresh(
				token,
				policy.sessionExpiresInSeconds,
				updateAge,
				client,
			);
			if (renewed) session = { ...session, ...renewed };
		}
		writeCookie(
			headers,
			sessionCookie,
			token,
			remember ? policy.sessionExpiresInSeconds : undefined,
		);
		return { headers, session };
	}

	async function continueEmailVerificationSession(
		client: PoolClient,
		request: Request,
		user: ProjectUser,
		token: string,
		callback?: string,
	): Promise<Headers | Response> {
		const current = await lockExistingSession(client, token, user.id);
		if (!current) return forbidden();
		const result = await reissueExistingSession(
			client,
			request,
			current,
			"/verify-email",
			callback,
		);
		return result instanceof Response ? result : result.headers;
	}

	const recoveryOptions = options.recovery;
	const recoveryHttp =
		recoveryOptions &&
		createOwnedRecoveryHttp({
			...recoveryOptions,
			emailAliases,
			database: options.database,
			project: options.project,
			policy,
			signingSecret: options.signingSecret,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			auditContext: browserEventContext,
			prepareEmailOtpReset: policy.mfaMode === "required"
				? async (request) => {
						const token = tokenFrom(request.headers);
						if (!token) return;
						const current = await store.transaction(async (client) => {
							const observed = await store.session(token, refreshWindow, client, {
								includeExpired: true,
							});
							return observed?.expired
								? cleanupExpiredSession(client, request, token, "/email-otp/reset-password")
								: observed;
						});
						if (!current) return;
						const { user, session } = current;
						if (!session.impersonatedBy && (!user.emailVerified || !user.twoFactorEnabled))
							return failure(
								403,
								"FORBIDDEN",
								"This application requires an already verified account enrolled in MFA.",
							);
						return user.id;
					}
				: undefined,
			verifyHostedVerificationContinuation: issuer
				? (target) =>
						verifiedHostedOAuthContinuation(
							{ readOAuthContext: issuer.readContext },
							target.hostname,
							target.search.slice(1),
						)
				: undefined,
			async admit(request, operation, email) {
				if (
					operation === "request-password-reset" ||
					operation === "email-otp/request-password-reset" ||
					operation === "email-otp/send-verification-otp" ||
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
				if (active?.user.id === user.id) {
					const result = await continueEmailVerificationSession(
						client,
						request,
						active.user,
						active.token,
						callback,
					);
					if (result instanceof Response) return result;
					return callback
						? redirect(result, callback)
						: json({ status: true, user: null }, 200, result);
				}
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

	const accountLinks = options.accountLinks && {
		...options.accountLinks,
		database: options.database,
		project: options.project,
		baseURL: origin,
		basePath: options.basePath,
		trustedOrigins: options.trustedOrigins,
		async authority(client: PoolClient, request: Request) {
			const token = tokenFrom(request.headers);
			if (!token) return null;
			const found = await store.session(token, refreshWindow, client);
			return (
				found && {
					userId: found.user.id,
					sessionId: found.session.id,
					token,
					impersonatedBy: found.session.impersonatedBy,
					eligible:
						policy.mfaMode !== "required" ||
						(found.user.emailVerified && found.user.twoFactorEnabled === true),
				}
			);
		},
	};
	const emailChange =
		accountLinks?.emailChange &&
		createOwnedProjectEmailChange({
			...accountLinks,
			signingSecret: options.signingSecret,
			auditContext: browserEventContext,
			admitVerification: (request) =>
				factorAdmission(request, "change-email-verification"),
			async complete(client, { request, user, current, callbackURL }) {
				if (current)
					return continueEmailVerificationSession(
						client,
						request,
						user,
						current.token,
						callbackURL,
					);
				const response = await primaryResult(
					client,
					user,
					request,
					true,
					"/verify-email",
					callbackURL,
				);
				if (
					!callbackURL &&
					response.status === 200 &&
					response.headers
						.getSetCookie()
						.some(
							(cookie) =>
								cookie.startsWith(`${sessionCookie}=`) &&
								!cookie.includes("Max-Age=0"),
						)
				)
					return new Headers(response.headers);
				return response;
			},
		});
	const accountDeletion =
		accountLinks?.beforeDelete &&
		createOwnedProjectAccountDeletion({
			...accountLinks,
			auditContext: browserEventContext,
			beforeDelete: accountLinks.beforeDelete,
			async revokeSessions(client, request, userId, path) {
				const { rows } = await client.query<{ token: string }>(
					'SELECT token FROM "session" WHERE "userId"=$1 ORDER BY id',
					[userId],
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
				const headers = new Headers();
				clearSessionCookies(headers);
				for (const cookie of multiSessionTokens(request.headers))
					if (tokens.includes(cookie.token))
						writeCookie(headers, cookie.name, "", 0);
				return headers;
			},
		});
	async function clearUserAuthentication(client: PoolClient, userId: string) {
		await client.query('DELETE FROM "oauthAccessToken" WHERE "userId"=$1', [
			userId,
		]);
		await client.query('DELETE FROM "oauthRefreshToken" WHERE "userId"=$1', [
			userId,
		]);
		await client.query(
			`DELETE FROM "verification" WHERE value=$1
			 AND (starts_with(identifier,'trust-device-') OR starts_with(identifier,'2fa-'))`,
			[userId],
		);
	}
	async function revokeAdminSessions(
		client: PoolClient,
		request: Request,
		selector: { tokens: string[] } | { userId: string },
		path: string,
		actorId: string,
		authentication: "all" | "linked" = "all",
	) {
		const removed = await store.revoke(
			selector,
			path,
			Boolean(backchannel),
			client,
			actorId,
		);
		if (!removed) throw unavailableLogout;
		if (authentication === "all" && "userId" in selector)
			await clearUserAuthentication(client, selector.userId);
		deliverLogoutAfterCommit(client, request, removed.targets);
	}
	const adminProject = options.adminDeletion && {
		id: options.adminDeletion.id,
		workspaceId: options.adminDeletion.workspaceId,
		schemaName: options.project.schemaName,
		slug: options.project.slug,
	};
	const adminDeletion =
		options.adminDeletion &&
		adminProject &&
		accountLinks?.beforeDelete &&
		createOwnedProjectAdminDeletion({
			...options.adminDeletion,
			project: adminProject,
			database: options.database,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			requireMfa: policy.mfaMode === "required",
			auditContext: browserEventContext,
			async readRealmSession(request, client) {
				const token = tokenFrom(request.headers);
				const current = token ? await store.session(token, 0, client) : null;
				return token && current ? { token, ...current } : null;
			},
			beforeDelete: accountLinks.beforeDelete,
			async revokeSessions(client, request, userId, path, actorId) {
				const removed = await store.revoke(
					{ userId },
					path,
					Boolean(backchannel),
					client,
					actorId,
				);
				if (!removed) throw unavailableLogout;
				deliverLogoutAfterCommit(client, request, removed.targets);
			},
		});
	const adminUsers =
		options.adminDeletion &&
		adminProject &&
		createOwnedProjectAdminUsers({
			...options.adminDeletion,
			reservedEmail: emailAliases.reserved,
			project: adminProject,
			store,
			origin,
			basePath: options.basePath,
			policy,
			readBody: requestBody,
			checkPasswordSafety: options.passwordChange?.checkPasswordSafety,
			blockCreation: (client, request, email) =>
				security.admit(client, request, { email }),
			revoke: (client, request, userId, path, actorId) =>
				revokeAdminSessions(client, request, { userId }, path, actorId),
		});
	const clerkImport =
		options.adminDeletion &&
		adminProject &&
		createOwnedProjectClerkImport({
			...options.adminDeletion,
			project: adminProject,
			store,
			origin,
			basePath: options.basePath,
			readBody: (request) => requestBody(request, 1024 * 1024),
		});
	const invitationImport =
		options.adminDeletion &&
		adminProject &&
		createOwnedProjectInvitationImport({
			...options.adminDeletion,
			project: adminProject,
			store,
			origin,
			basePath: options.basePath,
			readBody: (request) => requestBody(request, 1024 * 1024),
		});
	const projectControl = options.adminDeletion && adminProject &&
		createOwnedProjectControl({
			...options.adminDeletion,
			database: options.database,
			project: adminProject,
			origin,
			basePath: options.basePath,
			trustedIP: options.trustedIP,
			readBody: requestBody,
			backchannelLogout: backchannel,
			async readProjectSession(headers) {
				if (!trustedRequest(headers, false)) return null;
				const current = await currentSession(headers);
				return current ? { id: current.session.id, userId: current.user.id } : null;
			},
		});
	const webhookManagement =
		options.webhookManagement &&
		options.adminDeletion &&
		adminProject &&
		createOwnedProjectWebhookManagement({
			...options.webhookManagement,
			...options.adminDeletion,
			project: adminProject,
			store,
			origin,
			basePath: options.basePath,
			trustedIP: options.trustedIP,
			readBody: requestBody,
		});
	const securityManagement =
		options.security?.management &&
		options.adminDeletion &&
		adminProject &&
		createOwnedProjectSecurityManagement({
			...options.adminDeletion,
			project: adminProject,
			store,
			origin,
			basePath: options.basePath,
			trustedIP: options.trustedIP,
			readBody: requestBody,
			newDeviceNotifications: Boolean(options.security.newDevice),
		});
	const analytics =
		options.analytics &&
		createOwnedProjectAnalytics({
			database: options.database,
			project: options.project,
			workspace:
				options.adminDeletion && adminProject
					? { ...options.adminDeletion, project: adminProject }
					: undefined,
			origin,
			basePath: options.basePath,
			trustedIP: options.trustedIP,
		});

	const beforeGuestDelete = accountLinks?.beforeDelete;
	const guest =
		beforeGuestDelete &&
		createOwnedProjectGuest({
			store,
			emailAliases,
			denyProvisioning: security.denyStandaloneSignup,
			beforeDelete: beforeGuestDelete,
			auditContext: browserEventContext,
			async revoke(client, request, userId, path) {
				const removed = await store.revoke(
					{ userId },
					path,
					Boolean(backchannel),
					client,
				);
				if (!removed) throw unavailableLogout;
				deliverLogoutAfterCommit(client, request, removed.targets);
			},
		});

	async function currentGuestProof(
		headers: Headers,
		client?: PoolClient,
		capturedUser?: string,
		signedInUser?: string,
	): Promise<ProjectGuestProof | null> {
		const current = await currentSession(headers, client);
		if (current?.user.isAnonymous && current.user.id !== signedInUser)
			return { token: current.token };
		return capturedUser && capturedUser !== signedInUser
			? { userId: capturedUser }
			: null;
	}

	async function guestSession(request: Request, path: string) {
		if (!guest) return unsupported();
		if (path === "/delete-anonymous-user") {
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: 100,
					windowMs: 60_000,
				}),
			);
			if (limited) return limited;
			if (!trustedRequest(request.headers, true)) return forbidden();
			const reject = async (
				status: number,
				code: string,
				message: string,
				userId?: string,
			) => {
				await guest.recordDeletionFailure(request, code, userId);
				return failure(status, code, message);
			};
			const unauthorizedGuest = () =>
				reject(401, "UNAUTHORIZED", "Unauthorized");
			const current = await currentSession(request.headers);
			if (!current) return unauthorizedGuest();
			if (!current.user.isAnonymous)
				return reject(
					403,
					"USER_IS_NOT_ANONYMOUS",
					"User is not anonymous",
					current.user.id,
				);
			const result = await guest.erase(request, { token: current.token }, path);
			if (result.status === "missing") return unauthorizedGuest();
			if (result.status === "ineligible") return forbidden();
			if (result.status === "pending")
				return failure(
					409,
					"DELETION_PENDING",
					"Account deletion is already being processed.",
				);
			if (result.status !== "deleted")
				return failure(
					503,
					"FAILED_TO_DELETE_ANONYMOUS_USER",
					"Failed to delete anonymous user",
				);
			const headers = new Headers();
			clearSessionCookies(headers);
			writeCookie(
				headers,
				`${multiCookiePrefix}${current.token.toLowerCase()}`,
				"",
				0,
			);
			return json({ success: true }, 200, headers);
		}
		if (!trustedRequest(request.headers, true)) return forbidden();
		if (!policy.signUpEnabled)
			return failure(
				403,
				"FORBIDDEN",
				"New guest sessions are disabled for this application.",
			);
		return store.transaction(async (client) => {
			if (await currentGuestProof(request.headers, client))
				return failure(
					400,
					"ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
					"Anonymous users cannot sign in again anonymously",
				);
			const guestAccount = await guest.create(client, request);
			if (guestAccount.status === "blocked")
				return failure(403, "validation_failed", "User validation failed");
			if (guestAccount.status === "reserved")
				return failure(
					reservedProjectEmailError.status,
					reservedProjectEmailError.code,
					reservedProjectEmailError.message,
				);
			const signedIn = await createSession(client, guestAccount.user, request, true, path);
			return json(
				{ token: signedIn.token, user: signedIn.user },
				200,
				signedIn.headers,
			);
		});
	}

	const wallet =
		options.walletOrigin &&
		createOwnedProjectWallet({
			store,
			emailAliases,
			schemaName: options.project.schemaName,
			signingOrigin: options.walletOrigin,
			signUpEnabled: policy.signUpEnabled,
			readBody: requestBody,
			cleanupExpiredPrimary:
				policy.mfaMode === "required"
					? (request) => cleanupExpiredBrowserSession(request, "/siwe/verify")
					: undefined,
			denyProvisioning: security.denyStandaloneSignup,
			async admit(client, request, operation) {
				const identity =
					operation.kind === "nonce"
						? { message: true }
						: { email: operation.email };
				return (await security.admit(client, request, identity))
					? securityBlocked()
					: null;
			},
			async recordFailure(client, request, email, response) {
				const body: unknown = await response.clone().json().catch(() => null);
				const code =
					body &&
					typeof body === "object" &&
					"code" in body &&
					typeof body.code === "string" &&
					/^[a-zA-Z0-9_-]{1,100}$/.test(body.code)
						? body.code
						: "AUTHENTICATION_FAILED";
				if (code !== projectSecurityBlockedCode)
					await security.failed(client, request, "/siwe/verify", { email });
				await recordPrimaryFailure(client, request, "/siwe/verify", code);
			},
			complete(client, request, user, wallet) {
				return primaryResult(
					client,
					user,
					request,
					true,
					"/siwe/verify",
					undefined,
					{
						allowUnverifiedEmail: true,
						wallet,
					},
				);
			},
		});

	const oauth =
		options.oauth &&
		createOwnedProjectOAuth({
			...options.oauth,
			reservedEmail: emailAliases.reserved,
			database: options.database,
			project: options.project,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			auditContext: browserEventContext,
			denyProviderProfile: security.denyProvisioning,
			prepareProviderSignup: security.prepareProviderSignup,
			async readGuestUserId(request) {
				if (!guest) return undefined;
				const current = await currentSession(request.headers);
				return current?.user.isAnonymous ? current.user.id : undefined;
			},
			signingSecret: options.signingSecret,
			signUpEnabled: policy.signUpEnabled,
			requireEmailVerification: policy.requireEmailVerification,
			passwordSignIn: policy.emailAndPasswordEnabled,
			passkeySignIn: Boolean(options.passkeys),
			missingBrowserSessionHeaders,
			async otherLinkedSignIn(_client, user) {
				return Boolean(
					user.emailVerified &&
						options.emailSignIn &&
						emailConfigured(options.emailSignIn.email.environment),
				);
			},
			async authorizeLinkedAccounts(client, { request, user, operation }) {
				const bearer =
					operation === "provider-token"
						? providerSessionBearer(request)
						: null;
				const active = bearer
					? await eligibleSession(bearer, client)
					: await currentSession(request.headers, client);
				if (active?.user.id !== user.id) return false;
				if (operation !== "provider-token") return true;
				const headers = new Headers();
				await renewAuthorizedSession(
					request,
					active,
					client,
					headers,
					Boolean(bearer),
				);
				if (headers.has("set-cookie"))
					afterOwnedProjectCommit(client, () =>
						providerSessionRenewals.set(request, headers),
					);
				return true;
			},
			async complete(
				client,
				{
					user,
					request,
					provider,
					destination,
					verificationDestination,
					anonymousUserId,
					registered,
					transport,
				},
			) {
				const browser = transport === "browser";
				const result = await primaryResult(
					client,
					await store.lockUser(client, user.id),
					request,
					true,
					browser ? `/callback/${provider}` : "/sign-in/social",
					browser ? destination : undefined,
					{
						allowUnverifiedEmail:
							provider === "microsoft" || provider === "apple",
						anonymousUserId,
					},
				);
				if (
					result.status < 400 &&
					provider === "apple" &&
					registered &&
					!user.emailVerified &&
					policy.requireEmailVerification
				) {
					const verification = signUp?.verification;
					const target = verificationDestination ?? destination;
					const callback = verification?.callbackURLs.includes(target)
						? target
						: (verification?.callbackPolicy?.(
								new URL(target),
								"verification",
								"issue",
							)?.url.href ?? verification?.callbackURLs[0]);
					if (!verification || !callback) return unsupported();
					afterOwnedProjectCommit(client, () =>
						scheduleOwnedSignUpVerification(verification, user, callback),
					);
				}
				return browser && result.status === 200
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
			auditContext: browserEventContext,
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
					{ ...session, activeOrganizationId: null, activeTeamId: null },
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
			emailAliases,
			database: options.database,
			project: options.project,
			baseURL: origin,
			basePath: options.basePath,
			trustedOrigins: options.trustedOrigins,
			signingSecret: options.signingSecret,
			signUpEnabled: policy.signUpEnabled,
			denyProviderProfile: security.denyProvisioning,
			prepareProviderSignup: security.prepareProviderSignup,
			encryptedSamlApproval: options.sso?.encryptedSamlApproval,
			cleanupExpiredPrimary:
				policy.mfaMode === "required" ? cleanupExpiredBrowserSession : undefined,
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
	const ssoManagement =
		sso &&
		createOwnedProjectSsoManagement({
			database: options.database,
			schemaName: options.project.schemaName,
			baseURL: `${origin}${options.basePath}`,
			trustedOrigins: acceptedOrigins,
			fetch: options.sso?.fetch,
			saml: options.sso?.saml,
			customSamlTransport: options.sso?.customSamlTransport,
			encryptedSamlFixture: options.sso?.encryptedSamlFixture,
			trustedRequest,
			readBody: requestBody,
			readSession: (request, client) => currentSession(request.headers, client),
		});
	const scimDiscovery =
		options.scim &&
		createOwnedProjectSCIMDiscovery(`${origin}${options.basePath}`);
	const scimAuthority = options.scim && {
		database: options.database,
		schemaName: options.project.schemaName,
		baseURL: `${origin}${options.basePath}`,
		credentialHashSecret: options.scim.credentialHashSecret,
		manageCredentialUsage: true,
	};
	const scimResources =
		scimAuthority && createOwnedProjectSCIMResources(scimAuthority);
	const scimGroupWrites =
		scimAuthority && createOwnedProjectSCIMGroupWrites(scimAuthority);
	const scimUserWrites =
		scimAuthority &&
		createOwnedProjectSCIMUserWrites({
			...scimAuthority,
			emailAliases,
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
					path === "/project-admin/stop-impersonating" ? current.userId : null,
				);
				if (!removed) throw unavailableLogout;
				deliverLogoutAfterCommit(client, request, removed.targets);
				return removed.ids.length > 0;
			},
		});
	const impersonationCookies = {
		admin: `${prefix}admin_session`,
		session: sessionCookie,
		remember: rememberCookie,
	};
	const realmAdminMutations = createOwnedProjectRealmAdminMutations({
		store,
		reservedEmail: emailAliases.reserved,
		readBody: requestBody,
		checkOrigin: sessionMutationOrigin,
		readCookie: tokenFrom,
		clearCookies: clearSessionCookies,
		readSession: (token, client) => store.session(token, refreshWindow, client),
		renew: (request, current, client, headers) =>
			renewAuthorizedSession(request, current, client, headers, false),
		trustedIP: security.trustedIP,
		requireMfa: policy.mfaMode === "required",
		passwordPolicy: policy.passwordPolicy,
		checkPasswordSafety: passwordSafety,
		primaryOrigin: origin,
		blockAdminCreation: security.denyProvisioning,
		clearUserAuthentication,
		revoke: revokeAdminSessions,
	});
	const realmImpersonation = createOwnedProjectRealmImpersonation({
		store,
		trustedRequest,
		readBody: requestBody,
		trustedIP: security.trustedIP,
		readCookie: (headers, kind) =>
			tokenFrom(headers, impersonationCookies[kind]),
		writeCookie: (headers, kind, value, maxAge) =>
			writeCookie(headers, impersonationCookies[kind], value, maxAge),
		clearCookies: clearSessionCookies,
		async revoke(client, request, token) {
			const removed = await store.revoke(
				{ tokens: [token] },
				"/admin/stop-impersonating",
				Boolean(backchannel),
				client,
			);
			if (!removed) throw unavailableLogout;
			deliverLogoutAfterCommit(client, request, removed.targets);
			return removed.ids.length === 1;
		},
	});
	const personalKeys = createOwnedProjectPersonalKeys({
		database: options.database,
		schemaName: options.project.schemaName,
		readBody: requestBody,
		trustedIP: options.trustedIP,
		async authorize(request, client) {
			if (request.method === "POST") {
				const originFailure = sessionMutationOrigin(request);
				if (originFailure) return originFailure;
			} else if (request.headers.get("sec-fetch-site") === "cross-site") {
				return forbidden();
			}
			const token =
				serverSessionBearer(request.headers) ?? tokenFrom(request.headers);
			const raw = token ? await store.session(token, refreshWindow, client) : null;
			if (request.method === "POST" && raw?.session.impersonatedBy)
				return failure(
					403,
					"FORBIDDEN",
					"Authentication changes and account deletion are unavailable during impersonation.",
				);
			if (
				raw &&
				!raw.session.impersonatedBy &&
				policy.mfaMode === "required" &&
				(!raw.user.emailVerified || !raw.user.twoFactorEnabled)
			)
				return failure(
					403,
					"FORBIDDEN",
					"This application requires an already verified account enrolled in MFA.",
				);
			const observed = ordinarySession(token, raw);
			if (!observed) return null;
			const userId = observed.user.id;
			if (
				request.method === "POST" &&
				(!(await store.lockUser(client, userId)) ||
					!(await store.lockSession(client, observed.token, userId, false)))
			)
				return null;
			const current = await eligibleSession(observed.token, client);
			if (!current || current.user.id !== userId) return null;
			const headers = new Headers();
			await renewAuthorizedSession(request, current, client, headers);
			return {
				userId,
				headers,
				platformAdmin: isPlatformAdmin(current.user, current.session),
			};
		},
	});

	const realmAdminRead = createOwnedProjectRealmAdminRead({
		store,
		trustedRequest,
		readBody: requestBody,
		readSessionToken: tokenFrom,
		trustedIP: security.trustedIP,
		requireMfa: policy.mfaMode === "required",
	});

	const organization = createOwnedProjectOrganizationHttp({
		database: options.database,
		project: options.project,
		policy,
		currentSession,
		trustedRequest,
		readBody: requestBody,
		auditContext: browserEventContext,
		collectActivity: analytics !== false && analytics !== undefined
			? (session, organizationId) =>
					analytics.session(session, 4, organizationId, true)
			: undefined,
		membershipLimit: options.organization?.membershipLimit,
		invitationEmail: options.organization?.invitationEmail,
		async renewInvitationSession(request, client, principal) {
			const headers = new Headers();
			await renewAuthorizedSession(request, principal, client, headers, false);
			return headers.has("set-cookie") ? headers : undefined;
		},
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

	const oneTimeToken = createOwnedProjectOneTimeToken({
		store,
		readBody: requestBody,
		trustedIP: options.trustedIP,
		sessionToken: (headers) =>
			serverSessionBearer(headers) ?? tokenFrom(headers),
		eligible: (token, client) => eligibleSession(token, client),
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
			apiKeys: options.sdk?.personalApiKeys === true,
			enterpriseSSO: Boolean(sso),
			scim: Boolean(scimAuthority && options.manageSCIMConsole),
			organizations: true,
			twoFactor: true,
			profileImageUpload: Boolean(options.sdk?.avatar),
			profileImageOwnershipAndDeletion:
				(await options.sdk?.avatar?.ownershipAndDeletion?.()) === true,
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
		// These management methods are internal calls on the shared platform broker.
		if (path === "/admin/oauth2/create-client" || path === "/admin/oauth2/update-client")
			return new Response(null, { status: 404 });
		if (
			options.openApi &&
			(path === projectOpenApiPath || path === "/reference")
		) {
			if (path !== projectOpenApiPath || request.method !== "GET")
				return failure(404, "NOT_FOUND", "Not found.");
			if (request.headers.has("authorization"))
				return failure(
					403,
					"FORBIDDEN",
					"Use your signed-in browser session for this action.",
				);
			if (!trustedRequest(request.headers, false)) return forbidden();
			const current = await currentSession(request.headers);
			if (!isPlatformAdmin(current?.user, current?.session))
				return failure(
					403,
					"FORBIDDEN",
					"An administrator is required to view the API schema.",
				);
			return json(
				ownedProjectOpenApi({
					serverURL: `${origin}${options.basePath}`,
					cookieName: sessionCookie,
					passwordMaxLength:
						policy.emailAndPasswordEnabled && !missingSupportAdapter
							? defaultPasswordPolicy.maxLength
							: undefined,
				}),
			);
		}
		const impersonation = await realmImpersonation.dispatch(path, request);
		if (impersonation) return impersonation;
		const realmMutation = await realmAdminMutations(path, request);
		if (realmMutation) return realmMutation;
		if (
			wallet &&
			request.method === "POST" &&
			["/siwe/nonce", "/siwe/get-nonce", "/siwe/verify"].includes(path)
		)
			return trustedRequest(request.headers, true)
				? wallet(path, request)
				: forbidden();
		if (
			request.method === "POST" &&
			(path === "/sign-in/anonymous" || path === "/delete-anonymous-user")
		)
			return guestSession(request, path);
		const administrative = await adminUsers?.(request, path);
		if (administrative) return administrative;
		const imported = await clerkImport?.(request, path);
		if (imported) return imported;
		const importedInvitations = await invitationImport?.(request, path);
		if (importedInvitations) return importedInvitations;
		const control = await projectControl?.(request, path);
		if (control) return control;
		const webhook = await webhookManagement?.(request, path);
		if (webhook) return webhook;
		const securityResult =
			securityManagement && (await securityManagement(request, path));
		if (securityResult) return securityResult;
		const analyticsRead = analytics && (await analytics.read(request, path));
		if (analyticsRead) return analyticsRead;
		const agentHost = agentHosts && (await agentHosts(path, request));
		if (agentHost) return agentHost;
		const issuerResponse = issuer && (await issuer.dispatch(path, request));
		if (issuerResponse) return issuerResponse;
		if (
			path === projectBrokerMfaPath &&
			request.method === "POST" &&
			options.brokerTwoFactor
		)
			return verifyOwnedProjectBrokerMfa(request, {
				authorize: options.brokerTwoFactor,
				admit: (verified) =>
					store.transaction((client) =>
						admitOwnedProjectBrokerMfa(client, options.trustedIP(verified)),
					),
				readBody: (verified) => requestBody(verified, 2048),
			});
		if (path.startsWith("/one-time-token/"))
			return (await oneTimeToken.dispatch(path, request)) ?? unsupported();
		if (path.startsWith("/api-key/"))
			return (
				(await personalKeys.dispatch(path, request)) ??
				new Response(null, { status: 404 })
			);
		const realmAdmin = await realmAdminRead(path, request);
		if (realmAdmin) return realmAdmin;
		const directoryResponse = await directory?.dispatch(path, request);
		if (directoryResponse) return directoryResponse;
		if (path === "/sdk/config" && request.method === "GET") {
			if (!trustedRequest(request.headers, false)) return forbidden();
			return publicSDKConfiguration();
		}
		if (path === "/sdk/sessions" && request.method === "GET")
			return listSdkSessions(request);
		if (path === "/sdk/avatar" && request.method === "POST") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const current = await currentSession(request.headers);
			if (!current) return failure(401, "UNAUTHORIZED", "Unauthorized");
			if (!current.user.emailVerified)
				return failure(
					403,
					"FORBIDDEN",
					"A verified, active project account is required.",
				);
			return uploadProjectAvatar(
				options.sdk?.avatar,
				current.user.id,
				await requestBody(request, 262_144),
			);
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
		if (ssoManagement && path.startsWith("/sso/")) {
			const response = await ssoManagement(path, request);
			if (response) return response;
		}
		if (sso && request.method === "POST" && path === "/sign-in/sso") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const body = ownedProjectSsoInput.safeParse(await requestBody(request));
			if (!body.success)
				return failure(
					400,
					"INVALID_BODY",
					"Invalid enterprise sign-in request.",
				);
			if (!(await sso.verifyEncryptedSamlStart(body.data)))
				return failure(
					503,
					"AUTHENTICATION_UNAVAILABLE",
					"Enterprise sign-in is unavailable.",
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
			return providerCallback(request, "/sso/callback/:providerId", () =>
				sso.callback(request, provider),
			);
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
			if (!(await sso.verifyEncryptedSamlCallback(request, provider)))
				return failure(
					503,
					"AUTHENTICATION_UNAVAILABLE",
					"Enterprise sign-in is unavailable.",
				);
			const denied = await store.transaction((client) =>
				security.admit(client, request),
			);
			if (denied) return securityBlocked();
			// The IdP posts cross-site. The SAML service validates the signed response
			// against the stored, single-use request for this realm and provider.
			return providerCallback(request, "/sso/saml2/sp/acs/:providerId", () =>
				sso.samlCallback(request, provider),
			);
		}
		if (emailChange && path === "/change-email" && request.method === "POST") {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: 3,
					windowMs: 10_000,
				}),
			);
			if (limited) return limited;
			const denied = await factorAdmission(request, "change-email");
			if (denied) return denied;
			const input = request.body ? await requestBody(request) : undefined;
			const missing =
				input === undefined
					? null
					: await missingBrowserSessionHeaders(request, path);
			const response = await emailChange.start(request, input);
			if (missing && response.status === 401)
				for (const cookie of missing.getSetCookie())
					response.headers.append("set-cookie", cookie);
			return response;
		}
		if (emailChange && path === "/verify-email" && request.method === "GET") {
			const response = await emailChange.verify(request);
			if (response) return response;
		}
		if (
			adminDeletion &&
			request.method === "POST" &&
			(path === "/project-admin/remove-user" || path === "/admin/remove-user")
		)
			return adminDeletion(request, path, await requestBody(request));
		if (
			accountDeletion &&
			path === "/delete-user" &&
			request.method === "POST"
		) {
			if (!trustedRequest(request.headers, true)) return forbidden();
			const denied = await factorAdmission(request, "delete-user");
			if (denied) return denied;
			return accountDeletion.start(request, await requestBody(request));
		}
		if (
			accountDeletion &&
			path === "/delete-user/callback" &&
			request.method === "GET"
		) {
			const denied = await factorAdmission(request, "delete-user-callback");
			if (denied) return denied;
			return accountDeletion.confirm(request);
		}
		if (
			emailOtpVerification &&
			request.method === "POST" &&
			(path === "/email-otp/request-email-change" || path === "/email-otp/change-email")
		) {
			if (!trustedRequest(request.headers, true)) return forbidden();
			if (!(await currentSession(request.headers)))
				return failure(401, "UNAUTHORIZED", "Unauthorized");
			return json({ message: "Change email with OTP is disabled" }, 400);
		}
		const recovery = await recoveryHttp?.(request);
		if (recovery) return recovery;
		const emailVerification = await emailOtpVerification?.(request);
		if (emailVerification) return emailVerification;
		const registration = await signUpHttp?.(request);
		if (registration) return registration;
		const emailSignIn = await emailSignInHttp?.(request);
		if (emailSignIn) return emailSignIn;
		const organizationResponse = await organization(path, request);
		if (organizationResponse) return organizationResponse;
		if (oauth && path === "/list-accounts" && request.method === "GET")
			return oauth.listAccounts(request);
		if (oauth && path === "/account-info" && request.method === "GET")
			return oauth.accountInfo(request);
		if (
			oauth &&
			(path === "/get-access-token" || path === "/refresh-token") &&
			request.method === "POST"
		) {
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: 100,
					windowMs: 60_000,
				}),
			);
			if (limited) return limited;
			const bearer = providerSessionBearer(request);
			if (bearer) {
				const originFailure = sessionMutationOrigin(request);
				if (originFailure) return originFailure;
			}
			const response = await oauth.providerToken(
				request,
				() => requestBody(request, 8192),
				path,
				bearer,
			);
			const renewal = providerSessionRenewals.get(request);
			if (renewal) {
				providerSessionRenewals.delete(request);
				for (const [name, value] of renewal)
					response.headers.append(name, value);
			}
			return response;
		}
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
			const hosted =
				path === "/sign-in/social" && hostedSocialSignInRequests.has(request);
			const input = await requestBody(hosted ? request.clone() : request);
			const regular = ownedProjectOAuthStartInput.safeParse(input);
			const body =
				hosted && !regular.success
					? ownedProjectHostedSocialContinuationInput.safeParse(
							input === undefined
								? await requestBody(
										request,
										maximumHostedSocialContinuationBodyBytes,
									)
								: input,
						)
					: regular;
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
			await cleanupExpiredBrowserSession(request, path);
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
				return providerCallback(request, "/callback/:id", () =>
					oauth.callback(request, provider.data),
				);
			}
		}
		if (passkeyHttp && path.startsWith("/passkey/")) {
			if (!trustedRequest(request.headers, request.method !== "GET"))
				return forbidden();
			if (path === "/passkey/list-user-passkeys" && request.method === "GET") {
				const headers = await missingBrowserSessionHeaders(request, path);
				if (headers)
					return failure(401, "UNAUTHORIZED", "Unauthorized", headers);
			}
			const response = await passkeyHttp(path, request);
			if (response) return response;
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
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: 3,
					windowMs: 10_000,
				}),
			);
			if (limited) return limited;
			const denied = await factorAdmission(request, "change-password");
			if (denied) return denied;
			const input = request.body ? await requestBody(request) : undefined;
			// The installed identity hook checks the caller before password policy.
			const missing =
				input === undefined
					? null
					: await missingBrowserSessionHeaders(request, path);
			const response = await passwordChange.change(request, input);
			if (missing && response.status === 401)
				for (const cookie of missing.getSetCookie())
					response.headers.append("set-cookie", cookie);
			return response;
		}
		if (request.method === "POST" && path === "/update-user") {
			const direct = options.basePath === `/api/projects/${slug}/auth`;
			const authorization = request.headers.has("authorization");
			const cookie = request.headers.has("cookie");
			if (direct) {
				const deniedOrigin = sessionMutationOrigin(request);
				if (deniedOrigin) return deniedOrigin;
				if (authorization && cookie) return forbidden();
			} else if (!trustedRequest(request.headers, true)) return forbidden();
			const token = authorization
				? providerSessionBearer(request)
				: tokenFrom(request.headers);
			const serverTokenResponse = direct && isServerTokenRequest(request.headers);
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
					max: 100,
					windowMs: 60_000,
				}),
			);
			if (limited) return limited;
			const input = request.body ? await requestBody(request) : undefined;
			if (input === undefined)
				return failure(400, "INVALID_BODY", "Invalid profile.");
			const parsed = ownedProjectProfileBody.safeParse(input);
			const eventContext = browserEventContext(request);
			if (!parsed.success) {
				await store.transaction((client) =>
					store.recordEvent(client, {
						type: "user.updated",
						outcome: "failure",
						...eventContext,
						metadata: { path, errorCode: "VALIDATION_ERROR" },
					}),
				);
				return json(
					{
						code: "VALIDATION_ERROR",
						message: "Validation error",
						originalMessage: parsed.error.issues
							.map(({ message }) => `[body] ${message}`)
							.join("; "),
					},
					400,
				);
			}
			const headers = new Headers();
			const current = await store.transaction(async (client) => {
				const observed = await readBrowserRouteSession(
					client,
					request,
					path,
					headers,
					token,
				);
				const session = ordinarySession(observed?.token ?? null, observed);
				if (session)
					await renewAuthorizedSession(
						request,
						session,
						client,
						headers,
						serverTokenResponse,
					);
				return session;
			});
			const renewedBearer = headers.get("set-auth-token");
			if (renewedBearer)
				headers.set("set-auth-token", decodeURIComponent(renewedBearer));
			const result = await updateProfile(
				parsed.data,
				current && { userId: current.user.id, token: current.token },
				eventContext,
			);
			if (result.status !== 200)
				return failure(result.status, result.code, result.message, headers);
			writeCookie(
				headers,
				sessionCookie,
				result.token,
				tokenFrom(request.headers, rememberCookie)
					? undefined
					: policy.sessionExpiresInSeconds,
			);
			if (serverTokenResponse) {
				const signed = headers
					.getSetCookie()
					.at(-1)
					?.split(";", 1)[0]
					?.slice(sessionCookie.length + 1);
				if (signed) {
					headers.set("set-auth-token", decodeURIComponent(signed));
					headers.set("access-control-expose-headers", "set-auth-token");
				}
			}
			return json({ status: true }, 200, headers);
		}
		if (request.method === "POST" && path === "/sign-in/email")
			return signIn(request);
		if (request.method === "POST" && path === "/sign-in/username")
			return signIn(request, "username");
		if (request.method === "GET" && path === "/get-session")
			return readSession(request);
		if (request.method === "GET" && path === "/list-sessions")
			return listNativeSessions(request);
		if (request.method === "POST" && path === "/get-session")
			return failure(
				405,
				"METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
				"POST method requires deferSessionRefresh to be enabled in session config",
			);
		if (request.method === "POST" && path === "/sign-out")
			return signOut(request);
		if (request.method === "POST" && path === "/sdk/sessions/revoke")
			return revokeSdkSession(request);
		if (
			request.method === "POST" &&
			(path === "/revoke-sessions" ||
				path === "/revoke-other-sessions" ||
				path === "/revoke-session")
		)
			return revokeBrowserSessions(request, path);
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
			return listAccountSessions(request);
		if (request.method === "POST" && path === "/account/sessions/revoke") {
			const body = sessionIdInput.safeParse(await requestBody(request));
			return body.success
				? revokeAccountSession(request, body.data)
				: failure(400, "INVALID_BODY", "Supply a session ID.");
		}
		return unsupported();
	}

	async function deliverCommittedLogout(request: Request) {
		const targets = committedLogoutTargets.get(request);
		committedLogoutTargets.delete(request);
		if (targets) await backchannel?.(targets);
	}

	async function recordAnalytics(request: Request, response: Response) {
		if (
			!analytics ||
			response.status < 200 ||
			response.status >= 400 ||
			request.headers.has("authorization") ||
			controlResponseFailure(undefined, response.headers).failed
		)
			return;
		const session = analyticsSessions.get(request);
		if (session) {
			await analytics.session(session.session, session.source);
			return;
		}
		if (request.method === "GET") return;
		const path = new URL(request.url).pathname.slice(options.basePath.length);
		if (isOwnedProjectActivityMutation(path, request.method)) {
			const token = tokenFrom(request.headers);
			if (token) await analytics.mutation(token);
		}
	}

	return {
		async dispatch(request) {
			try {
				const response = await route(request);
				await recordAnalytics(request, response);
				const upgradedGuest = completedGuestUpgrades.get(request);
				if (response.status < 400 && guest && upgradedGuest)
					await guest
						.erase(request, upgradedGuest.proof, upgradedGuest.path)
						.catch(() => undefined);
				const notify = notifications.get(request);
				if (response.status < 400 && notify && newDevice)
					newDevice.defer(notify);
				return response;
			} catch (error) {
				if (error === unavailableLogout) return unsupported();
				throw error;
			} finally {
				notifications.delete(request);
				analyticsSessions.delete(request);
				completedGuestUpgrades.delete(request);
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
		readIssuerMetadata: async () =>
			issuer
				? Response.json(
						ownedProjectIssuerMetadata({
							origin,
							basePath: options.basePath,
							slug,
						}),
						{ headers: discoveryHeaders },
					)
				: unsupported(),
		readOAuthContext: async (request) =>
			issuer ? issuer.readContext(request) : unsupported(),
		issueOneTimeToken: oneTimeToken.issue,
		verifyApiKey: options.sdk?.personalApiKeys ? personalKeys.verifyApiKey : undefined,
		deleteAllExpiredApiKeys: options.sdk?.personalApiKeys ? personalKeys.deleteAllExpiredApiKeys : undefined,
		manageSCIMConsole: options.manageSCIMConsole,
		manageOrganizationConsole: options.manageOrganizationConsole,
		manageUserConsole: options.manageUserConsole,
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
