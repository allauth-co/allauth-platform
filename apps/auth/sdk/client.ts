import { createPasskeyActions } from "./client-passkeys";
import type { AllAuthPasskey } from "./client-passkeys";
import { createClientQuery } from "./client-query";
import type {
	ClientQuery,
	ClientQueryOptions,
	ClientResult,
} from "./client-query";
import { authError, proxyBasePath } from "./helpers";
import sdkPackage from "./package.json";

export type { AllAuthClientError } from "./client-query";
export type { AllAuthPasskey } from "./client-passkeys";

/** The user returned by the cookie-only AllAuth API. */
export type AllAuthUser = {
	id: string;
	name: string;
	email: string;
	emailVerified: boolean;
	image?: string | null;
	twoFactorEnabled?: boolean | null;
	createdAt?: string;
	updatedAt?: string;
};

/** Session details without a browser-readable session credential. */
export type AllAuthSession = {
	user: AllAuthUser;
	session: {
		id: string;
		userId: string;
		createdAt: string;
		updatedAt: string;
		expiresAt: string;
		activeOrganizationId?: string | null;
		activeTeamId?: string | null;
		ipAddress?: string | null;
		userAgent?: string | null;
	};
};

export type AllAuthOrganization = {
	id: string;
	name: string;
	slug: string;
	logo?: string | null;
	createdAt?: string;
	metadata?: unknown;
};

export type AllAuthOrganizationMember = {
	id: string;
	userId: string;
	organizationId: string;
	role: string;
	createdAt?: string;
};

export type AllAuthInvitation = {
	id: string;
	organizationId: string;
	email: string;
	role: string;
	status: string;
	expiresAt: string;
	inviterId?: string;
	teamId?: string | null;
};

export type AllAuthTeam = {
	id: string;
	organizationId: string;
	name: string;
	createdAt?: string;
	updatedAt?: string | null;
};
export type AllAuthTeamMember = {
	id: string;
	teamId: string;
	userId: string;
	createdAt?: string;
};
export type AllAuthOrganizationRole = {
	id: string;
	organizationId: string;
	role: string;
	permission: Record<string, string[]>;
	createdAt?: string;
	updatedAt?: string | null;
};
export type AllAuthPermissions = Record<string, readonly string[]>;

type FullOrganization = AllAuthOrganization & {
	members: AllAuthOrganizationMember[];
	invitations: AllAuthInvitation[];
	teams: AllAuthTeam[];
};
type MemberWithUser = AllAuthOrganizationMember & {
	user: Pick<AllAuthUser, "id" | "name" | "email" | "image">;
};
type ActiveMemberRole = { role: string };
type SessionQuery = { disableCookieCache?: boolean; disableRefresh?: boolean };
type Status = { status: boolean };
type Redirect = { url?: string; redirect?: boolean };
type Authentication = Redirect & {
	user?: AllAuthUser;
	twoFactorRedirect?: boolean;
	twoFactorMethods?: string[];
};
type SocialInput = {
	provider: string;
	callbackURL?: string;
	newUserCallbackURL?: string;
	errorCallbackURL?: string;
	disableRedirect?: boolean;
	scopes?: string[];
	loginHint?: string;
	requestSignUp?: boolean;
	additionalData?: Record<string, unknown>;
	additionalParams?: Record<string, string>;
	idToken?: {
		token: string;
		nonce?: string;
		accessToken?: string;
		refreshToken?: string;
		expiresAt?: number;
	};
};
type SignupInput = {
	name: string;
	email: string;
	password: string;
	image?: string;
	callbackURL?: string;
	rememberMe?: boolean;
	username?: string;
	displayUsername?: string;
};
type InvitationResult = {
	invitation: AllAuthInvitation;
	member: AllAuthOrganizationMember;
};
type UserInvitation = AllAuthInvitation & {
	organizationName: string;
	organizationSlug?: string;
	inviterEmail?: string;
};
type RoleSelector =
	| { roleId: string; roleName?: never }
	| { roleName: string; roleId?: never };
type OrgScope = { organizationId?: string };
type TeamScope = OrgScope & { teamId: string };
type TeamMemberInput = TeamScope & { userId: string };
type FactorInput = { code: string; trustDevice?: boolean };
type OtpPurpose =
	| "sign-in"
	| "email-verification"
	| "forget-password"
	| "change-email";
type ClientFetchOptions = Pick<ClientQueryOptions, "headers" | "signal">;
type WithFetchOptions = { fetchOptions?: ClientFetchOptions };
type RequestOptions = ClientQueryOptions & {
	body?: object;
	method?: "GET" | "POST";
};

const sessionActions = new Set([
	"sign-out",
	"update-user",
	"sign-up/email",
	"sign-in/email",
	"sign-in/username",
	"sign-in/anonymous",
	"sign-in/email-otp",
	"verify-email",
	"email-otp/verify-email",
	"delete-user",
	"delete-anonymous-user",
	"change-email",
	"change-password",
	"passkey/verify-authentication",
	"organization/set-active",
	"organization/set-active-team",
	"organization/create",
	"organization/delete",
	"organization/remove-member",
	"organization/leave",
	"organization/accept-invitation",
]);
const organizationListActions = new Set([
	"organization/create",
	"organization/update",
	"organization/delete",
	"organization/leave",
	"organization/remove-member",
	"organization/accept-invitation",
]);
const identityActions = new Set([
	"sign-in/email",
	"sign-in/username",
	"sign-in/anonymous",
	"sign-in/email-otp",
	"sign-up/email",
	"passkey/verify-authentication",
	"sign-out",
	"delete-user",
	"delete-anonymous-user",
]);
const passkeyListActions = new Set([
	"passkey/verify-registration",
	"passkey/delete-passkey",
	"passkey/update-passkey",
]);

function record(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function requestFailure(aborted: boolean): ClientResult<never> {
	return {
		data: null,
		error: {
			code: aborted ? "REQUEST_ABORTED" : "NETWORK_ERROR",
			status: 0,
			statusText: "",
			message: aborted
				? "The request was cancelled."
				: "Could not reach AllAuth. Please try again.",
		},
	};
}

function navigate(value: unknown, appOrigin: string) {
	if (typeof value !== "string" || typeof window === "undefined") return;
	try {
		const target = new URL(value, appOrigin);
		if (
			(target.protocol === "https:" || target.origin === appOrigin) &&
			!target.username &&
			!target.password
		) {
			window.location.assign(target.href);
		}
	} catch {
		// A malformed continuation should not navigate the embedding app.
	}
}

function listenForSessionUpdates(
	path: string,
	refresh: () => void,
	invalidate: () => void,
) {
	if (typeof window === "undefined") return () => {};
	const visible = () => {
		if (document.visibilityState === "visible" && navigator.onLine !== false)
			refresh();
	};
	const storage = (event: StorageEvent) => {
		if (
			event.key === `allauth:session:${path}` ||
			event.key === "better-auth.message"
		)
			invalidate();
	};
	document.addEventListener("visibilitychange", visible);
	window.addEventListener("online", visible);
	window.addEventListener("storage", storage);
	return () => {
		document.removeEventListener("visibilitychange", visible);
		window.removeEventListener("online", visible);
		window.removeEventListener("storage", storage);
	};
}

/** Create a cookie-only client whose requests stay within the app's signed proxy. */
export function createAllAuthClient(
	basePath: string,
	onTwoFactorRedirect: (methods?: string[]) => void,
) {
	const path = proxyBasePath(basePath);

	async function request<T>(
		endpoint: string,
		options: RequestOptions = {},
	): Promise<ClientResult<T>> {
		if (options.signal?.aborted) return requestFailure(true);
		const origin =
			typeof window === "undefined"
				? "http://localhost"
				: window.location.origin;
		const url = new URL(`${path}/${endpoint}`, origin);
		if (url.origin !== origin || !url.pathname.startsWith(`${path}/`)) {
			throw new Error("AllAuth requests must use the app's same-origin proxy.");
		}
		for (const [key, value] of Object.entries(options.query ?? {})) {
			if (value !== undefined) url.searchParams.set(key, String(value));
		}

		const headers = new Headers(options.headers);
		headers.set("accept", "application/json");
		headers.set("x-allauth-sdk-version", sdkPackage.version);
		if (options.body !== undefined)
			headers.set("content-type", "application/json");
		const method =
			options.method ?? (options.body === undefined ? "GET" : "POST");
		let response: Response;
		let value: unknown;
		try {
			response = await fetch(url.href, {
				method,
				headers,
				body:
					options.body === undefined ? undefined : JSON.stringify(options.body),
				credentials: "same-origin",
				cache: "no-store",
				redirect: "error",
				signal: options.signal,
			});
			const body = await response.text();
			if (body) {
				try {
					value = JSON.parse(body) as unknown;
				} catch {
					value = undefined;
				}
			}
		} catch {
			return requestFailure(options.signal?.aborted === true);
		}
		if (options.signal?.aborted) return requestFailure(true);
		const fields = record(value);
		if (!response.ok) {
			const details = record(fields?.error);
			const code = fields?.code ?? details?.code;
			return {
				data: null,
				error: {
					status: response.status,
					statusText: response.statusText,
					code: typeof code === "string" ? code : undefined,
					message: authError(value),
					retryAfter: response.headers.get("retry-after") ?? undefined,
				},
			};
		}
		if (value === undefined && response.status !== 204) {
			return {
				data: null,
				error: {
					code: "INVALID_RESPONSE",
					status: response.status,
					statusText: response.statusText,
					message: "AllAuth returned an unreadable response.",
				},
			};
		}
		if (fields?.twoFactorRedirect === true) {
			const methods = fields.twoFactorMethods;
			onTwoFactorRedirect(
				Array.isArray(methods)
					? methods.filter(
							(method): method is string => typeof method === "string",
						)
					: undefined,
			);
		} else if (fields?.redirect === true) {
			navigate(fields.url, origin);
		}
		invalidateAfterSuccess(endpoint, method, fields);
		return { data: (value ?? null) as T | null, error: null };
	}

	const get =
		<T, Q extends ClientQuery = ClientQuery>(endpoint: string) =>
		(
			options?: ClientQueryOptions<Q> & WithFetchOptions,
			fetchOptions?: ClientFetchOptions,
		) =>
			request<T>(endpoint, {
				...fetchOptions,
				...options,
				...options?.fetchOptions,
				method: "GET",
			});
	const postOptional =
		<T, B extends object>(endpoint: string) =>
		(input?: B & WithFetchOptions, options?: ClientFetchOptions) => {
			const { fetchOptions, ...body } = input ?? {};
			return request<T>(endpoint, {
				...options,
				...fetchOptions,
				method: "POST",
				body,
			});
		};
	const post = <T, B extends object>(endpoint: string) =>
		postOptional<T, B>(endpoint) as (
			input: B & WithFetchOptions,
			options?: ClientFetchOptions,
		) => Promise<ClientResult<T>>;

	const getSession = async (
		input?: ClientQueryOptions<SessionQuery> & WithFetchOptions,
		fetchOptions?: ClientFetchOptions,
	): Promise<ClientResult<AllAuthSession>> => {
		type SessionResponse = AllAuthSession & { needsRefresh?: boolean };
		const options = { ...fetchOptions, ...input, ...input?.fetchOptions };
		let result = await request<SessionResponse>("get-session", options);
		if (
			result.data?.needsRefresh &&
			!options?.query?.disableRefresh &&
			!options?.signal?.aborted
		) {
			const refreshed = await request<SessionResponse>("get-session", {
				...options,
				method: "POST",
			});
			if (refreshed.error?.code !== "NETWORK_ERROR") result = refreshed;
		}
		if (!result.data) return result;
		if (result.data.session === null && result.data.user === null)
			return { data: null, error: null };
		if (
			typeof result.data.session?.id !== "string" ||
			typeof result.data.user?.id !== "string"
		) {
			return {
				data: null,
				error: {
					code: "INVALID_RESPONSE",
					status: 200,
					statusText: "OK",
					message: "AllAuth returned an unreadable session.",
				},
			};
		}
		return result;
	};

	const organization = {
		list: get<AllAuthOrganization[]>("organization/list"),
		getFullOrganization: get<
			FullOrganization,
			OrgScope & { organizationSlug?: string; membersLimit?: number }
		>("organization/get-full-organization"),
		getActiveMember: get<AllAuthOrganizationMember>(
			"organization/get-active-member",
		),
		getActiveMemberRole: get<
			ActiveMemberRole,
			OrgScope & { organizationSlug?: string; userId?: string }
		>("organization/get-active-member-role"),
		getInvitation: get<
			AllAuthInvitation & {
				organizationName: string;
				organizationSlug: string;
				inviterEmail: string;
			},
			{ id: string }
		>("organization/get-invitation"),
		listInvitations: get<AllAuthInvitation[], OrgScope>(
			"organization/list-invitations",
		),
		listUserInvitations: get<UserInvitation[]>(
			"organization/list-user-invitations",
		),
		listMembers: get<
			{ members: MemberWithUser[]; total: number },
			OrgScope & {
				organizationSlug?: string;
				limit?: number | string;
				offset?: number | string;
				sortBy?: string;
				sortDirection?: "asc" | "desc";
				filterField?: string;
				filterOperator?: string;
				filterValue?: string | number | boolean;
			}
		>("organization/list-members"),
		listRoles: get<AllAuthOrganizationRole[], OrgScope>(
			"organization/list-roles",
		),
		getRole: get<AllAuthOrganizationRole, OrgScope & RoleSelector>(
			"organization/get-role",
		),
		listTeams: get<AllAuthTeam[], OrgScope>("organization/list-teams"),
		listUserTeams: get<AllAuthTeam[]>("organization/list-user-teams"),
		listTeamMembers: get<AllAuthTeamMember[], { teamId?: string }>(
			"organization/list-team-members",
		),
		checkSlug: post<{ status: boolean }, { slug: string }>(
			"organization/check-slug",
		),
		hasPermission: post<
			{ success: boolean; error?: string | null },
			OrgScope & { permissions: AllAuthPermissions }
		>("organization/has-permission"),
		create: post<
			AllAuthOrganization & { members: AllAuthOrganizationMember[] },
			{
				name: string;
				slug: string;
				logo?: string;
				metadata?: Record<string, unknown>;
				keepCurrentActiveOrganization?: boolean;
			}
		>("organization/create"),
		update: post<
			AllAuthOrganization,
			OrgScope & {
				data: Partial<
					Pick<AllAuthOrganization, "name" | "slug" | "logo" | "metadata">
				>;
			}
		>("organization/update"),
		delete: post<AllAuthOrganization, { organizationId: string }>(
			"organization/delete",
		),
		setActive: postOptional<
			AllAuthOrganization,
			{ organizationId?: string | null; organizationSlug?: string }
		>("organization/set-active"),
		inviteMember: post<
			AllAuthInvitation,
			OrgScope & {
				email: string;
				role: string | string[];
				resend?: boolean;
				teamId?: string | string[];
			}
		>("organization/invite-member"),
		acceptInvitation: post<InvitationResult, { invitationId: string }>(
			"organization/accept-invitation",
		),
		rejectInvitation: post<
			{ invitation: AllAuthInvitation; member: null },
			{ invitationId: string }
		>("organization/reject-invitation"),
		cancelInvitation: post<AllAuthInvitation, { invitationId: string }>(
			"organization/cancel-invitation",
		),
		updateMemberRole: post<
			AllAuthOrganizationMember,
			OrgScope & { memberId: string; role: string | string[] }
		>("organization/update-member-role"),
		removeMember: post<
			{ member: AllAuthOrganizationMember },
			OrgScope & { memberIdOrEmail: string }
		>("organization/remove-member"),
		leave: post<AllAuthOrganizationMember, { organizationId: string }>(
			"organization/leave",
		),
		createTeam: post<AllAuthTeam, OrgScope & { name: string }>(
			"organization/create-team",
		),
		updateTeam: post<
			AllAuthTeam,
			TeamScope & { data: { name?: string; organizationId?: string } }
		>("organization/update-team"),
		removeTeam: post<{ message: string }, TeamScope>(
			"organization/remove-team",
		),
		setActiveTeam: postOptional<AllAuthTeam, { teamId?: string | null }>(
			"organization/set-active-team",
		),
		addTeamMember: post<AllAuthTeamMember, TeamMemberInput>(
			"organization/add-team-member",
		),
		removeTeamMember: post<{ message: string }, TeamMemberInput>(
			"organization/remove-team-member",
		),
		createRole: post<
			{
				success: boolean;
				roleData: AllAuthOrganizationRole;
				statements: AllAuthPermissions;
			},
			OrgScope & { role: string; permission: AllAuthPermissions }
		>("organization/create-role"),
		updateRole: post<
			{ success: boolean; roleData: AllAuthOrganizationRole },
			OrgScope &
				RoleSelector & {
					data: { roleName?: string; permission?: AllAuthPermissions };
				}
		>("organization/update-role"),
		deleteRole: post<{ success: boolean }, OrgScope & RoleSelector>(
			"organization/delete-role",
		),
	};

	const organizations = createClientQuery(organization.list);
	const activeOrganization = createClientQuery(
		organization.getFullOrganization,
	);
	const activeMember = createClientQuery(organization.getActiveMember);
	const activeMemberRole = createClientQuery(organization.getActiveMemberRole);
	const listPasskeys = get<AllAuthPasskey[]>("passkey/list-user-passkeys");
	const passkeys = createClientQuery(listPasskeys);
	const session = createClientQuery(
		getSession,
		(previous, current) => {
			if (previous && previous.user.id !== current?.user.id) {
				invalidateIdentity(false);
			}
		},
		(refresh) =>
			listenForSessionUpdates(path, refresh, () => invalidateIdentity(true)),
	);

	function invalidateActiveOrganization(clear = false) {
		activeOrganization.invalidate(clear);
		activeMember.invalidate(clear);
		activeMemberRole.invalidate(clear);
	}

	function invalidateIdentity(includeSession: boolean) {
		if (includeSession) session.invalidate(true);
		organizations.invalidate(true);
		invalidateActiveOrganization(true);
		passkeys.invalidate(true);
	}

	function broadcastSessionChange() {
		if (typeof window === "undefined") return;
		try {
			window.localStorage.setItem(
				`allauth:session:${path}`,
				String(Date.now()),
			);
		} catch {
			// A blocked storage API does not prevent authentication.
		}
	}

	function invalidateAfterSuccess(
		endpoint: string,
		method: string,
		data: Record<string, unknown> | null,
	) {
		if (data?.twoFactorRedirect === true) return;
		if (identityActions.has(endpoint)) {
			invalidateIdentity(true);
			broadcastSessionChange();
			return;
		}
		if (
			sessionActions.has(endpoint) ||
			endpoint.startsWith("two-factor/") ||
			(endpoint === "passkey/verify-registration" && data?.session)
		) {
			session.invalidate();
			broadcastSessionChange();
		}
		if (
			method === "POST" &&
			endpoint.startsWith("organization/") &&
			endpoint !== "organization/has-permission" &&
			endpoint !== "organization/check-slug"
		) {
			invalidateActiveOrganization(sessionActions.has(endpoint));
		}
		if (organizationListActions.has(endpoint)) organizations.invalidate();
		if (passkeyListActions.has(endpoint)) passkeys.invalidate();
	}

	const ceremonies = createPasskeyActions<
		Authentication & Partial<AllAuthSession>
	>(request);
	return {
		getSession,
		useSession: session.useQuery,
		useListOrganizations: organizations.useQuery,
		useActiveOrganization: activeOrganization.useQuery,
		useActiveMember: activeMember.useQuery,
		useActiveMemberRole: activeMemberRole.useQuery,
		useListPasskeys: passkeys.useQuery,
		signIn: {
			email: post<
				Authentication,
				{
					email: string;
					password: string;
					callbackURL?: string;
					rememberMe?: boolean;
				}
			>("sign-in/email"),
			username: post<
				Authentication,
				{
					username: string;
					password: string;
					callbackURL?: string;
					rememberMe?: boolean;
				}
			>("sign-in/username"),
			anonymous: postOptional<Authentication, Record<never, never>>(
				"sign-in/anonymous",
			),
			emailOtp: post<
				Authentication,
				{ email: string; otp: string; name?: string; image?: string }
			>("sign-in/email-otp"),
			magicLink: post<
				Status,
				{
					email: string;
					name?: string;
					callbackURL?: string;
					newUserCallbackURL?: string;
					errorCallbackURL?: string;
				}
			>("sign-in/magic-link"),
			social: post<Authentication, SocialInput>("sign-in/social"),
			passkey: ceremonies.signInPasskey,
		},
		signUp: {
			email: post<{ user: AllAuthUser }, SignupInput>("sign-up/email"),
		},
		signOut: postOptional<{ success: boolean }, Record<never, never>>(
			"sign-out",
		),
		requestPasswordReset: post<
			Status & { message?: string },
			{ email: string; redirectTo?: string }
		>("request-password-reset"),
		resetPassword: post<Status, { newPassword: string; token?: string }>(
			"reset-password",
		),
		updateUser: post<
			Status,
			{
				name?: string;
				image?: string | null;
				username?: string;
				displayUsername?: string;
			}
		>("update-user"),
		changePassword: post<
			{ user: AllAuthUser },
			{
				newPassword: string;
				currentPassword: string;
				revokeOtherSessions?: boolean;
			}
		>("change-password"),
		setPassword: post<Status, { newPassword: string }>("set-password"),
		changeEmail: post<Status, { newEmail: string; callbackURL?: string }>(
			"change-email",
		),
		deleteUser: post<
			Status & { message?: string },
			{ callbackURL?: string; password?: string; token?: string }
		>("delete-user"),
		listAccounts:
			get<
				{
					id: string;
					providerId: string;
					accountId: string;
					scopes?: string[];
				}[]
			>("list-accounts"),
		linkSocial: post<Authentication, SocialInput>("link-social"),
		unlinkAccount: post<Status, { providerId: string; accountId?: string }>(
			"unlink-account",
		),
		isUsernameAvailable: post<{ available: boolean }, { username: string }>(
			"is-username-available",
		),
		deleteAnonymousUser: postOptional<Status, Record<never, never>>(
			"delete-anonymous-user",
		),
		sendVerificationEmail: post<
			Status,
			{ email: string; callbackURL?: string }
		>("send-verification-email"),
		verifyEmail: get<
			Redirect & { user: AllAuthUser | null; status: boolean },
			{ token: string; callbackURL?: string }
		>("verify-email"),
		emailOtp: {
			sendVerificationOtp: post<
				{ success: boolean },
				{ email: string; type: OtpPurpose }
			>("email-otp/send-verification-otp"),
			checkVerificationOtp: post<
				{ success: boolean },
				{ email: string; otp: string; type: OtpPurpose }
			>("email-otp/check-verification-otp"),
			verifyEmail: post<Authentication, { email: string; otp: string }>(
				"email-otp/verify-email",
			),
			requestPasswordReset: post<{ success: boolean }, { email: string }>(
				"email-otp/request-password-reset",
			),
			resetPassword: post<
				{ success: boolean },
				{ email: string; otp: string; password: string }
			>("email-otp/reset-password"),
			requestEmailChange: post<
				{ success: boolean },
				{ newEmail: string; otp?: string }
			>("email-otp/request-email-change"),
			changeEmail: post<
				{ success: boolean },
				{ newEmail: string; otp: string }
			>("email-otp/change-email"),
		},
		organization,
		twoFactor: {
			enable: post<
				{ method: string; totpURI: string; backupCodes: string[] },
				{ password?: string; issuer?: string }
			>("two-factor/enable"),
			disable: post<Status, { password?: string }>("two-factor/disable"),
			verifyTotp: post<Authentication, FactorInput>("two-factor/verify-totp"),
			verifyBackupCode: post<
				Authentication,
				FactorInput & { disableSession?: boolean }
			>("two-factor/verify-backup-code"),
			generateBackupCodes: post<
				Status & { backupCodes: string[] },
				{ password?: string }
			>("two-factor/generate-backup-codes"),
			getTotpUri: post<{ totpURI: string }, { password?: string }>(
				"two-factor/get-totp-uri",
			),
		},
		passkey: {
			addPasskey: ceremonies.addPasskey,
			deletePasskey: post<Status, { id: string }>("passkey/delete-passkey"),
			updatePasskey: post<
				{ passkey: AllAuthPasskey },
				{ id: string; name: string }
			>("passkey/update-passkey"),
			listUserPasskeys: listPasskeys,
		},
	};
}

/** First-party browser operations exposed through useAllAuth().client. */
export type AllAuthClient = ReturnType<typeof createAllAuthClient>;
