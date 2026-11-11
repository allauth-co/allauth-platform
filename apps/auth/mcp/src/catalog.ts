// cspell:words organisation
import * as z from "zod";

/** A bounded, allowlisted AllAuth management request. */
export interface ToolRequest {
	method: "GET" | "POST" | "PATCH" | "DELETE";
	path: string;
	query?: Record<string, string | number | boolean | undefined>;
	body?: unknown;
}

/** Tool metadata consumed by the MCP transport and installation documentation. */
export interface AllAuthTool {
	name: string;
	description: string;
	inputSchema: z.ZodObject;
	readOnly: boolean;
	destructive?: boolean;
	sensitive?: boolean;
	buildRequest: (input: unknown) => ToolRequest;
}

type Flags = Pick<AllAuthTool, "destructive" | "sensitive">;

function tool<S extends z.ZodRawShape>(
	name: string,
	description: string,
	shape: S,
	readOnly: boolean,
	build: (input: z.output<z.ZodObject<S>>) => ToolRequest,
	flags: Flags = {},
): AllAuthTool {
	const inputSchema = z.object(shape).strict();
	return {
		name: `allauth_${name}`,
		description,
		inputSchema,
		readOnly,
		...flags,
		buildRequest: (input) => build(inputSchema.parse(input)),
	};
}

const id = z.string().trim().min(1).max(160);
const uuid = z.uuid();
const name = z.string().trim().min(1).max(100);
const email = z
	.email()
	.max(320)
	.transform((value) => value.toLowerCase());
const reserved = new Set([
	"admin",
	"platform",
	"auth",
	"api",
	"allauth",
	"public",
	"internal",
]);
const project = z
	.string()
	.regex(/^[a-z][a-z0-9-]{1,47}$/)
	.refine(
		(value) => !reserved.has(value),
		"Select an application environment slug.",
	);
const tenant = { project };
const clerkSourceId = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const clerkImportUser = z
	.object({
		sourceUserId: clerkSourceId,
		email,
		emailVerified: z.boolean(),
		name,
		image: z
			.url()
			.max(2048)
			.refine((value) => {
				const url = new URL(value);
				return url.protocol === "https:" && !url.username && !url.password;
			})
			.optional(),
		createdAt: z.iso.datetime({ offset: true }).optional(),
		updatedAt: z.iso.datetime({ offset: true }).optional(),
		passwordHash: z
			.string()
			.regex(/^\$2[aby]\$(?:0[4-9]|1[0-4])\$[./A-Za-z0-9]{53}$/)
			.optional(),
		passwordHasher: z.literal("bcrypt").optional(),
		socialAccounts: z
			.array(
				z
					.object({
						provider: z.enum(["google", "apple"]),
						subject: z.string().min(1).max(255),
					})
					.strict(),
			)
			.max(10)
			.default([]),
		banned: z.boolean().default(false),
		locked: z.boolean().default(false),
		twoFactorEnabled: z.boolean().default(false),
		publicMetadata: z.record(z.string(), z.json()).optional(),
		privateMetadata: z.record(z.string(), z.json()).optional(),
	})
	.strict();
const workspaceId = uuid;
const workspaceRole = z.enum(["owner", "admin", "member"]);
const role = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);
const customRole = role.refine(
	(value) => !["owner", "admin", "member"].includes(value),
	"Built-in roles cannot be changed.",
);
const page = {
	limit: z.number().int().min(1).max(100).default(25),
	offset: z.number().int().min(0).max(100000).default(0),
};
const search = z.string().trim().max(128).default("");
const nullableLogo = z
	.url()
	.max(2048)
	.refine((value) => new URL(value).protocol === "https:")
	.nullable()
	.optional();
const origin = z.url().refine((value) => {
	const url = new URL(value);
	return (
		value === url.origin &&
		!url.username &&
		!url.password &&
		!value.includes("*") &&
		(url.protocol === "https:" ||
			(url.protocol === "http:" &&
				["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
	);
}, "Use an exact HTTPS origin, or literal loopback HTTP for development.");
const segment = (value: string) => encodeURIComponent(value);
const rootWorkspace = (value: string) => `/api/workspaces/${segment(value)}`;
const native = (slug: string, path: string) =>
	`/api/projects/${segment(slug)}/auth/${path}`;
const organization = (value: string, suffix = "") =>
	`/api/admin/organizations/${segment(value)}${suffix}`;
const controlGet = (
	slug: string,
	path: string,
	query?: ToolRequest["query"],
): ToolRequest => ({
	method: "GET",
	path: native(slug, `control/${path}`),
	...(query ? { query } : {}),
});
const controlPost = (
	slug: string,
	path: string,
	body: unknown,
): ToolRequest => ({
	method: "POST",
	path: native(slug, `control/${path}`),
	body,
});

const calendarDate = z
	.string()
	.regex(/^\d{4}-\d{2}-\d{2}$/)
	.refine((value) => {
		const date = new Date(`${value}T00:00:00.000Z`);
		return (
			Number.isFinite(date.getTime()) &&
			date.toISOString().slice(0, 10) === value
		);
	}, "Use a real UTC calendar date.");
const analytics = {
	entity: z.enum(["users", "organizations"]).default("users"),
	range: z.enum(["7d", "30d", "90d", "6m"]).default("30d"),
	bucket: z.enum(["day", "week", "month"]).default("day"),
	end: calendarDate.optional(),
	from: calendarDate.optional(),
	to: calendarDate.optional(),
};
function analyticsQuery<T extends { from?: string; to?: string }>(value: T): T {
	if (Boolean(value.from) !== Boolean(value.to))
		throw new Error("Supply from and to together.");
	if (value.from && value.to && value.from > value.to)
		throw new Error("The start date must precede the end date.");
	return value;
}
const logFilters = {
	organizationId: id.optional(),
	userId: id.optional(),
	type: z
		.string()
		.max(128)
		.regex(/^[a-zA-Z0-9./_-]+$/)
		.optional(),
	outcome: z.enum(["success", "failure", "blocked"]).optional(),
	from: z.iso.datetime({ offset: true }).optional(),
	to: z.iso.datetime({ offset: true }).optional(),
	q: z.string().trim().min(1).max(128).optional(),
};
function interval<T extends { from?: string; to?: string }>(value: T): T {
	if (value.from && value.to && new Date(value.from) > new Date(value.to))
		throw new Error("The start date must precede the end date.");
	return value;
}
const policy = z
	.object({
		emailAndPasswordEnabled: z.boolean(),
		signUpEnabled: z.boolean(),
		requireEmailVerification: z.boolean(),
		sessionExpiresInSeconds: z
			.number()
			.int()
			.min(900)
			.max(30 * 86400),
		mfaMode: z.enum(["optional", "required"]),
		organizationCreation: z.enum(["verified-users", "admins-only", "disabled"]),
		passwordPolicy: z
			.object({
				minLength: z.number().int().min(6).max(128),
				maxLength: z.number().int().min(8).max(128),
				requireUppercase: z.boolean(),
				requireLowercase: z.boolean(),
				requireNumber: z.boolean(),
				requireSymbol: z.boolean(),
			})
			.strict()
			.refine(
				(value) => value.maxLength >= value.minLength,
				"Maximum password length must be at least the minimum.",
			)
			.optional(),
		supportAccess: z
			.object({
				applicationInitiated: z
					.object({
						enabled: z.boolean(),
						authorizeUrl: z.url().max(2048),
						returnUrl: z.url().max(2048),
					})
					.strict()
					.optional(),
				enabled: z.boolean(),
				callbackUrl: z
					.url()
					.max(2048)
					.refine((value) => {
						const url = new URL(value);
						return (
							value === url.href &&
							url.href === `${url.origin}${url.pathname}` &&
							!url.username &&
							!url.password &&
							/^\/(?:[a-zA-Z0-9_-]+\/)+support\/callback$/.test(url.pathname) &&
							(url.protocol === "https:" ||
								(url.protocol === "http:" &&
									["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
						);
					}, "Use the application's exact HTTPS proxy /support/callback URL."),
			})
			.strict()
			.optional(),
	})
	.strict()
	.refine(
		(value) =>
			value.mfaMode !== "required" ||
			(!value.signUpEnabled && value.requireEmailVerification),
		"Required MFA requires verified accounts and disabled sign-ups.",
	);
const version = z.number().int().min(0).max(2147483646);
const color = z
	.string()
	.regex(/^#[a-fA-F0-9]{6}$/)
	.transform((value) => value.toLowerCase());
const branding = z
	.object({
		name,
		supportEmail: z.email().max(254).nullable(),
		logoUrl: z.string().max(600).nullable(),
		logoDarkUrl: z.string().max(600).nullable(),
		faviconUrl: z.string().max(600).nullable(),
		primaryColor: color,
		darkPrimaryColor: color,
		showPoweredBy: z.boolean(),
	})
	.strict();
const securityPolicy = z
	.object({
		mode: z.enum(["enforce", "monitor"]),
		maxFailuresPerIp: z.number().int().min(3).max(1000),
		failureWindowSeconds: z.number().int().min(60).max(86400),
		blockSeconds: z.number().int().min(60).max(86400),
		maxSignUpsPerIp: z.number().int().min(1).max(1000),
		signUpWindowSeconds: z.number().int().min(60).max(86400),
		blockedEmailDomains: z.array(z.string().min(1).max(253)).max(200),
		logRetentionDays: z.number().int().min(7).max(365),
		newDeviceNotifications: z.boolean(),
	})
	.strict();
const webhookEvents = [
	"*",
	"user.*",
	"user.created",
	"user.updated",
	"user.deleted",
	"session.*",
	"session.created",
	"session.deleted",
	"auth.sign-in",
	"account.*",
	"organization.*",
	"mfa.*",
	"admin.*",
	"security.*",
	"directory.*",
	"oauth2.*",
	"passkey.*",
	"sso.*",
	"api-key.*",
	"legacy.audit",
] as const;
const permissions = z
	.object({
		organization: z.array(z.enum(["update", "delete"])).optional(),
		member: z.array(z.enum(["create", "update", "delete"])).optional(),
		invitation: z.array(z.enum(["create", "cancel"])).optional(),
		team: z.array(z.enum(["create", "update", "delete"])).optional(),
		ac: z.array(z.enum(["create", "read", "update", "delete"])).optional(),
	})
	.strict();
const oauthSettings = {
	name,
	redirectUris: z.array(z.string().max(2048)).min(1).max(20),
	organizationIds: z.array(z.string().min(1).max(200)).max(100).default([]),
	resourceURI: z.string().max(2048).optional(),
	allowLocalhost: z.boolean().default(false),
	allowDeviceAuthorization: z.boolean().default(false),
};

/** Explicit operations use only existing REST contracts; no caller can choose a raw URL, method or header. */
export const tools: AllAuthTool[] = [
	tool(
		"health",
		"Check AllAuth service health without reading accounts.",
		{},
		true,
		() => ({ method: "GET", path: "/api/health" }),
	),
	tool(
		"workspaces_list",
		"List workspaces visible to the current verified root account.",
		{},
		true,
		() => ({ method: "GET", path: "/api/workspaces" }),
	),
	tool(
		"workspace_get",
		"Read one workspace, its members and pending invitations.",
		{ workspaceId },
		true,
		(v) => ({ method: "GET", path: rootWorkspace(v.workspaceId) }),
	),
	tool(
		"workspace_create",
		"Create a workspace owned by the current root account.",
		{
			name: z.string().trim().min(2).max(100),
			slug: z
				.string()
				.regex(/^[a-z][a-z0-9-]{1,47}$/)
				.refine(
					(value) =>
						![
							"allauth-platform",
							"admin",
							"platform",
							"public",
							"internal",
						].includes(value),
				),
		},
		false,
		(body) => ({ method: "POST", path: "/api/workspaces", body }),
	),
	tool(
		"workspace_update",
		"Rename a workspace.",
		{ workspaceId, name: z.string().trim().min(2).max(100) },
		false,
		({ workspaceId: key, ...body }) => ({
			method: "PATCH",
			path: rootWorkspace(key),
			body,
		}),
	),
	tool(
		"workspace_delete",
		"Delete an empty workspace. Existing server ownership and emptiness checks apply.",
		{ workspaceId },
		false,
		(v) => ({ method: "DELETE", path: rootWorkspace(v.workspaceId) }),
		{ destructive: true },
	),
	tool(
		"workspace_invite",
		"Send a workspace invitation email. This contacts the recipient.",
		{ workspaceId, email, role: workspaceRole.default("member") },
		false,
		({ workspaceId: key, ...body }) => ({
			method: "POST",
			path: `${rootWorkspace(key)}/invitations`,
			body,
		}),
	),
	tool(
		"workspace_invitation_resend",
		"Resend an existing workspace invitation email; original expiry and one-minute spacing remain enforced.",
		{ workspaceId, invitationId: uuid },
		false,
		(v) => ({
			method: "POST",
			path: `${rootWorkspace(v.workspaceId)}/invitations/${segment(v.invitationId)}`,
		}),
	),
	tool(
		"workspace_invitation_cancel",
		"Cancel a pending workspace invitation.",
		{ workspaceId, invitationId: uuid },
		false,
		(v) => ({
			method: "DELETE",
			path: `${rootWorkspace(v.workspaceId)}/invitations/${segment(v.invitationId)}`,
		}),
		{ destructive: true },
	),
	tool(
		"workspace_member_role_update",
		"Change a workspace member role; sole owner protection remains enforced.",
		{ workspaceId, memberId: uuid, role: workspaceRole },
		false,
		(v) => ({
			method: "PATCH",
			path: `${rootWorkspace(v.workspaceId)}/members/${segment(v.memberId)}`,
			body: { role: v.role },
		}),
	),
	tool(
		"workspace_member_remove",
		"Remove a workspace member; sole owner protection remains enforced.",
		{ workspaceId, memberId: uuid },
		false,
		(v) => ({
			method: "DELETE",
			path: `${rootWorkspace(v.workspaceId)}/members/${segment(v.memberId)}`,
		}),
		{ destructive: true },
	),
	tool(
		"workspace_invitations_list",
		"List invitations addressed to the current verified root account.",
		{},
		true,
		() => ({ method: "GET", path: "/api/workspace-invitations" }),
	),
	tool(
		"workspace_invitation_accept",
		"Accept a pending workspace invitation for the current verified email address.",
		{ invitationId: uuid },
		false,
		(v) => ({
			method: "POST",
			path: `/api/workspace-invitations/${segment(v.invitationId)}/accept`,
		}),
	),
	tool(
		"projects_list",
		"List authorized application environments, including exact slugs, workspace and application IDs.",
		{ workspaceId: workspaceId.optional() },
		true,
		(v) => ({
			method: "GET",
			path: "/api/admin/projects",
			query: { workspace: v.workspaceId },
		}),
	),
	tool(
		"project_origins_get",
		"Read versioned canonical and allowed app origins for one exact environment, plus broker reconciliation status. Does not return credentials.",
		tenant,
		true,
		(v) => ({
			method: "GET",
			path: `/api/admin/projects/${segment(v.project)}/origins`,
		}),
	),
	tool(
		"project_origins_update",
		"Replace exact app origins using the selected immutable project ID, environment and current version. Preserve localhost explicitly when needed. Changing the canonical origin changes the passkey RP and provider callbacks; external Google/Apple registrations require separate review. A pending result requires retry, not a claim of completion.",
		{
			...tenant,
			projectId: uuid,
			environment: z.enum(["development", "production"]),
			version: z.string().regex(/^[a-f0-9]{64}$/),
			primaryOrigin: origin,
			origins: z.array(origin).min(1).max(10),
		},
		false,
		({ project: selected, ...body }) => {
			if (
				!body.origins.includes(body.primaryOrigin) ||
				new Set(body.origins).size !== body.origins.length ||
				(body.environment === "production" &&
					body.origins.some((value) => !value.startsWith("https:")))
			)
				throw new Error(
					"Provide the complete distinct origin list, including the primary origin; production requires HTTPS.",
				);
			return {
				method: "PATCH",
				path: `/api/admin/projects/${segment(selected)}/origins`,
				body,
			};
		},
	),
	tool(
		"project_create",
		"Provision an application environment in an explicit workspace. Returns a proxy secret once; requires sensitive tools.",
		{
			workspaceId,
			name: z.string().trim().min(2).max(100),
			slug: project,
			primaryOrigin: origin,
			origins: z.array(origin).max(10).default([]),
			applicationId: uuid.optional(),
			environment: z.enum(["development", "production"]),
		},
		false,
		(body) => {
			if (
				body.environment === "production" &&
				body.primaryOrigin.startsWith("http:")
			)
				throw new Error("Production environments require HTTPS.");
			return { method: "POST", path: "/api/admin/projects", body };
		},
		{ sensitive: true },
	),
	tool(
		"project_proxy_secret_rotate",
		"Rotate an environment proxy secret, invalidating the old one. Returns a credential once.",
		tenant,
		false,
		(v) => ({
			method: "POST",
			path: `/api/admin/projects/${segment(v.project)}/proxy-secret`,
		}),
		{ sensitive: true, destructive: true },
	),
	tool(
		"backend_credentials_list",
		"List scoped read-only backend credentials; keys and hashes are excluded.",
		tenant,
		true,
		(v) => ({
			method: "GET",
			path: `/api/admin/projects/${segment(v.project)}/backend-credentials`,
		}),
	),
	tool(
		"backend_credential_create",
		"Issue a project-bound directory:read backend credential once. It never grants sessions, writes or workspace administration.",
		{
			...tenant,
			name,
			expiresInDays: z.number().int().min(1).max(90).default(90),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: `/api/admin/projects/${segment(selected)}/backend-credentials`,
			body,
		}),
		{ sensitive: true },
	),
	tool(
		"backend_credential_revoke",
		"Immediately revoke one selected environment backend credential.",
		{ ...tenant, credentialId: uuid },
		false,
		(v) => ({
			method: "DELETE",
			path: `/api/admin/projects/${segment(v.project)}/backend-credentials/${segment(v.credentialId)}`,
		}),
		{ destructive: true },
	),
	tool(
		"domains_list",
		"List hosted and custom domains for one application environment.",
		tenant,
		true,
		(v) => ({
			method: "GET",
			path: `/api/admin/projects/${segment(v.project)}/domains`,
		}),
	),
	tool(
		"domain_create",
		"Add a custom authentication domain and obtain its required DNS records.",
		{ ...tenant, domain: z.string().trim().min(4).max(240) },
		false,
		(v) => ({
			method: "POST",
			path: `/api/admin/projects/${segment(v.project)}/domains`,
			body: { domain: v.domain },
		}),
	),
	tool(
		"domain_verify",
		"Check DNS ownership and hosting status for an existing custom domain.",
		{ ...tenant, domainId: uuid },
		false,
		(v) => ({
			method: "POST",
			path: `/api/admin/projects/${segment(v.project)}/domains/${segment(v.domainId)}/verify`,
		}),
	),
	tool(
		"domain_delete",
		"Remove a custom domain and update authentication routing. A pending deletion can return HTTP 202.",
		{ ...tenant, domainId: uuid },
		false,
		(v) => ({
			method: "DELETE",
			path: `/api/admin/projects/${segment(v.project)}/domains/${segment(v.domainId)}`,
		}),
		{ destructive: true },
	),
	tool(
		"users_list",
		"Search the selected environment's user directory; excludes platform account administration. Optional excludeOrganizationId finds users who are not already organization members.",
		{
			...tenant,
			search,
			status: z
				.enum(["all", "verified", "unverified", "banned"])
				.default("all"),
			role: z.enum(["all", "admin", "user"]).default("all"),
			sort: z
				.enum(["createdAt", "name", "email", "lastSignInAt"])
				.default("createdAt"),
			direction: z.enum(["asc", "desc"]).default("desc"),
			excludeOrganizationId: id.optional(),
			...page,
		},
		true,
		(query) => ({ method: "GET", path: "/api/admin/users", query }),
	),
	tool(
		"user_get",
		"Read one user from the selected environment, including directory details and metadata.",
		{ ...tenant, userId: id },
		true,
		({ project: selected, userId }) => ({
			method: "GET",
			path: `/api/admin/users/${segment(userId)}`,
			query: { project: selected },
		}),
	),
	tool(
		"user_create",
		"Create an unverified user in the selected environment. Optional password is sensitive input.",
		{
			...tenant,
			email,
			name,
			password: z.string().min(6).max(128).optional(),
			role: z.enum(["user", "admin"]).default("user"),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/create-user"),
			body,
		}),
	),
	tool(
		"invitations_import",
		"Dry-run or silently import bounded pending organisation invitations with immutable source provenance. Sends no email; requires verified current workspace administration.",
		{
			...tenant,
			sourceInstance: clerkSourceId,
			dryRun: z.boolean().default(true),
			invitations: z
				.array(
					z
						.object({
							sourceInvitationId: clerkSourceId,
							organizationId: id,
							email,
							role,
							inviterId: id,
							expiresAt: z.iso.datetime({ offset: true }),
							createdAt: z.iso.datetime({ offset: true }).optional(),
							sourceUpdatedAt: z.iso.datetime({ offset: true }).optional(),
						})
						.strict(),
				)
				.min(1)
				.max(100),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/import-invitations"),
			body,
		}),
		{ sensitive: true },
	),
	tool(
		"users_import_clerk",
		"Dry-run or import at most 100 Clerk identities into the exact environment. Existing source identities are never overwritten; source drift and ownership/MFA conflicts require reconciliation. Hash-bearing input is sensitive; results contain only source IDs, destination IDs and safe statuses.",
		{
			...tenant,
			sourceInstance: clerkSourceId,
			dryRun: z.boolean().default(true),
			users: z.array(clerkImportUser).min(1).max(100),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/import-clerk-users"),
			body,
		}),
		{ sensitive: true },
	),
	tool(
		"user_ban",
		"Ban a user in one environment and revoke their sessions and grants.",
		{
			...tenant,
			userId: id,
			banReason: z.string().trim().max(500).optional(),
			banExpiresIn: z
				.number()
				.int()
				.min(1)
				.max(365 * 86400)
				.optional(),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/ban-user"),
			body,
		}),
		{ destructive: true },
	),
	tool(
		"user_unban",
		"Remove a user's ban in the selected environment.",
		{ ...tenant, userId: id },
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/unban-user"),
			body,
		}),
	),
	tool(
		"user_role_update",
		"Set a user's environment role and revoke current sessions and grants.",
		{ ...tenant, userId: id, role: z.enum(["user", "admin"]) },
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/set-role"),
			body,
		}),
		{ destructive: true },
	),
	tool(
		"user_sessions_revoke",
		"Revoke every session and grant for a user in one environment.",
		{ ...tenant, userId: id },
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/revoke-user-sessions"),
			body,
		}),
		{ destructive: true },
	),
	tool(
		"user_delete",
		"Permanently remove a user from the selected environment and revoke their sessions and grants.",
		{ ...tenant, userId: id },
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: native(selected, "project-admin/remove-user"),
			body,
		}),
		{ destructive: true },
	),
	tool(
		"user_metadata_update",
		"Replace supplied public and/or private metadata for one environment user. Omitted metadata is preserved.",
		{
			...tenant,
			userId: id,
			publicMetadata: z.record(z.string(), z.unknown()).optional(),
			privateMetadata: z.record(z.string(), z.unknown()).optional(),
		},
		false,
		({ project: selected, userId, ...body }) => {
			if (
				body.publicMetadata === undefined &&
				body.privateMetadata === undefined
			)
				throw new Error("Supply publicMetadata or privateMetadata.");
			return {
				method: "PATCH",
				path: `/api/admin/users/${segment(userId)}/metadata`,
				query: { project: selected },
				body,
			};
		},
	),
	tool(
		"organizations_list",
		"Search organizations in the selected environment.",
		{ ...tenant, search, ...page },
		true,
		(query) => ({ method: "GET", path: "/api/admin/organizations", query }),
	),
	tool(
		"organization_get",
		"Read one organization and a bounded summary of members, teams, roles and invitations. Use the organization collection list tools to page through all records.",
		{ ...tenant, organizationId: id },
		true,
		(v) => ({
			method: "GET",
			path: organization(v.organizationId),
			query: { project: v.project },
		}),
	),
	tool(
		"organization_members_list",
		"Page and search an organization's members in the selected environment. Optional teamId selects its roster; excludeTeam finds members available to add. Follow total, limit and offset for complete results.",
		{
			...tenant,
			organizationId: id,
			search,
			...page,
			teamId: id.optional(),
			excludeTeam: z.boolean().default(false),
		},
		true,
		({ organizationId, ...query }) => {
			if (query.excludeTeam && !query.teamId)
				throw new Error("Supply teamId when excluding team members.");
			return {
				method: "GET",
				path: organization(organizationId, "/members"),
				query,
			};
		},
	),
	tool(
		"organization_teams_list",
		"Page and search all teams in an organization, including current member counts. Follow total, limit and offset for complete results.",
		{ ...tenant, organizationId: id, search, ...page },
		true,
		({ organizationId, ...query }) => ({
			method: "GET",
			path: organization(organizationId, "/teams"),
			query,
		}),
	),
	tool(
		"organization_roles_list",
		"Page and search built-in and custom organization roles with their permissions. Follow total, limit and offset for complete results.",
		{ ...tenant, organizationId: id, search, ...page },
		true,
		({ organizationId, ...query }) => ({
			method: "GET",
			path: organization(organizationId, "/roles"),
			query,
		}),
	),
	tool(
		"organization_invitations_list",
		"Page and search organization invitation history, including older pending invitations. Follow total, limit and offset for complete results.",
		{ ...tenant, organizationId: id, search, ...page },
		true,
		({ organizationId, ...query }) => ({
			method: "GET",
			path: organization(organizationId, "/invitations"),
			query,
		}),
	),
	tool(
		"organization_create",
		"Create an organization for a verified active owner from the same environment.",
		{
			...tenant,
			name,
			slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,63}$/),
			ownerId: id,
			logo: nullableLogo,
		},
		false,
		({ project: selected, ...body }) => ({
			method: "POST",
			path: "/api/admin/organizations",
			query: { project: selected },
			body,
		}),
	),
	tool(
		"organization_update",
		"Update an organization name, slug or logo in one environment.",
		{
			...tenant,
			organizationId: id,
			name: name.optional(),
			slug: z
				.string()
				.regex(/^[a-z0-9][a-z0-9-]{1,63}$/)
				.optional(),
			logo: nullableLogo,
		},
		false,
		({ project: selected, organizationId, ...body }) => {
			if (
				body.name === undefined &&
				body.slug === undefined &&
				body.logo === undefined
			)
				throw new Error("Supply a name, slug or logo change.");
			return {
				method: "PATCH",
				path: organization(organizationId),
				query: { project: selected },
				body,
			};
		},
	),
	tool(
		"organization_delete",
		"Delete an organization with explicit ID confirmation. Enterprise connections and OAuth bindings must be removed first.",
		{ ...tenant, organizationId: id, confirmOrganizationId: id },
		false,
		(v) => {
			if (v.organizationId !== v.confirmOrganizationId)
				throw new Error("confirmOrganizationId must match organizationId.");
			return {
				method: "DELETE",
				path: organization(v.organizationId),
				query: { project: v.project },
				body: { confirmOrganizationId: v.confirmOrganizationId },
			};
		},
		{ destructive: true },
	),
	tool(
		"organization_member_add",
		"Add a verified active environment user to an organization.",
		{ ...tenant, organizationId: id, userId: id, role: role.default("member") },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/members"),
			query: { project: selected },
			body: { action: "add", ...body },
		}),
	),
	tool(
		"organization_member_role_update",
		"Change a member's organization role. Server protects sole owners and directory-managed memberships.",
		{ ...tenant, organizationId: id, memberId: id, role },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/members"),
			query: { project: selected },
			body: { action: "update", ...body },
		}),
	),
	tool(
		"organization_member_remove",
		"Remove an organization member and revoke organization grants.",
		{ ...tenant, organizationId: id, memberId: id },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/members"),
			query: { project: selected },
			body: { action: "remove", ...body },
		}),
		{ destructive: true },
	),
	tool(
		"team_create",
		"Create a team inside an organization.",
		{ ...tenant, organizationId: id, name },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/teams"),
			query: { project: selected },
			body: { action: "create", ...body },
		}),
	),
	tool(
		"team_update",
		"Rename an organization team.",
		{ ...tenant, organizationId: id, teamId: id, name },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/teams"),
			query: { project: selected },
			body: { action: "update", ...body },
		}),
	),
	tool(
		"team_delete",
		"Delete a team and clear its active-session links.",
		{ ...tenant, organizationId: id, teamId: id },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/teams"),
			query: { project: selected },
			body: { action: "delete", ...body },
		}),
		{ destructive: true },
	),
	tool(
		"team_member_add",
		"Add an existing organization member to a team.",
		{ ...tenant, organizationId: id, teamId: id, userId: id },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/teams"),
			query: { project: selected },
			body: { action: "add-member", ...body },
		}),
	),
	tool(
		"team_member_remove",
		"Remove a user from a team.",
		{ ...tenant, organizationId: id, teamId: id, userId: id },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/teams"),
			query: { project: selected },
			body: { action: "remove-member", ...body },
		}),
		{ destructive: true },
	),
	tool(
		"organization_role_create",
		"Create a custom organization role using supported organization permissions.",
		{
			...tenant,
			organizationId: id,
			role: customRole,
			permission: permissions,
		},
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/roles"),
			query: { project: selected },
			body: { action: "create", ...body },
		}),
	),
	tool(
		"organization_role_update",
		"Replace a custom organization's role permissions and revoke affected grants.",
		{
			...tenant,
			organizationId: id,
			role: customRole,
			permission: permissions,
		},
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/roles"),
			query: { project: selected },
			body: { action: "update", ...body },
		}),
	),
	tool(
		"organization_role_delete",
		"Delete an unused custom organization role. Reassign its members first.",
		{ ...tenant, organizationId: id, role: customRole },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/roles"),
			query: { project: selected },
			body: { action: "delete", ...body },
		}),
		{ destructive: true },
	),
	tool(
		"organization_invite",
		"Send an organization invitation email. This contacts the recipient.",
		{
			...tenant,
			organizationId: id,
			email,
			role: role.default("member"),
			inviterId: id.optional(),
			teamId: id.optional(),
		},
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/invitations"),
			query: { project: selected },
			body: { action: "send", ...body },
		}),
	),
	tool(
		"organization_invitation_cancel",
		"Cancel a pending organization invitation.",
		{ ...tenant, organizationId: id, invitationId: id },
		false,
		({ project: selected, organizationId, ...body }) => ({
			method: "POST",
			path: organization(organizationId, "/invitations"),
			query: { project: selected },
			body: { action: "cancel", ...body },
		}),
		{ destructive: true },
	),
	tool(
		"google_provider_get",
		"Read versioned direct Google settings, exact callbacks and effective provider for one environment. Client secrets are never returned.",
		tenant,
		true,
		({ project: selected }) => ({
			method: "GET",
			path: `/api/admin/projects/${segment(selected)}/providers/google`,
		}),
	),
	tool(
		"google_provider_update",
		"Configure direct Google OAuth for one exact environment using its current version. Empty or omitted secret preserves the stored credential; disabling direct Google retains credentials and uses the shared broker when available.",
		{
			...tenant,
			version,
			google: z
				.object({
					enabled: z.boolean(),
					clientId: z
						.string()
						.trim()
						.max(512)
						.refine(
							(value) =>
								value === "" ||
								/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(value),
							"Use a Google OAuth web client ID.",
						),
					clientSecret: z
						.string()
						.trim()
						.max(4096)
						.refine(
							(value) => !/[\x00-\x20\x7f]/.test(value),
							"Use a Google secret without whitespace.",
						)
						.optional(),
				})
				.strict(),
		},
		false,
		({ project: selected, ...body }) => ({
			method: "PATCH",
			path: `/api/admin/projects/${segment(selected)}/providers/google`,
			body,
		}),
		{ sensitive: true },
	),
	tool(
		"configuration_get",
		"Read the complete versioned authentication policy and provider capabilities for one environment.",
		tenant,
		true,
		(query) => ({ method: "GET", path: "/api/admin/configuration", query }),
	),
	tool(
		"configuration_update",
		"Save a complete authentication policy with its current version. Server enforces lockout and MFA enrollment checks.",
		{ ...tenant, version, policy },
		false,
		({ project: selected, ...body }) => ({
			method: "PATCH",
			path: "/api/admin/configuration",
			query: { project: selected },
			body,
		}),
	),
	tool(
		"branding_get",
		"Read application branding shared by Development and Production and the current settings version.",
		tenant,
		true,
		(query) => ({
			method: "GET",
			path: "/api/admin/application-settings",
			query,
		}),
	),
	tool(
		"branding_update",
		"Save complete application branding using the current settings version. Asset URLs must belong to this application.",
		{ ...tenant, version, branding },
		false,
		({ project: selected, ...body }) => ({
			method: "PATCH",
			path: "/api/admin/application-settings",
			query: { project: selected },
			body,
		}),
	),
	tool(
		"branding_asset_upload",
		"Upload and save one application logo or favicon from inline base64 image bytes, at most 2 MB. Read the current branding version first.",
		{
			...tenant,
			version,
			kind: z.enum(["logo", "logoDark", "favicon"]),
			contentType: z.enum([
				"image/png",
				"image/jpeg",
				"image/webp",
				"image/x-icon",
			]),
			data: z
				.string()
				.min(4)
				.max(2796204)
				.regex(
					/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
				),
		},
		false,
		(v) => {
			const bytes = Uint8Array.from(atob(v.data), (character) =>
				character.charCodeAt(0),
			);
			if (!bytes.byteLength || bytes.byteLength > 2097152)
				throw new Error("Upload an image no larger than 2 MB.");
			if (
				v.kind === "favicon"
					? !["image/png", "image/x-icon"].includes(v.contentType)
					: v.contentType === "image/x-icon"
			)
				throw new Error("The image format does not match this branding field.");
			const extensions = {
				"image/png": "png",
				"image/jpeg": "jpg",
				"image/webp": "webp",
				"image/x-icon": "ico",
			};
			const body = new FormData();
			body.set("kind", v.kind);
			body.set("version", String(v.version));
			body.set(
				"file",
				new Blob([bytes], { type: v.contentType }),
				`asset.${extensions[v.contentType]}`,
			);
			return {
				method: "POST",
				path: "/api/admin/application-settings/assets",
				query: { project: v.project },
				body,
			};
		},
	),
	tool(
		"overview_get",
		"Read environment user, organization, session and sign-in summary counts.",
		tenant,
		true,
		(v) => controlGet(v.project, "overview"),
	),
	tool(
		"analytics_get",
		"Read UTC native authentication activity analytics. Preserve coverage and incomplete-history flags.",
		{ ...tenant, ...analytics },
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "analytics", analyticsQuery(query)),
	),
	tool(
		"analytics_entities_list",
		"List exact members of an authentication activity cohort for the selected UTC period.",
		{
			...tenant,
			...analytics,
			cohort: z
				.enum([
					"active",
					"new",
					"retained",
					"reactivated",
					"churned",
					"firstActive",
					"unknown",
					"all",
				])
				.default("active"),
			q: z.string().trim().min(1).max(128).optional(),
			...page,
		},
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "analytics/entities", analyticsQuery(query)),
	),
	tool(
		"events_list",
		"Search retained audit events for the selected environment's administrator scope.",
		{ ...tenant, ...logFilters, ...page },
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "events", { scope: "admin", ...interval(query) }),
	),
	tool(
		"logs_list",
		"Search retained environment audit logs, including actor, IP, target, application and session filters.",
		{
			...tenant,
			...logFilters,
			ipAddress: z.string().max(64).optional(),
			actorId: id.optional(),
			targetId: id.optional(),
			clientId: id.optional(),
			sessionId: id.optional(),
			...page,
		},
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "logs", { scope: "admin", ...interval(query) }),
	),
	tool(
		"log_get",
		"Inspect one retained environment audit log entry by exact ID.",
		{ ...tenant, id, ...logFilters },
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "logs/detail", {
				scope: "admin",
				...interval(query),
			}),
	),
	tool(
		"sessions_list",
		"List safe session attributes for one environment. Session tokens are never returned.",
		{
			...tenant,
			userId: id.optional(),
			q: z.string().trim().min(1).max(128).optional(),
			...page,
		},
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "sessions", query),
	),
	tool(
		"session_revoke",
		"Revoke one environment session by its safe session ID and revoke linked grants.",
		{ ...tenant, id },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "revoke-session", body),
		{ destructive: true },
	),
	tool(
		"security_get",
		"Read the environment abuse protection policy, active rules, counters and implemented capabilities.",
		tenant,
		true,
		(v) => controlGet(v.project, "security"),
	),
	tool(
		"security_update",
		"Replace the environment abuse policy. Read its current policy first and retain intended unchanged fields.",
		{ ...tenant, policy: securityPolicy },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "security/update", body),
	),
	tool(
		"security_rule_add",
		"Add or update an exact IP/email-domain block rule with an optional expiry within one year.",
		{
			...tenant,
			type: z.enum(["ip", "email-domain"]),
			value: z.string().min(1).max(253),
			reason: z.string().trim().min(1).max(200),
			expiresAt: z.iso.datetime({ offset: true }).optional(),
		},
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "security/rules/add", body),
	),
	tool(
		"security_rule_remove",
		"Remove an environment abuse block rule by ID.",
		{ ...tenant, id: uuid },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "security/rules/remove", body),
		{ destructive: true },
	),
	tool(
		"webhooks_list",
		"List webhook endpoints for one environment without revealing signing secrets.",
		tenant,
		true,
		(v) => controlGet(v.project, "webhooks"),
	),
	tool(
		"webhook_create",
		"Register a public HTTPS webhook destination. Returns its signing secret once.",
		{
			...tenant,
			url: z.url().max(2048),
			description: z.string().trim().max(200).default(""),
			eventTypes: z
				.array(z.enum(webhookEvents))
				.min(1)
				.max(webhookEvents.length),
		},
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "webhooks/create", body),
		{ sensitive: true },
	),
	tool(
		"webhook_secret_rotate",
		"Rotate a webhook signing secret, invalidating its previous secret. Returns the replacement once.",
		{ ...tenant, id },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "webhooks/rotate", body),
		{ sensitive: true, destructive: true },
	),
	tool(
		"webhook_delete",
		"Delete a webhook endpoint and its queued deliveries.",
		{ ...tenant, id },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "webhooks/delete", body),
		{ destructive: true },
	),
	tool(
		"webhook_deliveries_list",
		"List safe webhook delivery metadata within the server's 30-day retention.",
		{ ...tenant, endpointId: id.optional(), ...page },
		true,
		({ project: selected, ...query }) =>
			controlGet(selected, "webhooks/deliveries", query),
	),
	tool(
		"webhook_delivery_retry",
		"Requeue a failed webhook delivery with remaining attempts. This can contact its destination.",
		{ ...tenant, id },
		false,
		({ project: selected, ...body }) =>
			controlPost(selected, "webhooks/retry", body),
	),
	tool(
		"oauth_clients_list",
		"List native OAuth clients in the selected environment. Workspace administration grants read access only.",
		tenant,
		true,
		(query) => ({ method: "GET", path: "/api/admin/applications", query }),
	),
	tool(
		"platform_oauth_clients_list",
		"List root-platform OAuth integration clients. Requires a platform administrator.",
		{},
		true,
		() => ({ method: "GET", path: "/api/admin/applications" }),
	),
	tool(
		"platform_oauth_client_create",
		"Create a root-platform OAuth client with exact callbacks and mandatory PKCE. Requires platform admin; returns a confidential client secret once.",
		{ ...oauthSettings, kind: z.enum(["confidential", "public"]) },
		false,
		(body) => ({ method: "POST", path: "/api/admin/applications", body }),
		{ sensitive: true },
	),
	tool(
		"platform_oauth_client_update",
		"Update a root-platform OAuth client and revoke its tokens and consent. Requires platform administrator.",
		{ clientId: id, ...oauthSettings },
		false,
		({ clientId, ...body }) => ({
			method: "PATCH",
			path: `/api/admin/applications/${segment(clientId)}`,
			body,
		}),
		{ destructive: true },
	),
	tool(
		"platform_oauth_client_delete",
		"Delete a root-platform OAuth client. Requires platform administrator.",
		{ clientId: id },
		false,
		(v) => ({
			method: "DELETE",
			path: `/api/admin/applications/${segment(v.clientId)}`,
		}),
		{ destructive: true },
	),
	tool(
		"scim_connections_list",
		"Read managed SCIM directory connections for an organization in the selected environment.",
		{ ...tenant, organizationId: id },
		true,
		(v) => ({
			method: "GET",
			path: `/api/organizations/${segment(v.organizationId)}/scim`,
			query: { project: v.project },
		}),
	),
	tool(
		"scim_connection_create",
		"Bind a verified organization SSO provider to a managed SCIM directory. Returns a provisioning credential once.",
		{
			...tenant,
			organizationId: id,
			providerId: z.string().trim().min(1).max(255),
		},
		false,
		(v) => ({
			method: "POST",
			path: `/api/organizations/${segment(v.organizationId)}/scim`,
			query: { project: v.project },
			body: { providerId: v.providerId },
		}),
		{ sensitive: true },
	),
	tool(
		"scim_credential_rotate",
		"Rotate a managed SCIM credential for an organization. Returns a provisioning credential once.",
		{ ...tenant, organizationId: id, connectionId: z.string().min(1).max(255) },
		false,
		(v) => ({
			method: "POST",
			path: `/api/organizations/${segment(v.organizationId)}/scim/${segment(v.connectionId)}/rotate`,
			query: { project: v.project },
			body: {},
		}),
		{ sensitive: true },
	),
	tool(
		"scim_credential_revoke",
		"Revoke one credential belonging to this organization's managed SCIM connection.",
		{
			...tenant,
			organizationId: id,
			connectionId: z.string().min(1).max(255),
			credentialId: z.string().min(1).max(255),
		},
		false,
		(v) => ({
			method: "POST",
			path: `/api/organizations/${segment(v.organizationId)}/scim/${segment(v.connectionId)}/revoke`,
			query: { project: v.project },
			body: { credentialId: v.credentialId },
		}),
		{ destructive: true },
	),
	tool(
		"scim_connection_decommission",
		"Decommission an organization's managed SCIM connection. Existing server lifecycle checks apply.",
		{ ...tenant, organizationId: id, connectionId: z.string().min(1).max(255) },
		false,
		(v) => ({
			method: "POST",
			path: `/api/organizations/${segment(v.organizationId)}/scim/${segment(v.connectionId)}/decommission`,
			query: { project: v.project },
			body: {},
		}),
		{ destructive: true },
	),
];
