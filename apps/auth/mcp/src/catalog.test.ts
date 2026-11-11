import { describe, expect, it } from "vitest";
import * as z from "zod";
import type { AllAuthTool } from "./catalog.js";
import { tools } from "./catalog.js";

const project = "sample-development";
const uuid = "72d7081b-2c03-4a8b-8821-98f29bc741aa";
const branding = {
	name: "Sample",
	supportEmail: null,
	logoUrl: null,
	logoDarkUrl: null,
	faviconUrl: null,
	primaryColor: "#315bff",
	darkPrimaryColor: "#7892ff",
	showPoweredBy: true,
};
const authPolicy = {
	emailAndPasswordEnabled: true,
	signUpEnabled: true,
	requireEmailVerification: true,
	sessionExpiresInSeconds: 604800,
	mfaMode: "optional",
	organizationCreation: "verified-users",
};
const securityPolicy = {
	mode: "enforce",
	maxFailuresPerIp: 20,
	failureWindowSeconds: 900,
	blockSeconds: 900,
	maxSignUpsPerIp: 10,
	signUpWindowSeconds: 3600,
	blockedEmailDomains: [],
	logRetentionDays: 90,
	newDeviceNotifications: true,
};

function getTool(name: string): AllAuthTool {
	const selected = tools.find((entry) => entry.name === `allauth_${name}`);
	if (!selected) throw new Error(`Missing tool: ${name}`);
	return selected;
}

/** Representative valid arguments cover every operation without making a network request. */
function example(entry: AllAuthTool): Record<string, unknown> {
	const seed: Record<string, unknown> = {
		project,
		projectId: uuid,
		workspaceId: uuid,
		invitationId: uuid,
		memberId: uuid,
		applicationId: uuid,
		domainId: uuid,
		id: uuid,
		userId: "user_1",
		organizationId: "organization_1",
		confirmOrganizationId: "organization_1",
		teamId: "team_1",
		sourceInstance: "ins_fixture",
		invitations: [
			{
				sourceInvitationId: "invite_fixture",
				organizationId: "organization_1",
				email: "person@example.com",
				role: "member",
				inviterId: "user_1",
				expiresAt: "2030-01-01T00:00:00.000Z",
			},
		],
		users: [
			{
				sourceUserId: "user_fixture",
				email: "person@example.com",
				emailVerified: true,
				name: "Sample",
			},
		],
		name: "Sample",
		slug: "sample",
		email: "person@example.com",
		role: entry.name.includes("organization_role_")
			? "auditor"
			: /^allauth_users?_/.test(entry.name)
				? "user"
				: "member",
		primaryOrigin: "https://sample.example.com",
		origins:
			entry.name === "allauth_project_origins_update"
				? ["https://sample.example.com"]
				: [],
		environment: "development",
		domain: "auth.sample.example.com",
		clientId: "client_1",
		redirectUris: ["https://sample.example.com/callback"],
		organizationIds: [],
		google: { enabled: false, clientId: "" },
		kind: entry.name === "allauth_branding_asset_upload" ? "logo" : "public",
		version:
			entry.name === "allauth_project_origins_update" ? "a".repeat(64) : 0,
		branding,
		policy:
			entry.name === "allauth_security_update" ? securityPolicy : authPolicy,
		permission: { member: ["create"] },
		ownerId: "user_1",
		publicMetadata: { plan: "free" },
		url: "https://hooks.example.com/allauth",
		eventTypes: ["user.created"],
		type:
			entry.name === "allauth_security_rule_add"
				? "email-domain"
				: "user.created",
		value: "blocked.example.com",
		reason: "Test policy",
		providerId: "provider_1",
		connectionId: "connection_1",
		credentialId: uuid,
		contentType: "image/png",
		data: "aGVsbG8=",
	};
	const input: Record<string, unknown> = {};
	for (const [key, schema] of Object.entries(entry.inputSchema.shape)) {
		if (key in seed) input[key] = seed[key];
		else if (!schema.safeParse(undefined).success)
			throw new Error(`Missing fixture field ${entry.name}.${key}`);
	}
	return input;
}

describe("AllAuth management tool catalog", () => {
	it("scopes sensitive Clerk imports to one native environment and defaults to dry run", () => {
		const tool = getTool("users_import_clerk");
		const user = {
			sourceUserId: "user_fixture",
			email: "person@example.com",
			emailVerified: true,
			name: "Sample",
		};
		expect(tool.sensitive).toBe(true);
		expect(tool.readOnly).toBe(false);
		expect(
			tool.buildRequest({
				project,
				sourceInstance: "ins_fixture",
				users: [user],
			}),
		).toMatchObject({
			method: "POST",
			path: `/api/projects/${project}/auth/project-admin/import-clerk-users`,
			body: { dryRun: true, sourceInstance: "ins_fixture", users: [user] },
		});
		expect(() =>
			tool.buildRequest({
				project,
				sourceInstance: "ins_fixture",
				users: Array(101).fill(user),
			}),
		).toThrow();
		expect(() =>
			tool.buildRequest({
				project,
				sourceInstance: "ins_fixture",
				users: [
					{ ...user, passwordHash: "plaintext", passwordHasher: "bcrypt" },
				],
			}),
		).toThrow();
	});
	it.each([
		"six123",
		"eight123",
	])("leaves the selected environment to enforce its password rules for managed creation: %s", (password) => {
		expect(
			getTool("user_create").buildRequest({
				project,
				name: "Sample",
				email: "person@example.com",
				password,
			}).body,
		).toEqual({
			name: "Sample",
			email: "person@example.com",
			password,
			role: "user",
		});
	});
	it("rejects managed passwords below every supported application's minimum", () => {
		expect(() =>
			getTool("user_create").buildRequest({
				project,
				name: "Sample",
				email: "person@example.com",
				password: "short",
			}),
		).toThrow();
	});
	it("preserves per-environment password rules in a configuration update", () => {
		const passwordPolicy = {
			minLength: 6,
			maxLength: 64,
			requireUppercase: true,
			requireLowercase: false,
			requireNumber: true,
			requireSymbol: false,
		};
		const policy = { ...authPolicy, passwordPolicy };
		expect(
			getTool("configuration_update").buildRequest({
				project,
				version: 0,
				policy,
			}).body,
		).toEqual({ version: 0, policy });
		for (const invalid of [
			{ ...passwordPolicy, minLength: 5 },
			{ ...passwordPolicy, maxLength: 129 },
			{ ...passwordPolicy, minLength: 80 },
			{ ...passwordPolicy, requireNumber: "true" },
		]) {
			expect(() =>
				getTool("configuration_update").buildRequest({
					project,
					version: 0,
					policy: { ...policy, passwordPolicy: invalid },
				}),
			).toThrow();
		}
	});
	it("preserves connected support registration when updating the complete authentication policy", () => {
		const policy = {
			...authPolicy,
			supportAccess: {
				enabled: true,
				callbackUrl: "https://app.example/api/allauth/support/callback",
			},
		};
		expect(
			getTool("configuration_update").buildRequest({
				project,
				version: 0,
				policy,
			}).body,
		).toEqual({ version: 0, policy });
	});
	/** @see ../../lib/auth-policy/policy.ts */
	it.each([
		"?",
		"#",
	])("rejects an empty support callback delimiter %s in a policy update", (suffix) => {
		const policy = {
			...authPolicy,
			supportAccess: {
				enabled: true,
				callbackUrl: `https://app.example/api/allauth/support/callback${suffix}`,
			},
		};
		expect(() =>
			getTool("configuration_update").buildRequest({
				project,
				version: 0,
				policy,
			}),
		).toThrow();
	});
	it("defines unique bounded tools with valid discoverable JSON schemas", () => {
		expect(tools.length).toBeGreaterThan(70);
		expect(new Set(tools.map((entry) => entry.name)).size).toBe(tools.length);
		for (const entry of tools) {
			expect(entry.name).toMatch(/^allauth_[a-z0-9_]+$/);
			expect(entry.name.length).toBeLessThanOrEqual(64);
			expect(z.toJSONSchema(entry.inputSchema, { io: "input" }).type).toBe(
				"object",
			);
		}
	});

	it("builds only allowlisted paths and never hides writes behind read-only metadata", () => {
		for (const entry of tools) {
			const request = entry.buildRequest(example(entry));
			expect(request.path).toMatch(
				/^\/api\/(?:health$|workspaces(?:\/|$)|workspace-invitations(?:\/|$)|admin\/|organizations\/|projects\/sample-development\/auth\/)/,
			);
			expect(request.path).not.toContain("?");
			expect(request.path).not.toContain("#");
			expect(entry.readOnly).toBe(request.method === "GET");
			if (entry.readOnly) expect(request.body).toBeUndefined();
			if (entry.destructive || entry.sensitive)
				expect(entry.readOnly).toBe(false);
		}
	});

	it("requires an explicit tenant environment for every tenant operation", () => {
		const rootTools = new Set(
			[
				"health",
				"workspaces_list",
				"workspace_get",
				"workspace_create",
				"workspace_update",
				"workspace_delete",
				"workspace_invite",
				"workspace_invitation_resend",
				"workspace_invitation_cancel",
				"workspace_member_role_update",
				"workspace_member_remove",
				"workspace_invitations_list",
				"workspace_invitation_accept",
				"projects_list",
				"project_create",
				"platform_oauth_clients_list",
				"platform_oauth_client_create",
				"platform_oauth_client_update",
				"platform_oauth_client_delete",
			].map((value) => `allauth_${value}`),
		);
		for (const entry of tools) {
			if (rootTools.has(entry.name)) continue;
			const input = example(entry);
			input.project = undefined;
			expect(() => entry.buildRequest(input), entry.name).toThrow();
			const request = entry.buildRequest(example(entry));
			expect(
				request.query?.project === project ||
					request.path.startsWith(`/api/projects/${project}/auth/`) ||
					request.path.startsWith(`/api/admin/projects/${project}/`),
				entry.name,
			).toBe(true);
		}
	});

	it("rejects raw transport overrides and invalid project identifiers before requests", () => {
		for (const entry of tools) {
			expect(() =>
				entry.buildRequest({
					...example(entry),
					path: "https://attacker.example",
					method: "DELETE",
					headers: { authorization: "secret" },
				}),
			).toThrow();
			if (!("project" in entry.inputSchema.shape)) continue;
			for (const invalid of [
				"platform",
				"../production",
				"https://attacker.example",
				"good?project=other",
				"",
				"valid/path",
			]) {
				expect(() =>
					entry.buildRequest({ ...example(entry), project: invalid }),
				).toThrow();
			}
		}
	});

	it("encodes path identifiers without interpolating query strings or fragments", () => {
		const request = getTool("user_get").buildRequest({
			project,
			userId: "user/a?project=production#fragment",
		});
		expect(request.path).toBe(
			"/api/admin/users/user%2Fa%3Fproject%3Dproduction%23fragment",
		);
		expect(request.query).toEqual({ project });
	});

	it("keeps native tenant authorization and console project selection separate", () => {
		expect(
			getTool("user_ban").buildRequest({
				project,
				userId: "user_1",
				banReason: "abuse",
			}),
		).toEqual({
			method: "POST",
			path: `/api/projects/${project}/auth/project-admin/ban-user`,
			body: { userId: "user_1", banReason: "abuse" },
		});
		expect(
			getTool("organization_member_add").buildRequest({
				project,
				organizationId: "org_1",
				userId: "user_1",
			}),
		).toEqual({
			method: "POST",
			path: "/api/admin/organizations/org_1/members",
			query: { project },
			body: { action: "add", userId: "user_1", role: "member" },
		});
		expect(getTool("events_list").buildRequest({ project }).query).toEqual({
			scope: "admin",
			limit: 25,
			offset: 0,
		});
	});

	it("preserves exact organization actions and explicit deletion confirmation", () => {
		for (const [name, action, fields] of [
			[
				"organization_member_role_update",
				"update",
				{ memberId: "m_1", role: "admin" },
			],
			["team_member_remove", "remove-member", { teamId: "t_1", userId: "u_1" }],
			[
				"organization_role_create",
				"create",
				{ role: "auditor", permission: { member: ["create"] } },
			],
			["organization_invitation_cancel", "cancel", { invitationId: "i_1" }],
		] as const) {
			expect(
				getTool(name).buildRequest({
					project,
					organizationId: "o_1",
					...fields,
				}).body,
			).toEqual({ action, ...fields });
		}
		expect(() =>
			getTool("organization_delete").buildRequest({
				project,
				organizationId: "a",
				confirmOrganizationId: "b",
			}),
		).toThrow("must match");
		expect(() =>
			getTool("organization_role_update").buildRequest({
				project,
				organizationId: "o",
				role: "owner",
				permission: {},
			}),
		).toThrow();
		expect(() =>
			getTool("organization_role_create").buildRequest({
				project,
				organizationId: "o",
				role: "test",
				permission: { admin: ["delete"] },
			}),
		).toThrow();
	});

	/** @see apps/auth/lib/console/organizations.ts (bounded organization collection APIs) */
	it.each([
		"members",
		"teams",
		"roles",
		"invitations",
	])("reaches later organization %s pages through a read-only scoped operation", (collection) => {
		const entry = getTool(`organization_${collection}_list`);
		expect(entry.readOnly).toBe(true);
		expect(entry.destructive).not.toBe(true);
		expect(entry.sensitive).not.toBe(true);
		expect(
			entry.buildRequest({
				project,
				organizationId: "org/encoded",
				search: " old ",
				limit: 50,
				offset: 1000,
			}),
		).toMatchObject({
			method: "GET",
			path: `/api/admin/organizations/org%2Fencoded/${collection}`,
			query: { project, search: "old", limit: 50, offset: 1000 },
		});
		for (const invalid of [
			{ limit: 101 },
			{ offset: -1 },
			{ search: "a".repeat(129) },
		])
			expect(() =>
				entry.buildRequest({ project, organizationId: "org", ...invalid }),
			).toThrow();
	});

	it("lists a team roster or nonmembers without silently dropping the team filter", () => {
		const entry = getTool("organization_members_list");
		expect(
			entry.buildRequest({
				project,
				organizationId: "org",
				teamId: "team",
				excludeTeam: true,
			}).query,
		).toEqual({
			project,
			search: "",
			limit: 25,
			offset: 0,
			teamId: "team",
			excludeTeam: true,
		});
		expect(() =>
			entry.buildRequest({ project, organizationId: "org", excludeTeam: true }),
		).toThrow("teamId");
		expect(() =>
			entry.buildRequest({
				project,
				organizationId: "org",
				teamId: "team",
				excludeTeam: "true",
			}),
		).toThrow();
	});

	it("finds new organization member candidates without a capped detail-summary filter", () => {
		expect(
			getTool("users_list").buildRequest({
				project,
				excludeOrganizationId: "org",
				status: "verified",
			}).query,
		).toMatchObject({
			project,
			excludeOrganizationId: "org",
			status: "verified",
		});
		expect(() =>
			getTool("users_list").buildRequest({
				project,
				excludeOrganizationId: "",
			}),
		).toThrow();
		expect(getTool("organization_get").description).toContain(
			"bounded summary",
		);
	});

	it("bounds pagination and preserves versioned policy bodies", () => {
		for (const limit of [0, 101, 2.5])
			expect(() =>
				getTool("users_list").buildRequest({ project, limit }),
			).toThrow();
		for (const offset of [-1, 100001])
			expect(() =>
				getTool("organizations_list").buildRequest({ project, offset }),
			).toThrow();
		expect(
			getTool("configuration_update").buildRequest({
				project,
				version: 8,
				policy: authPolicy,
			}),
		).toEqual({
			method: "PATCH",
			path: "/api/admin/configuration",
			query: { project },
			body: { version: 8, policy: authPolicy },
		});
		expect(() =>
			getTool("configuration_update").buildRequest({
				project,
				version: 8,
				policy: { ...authPolicy, mfaMode: "required" },
			}),
		).toThrow();
		expect(() =>
			getTool("branding_update").buildRequest({ project, branding }),
		).toThrow();
	});

	it("validates paired UTC analytics dates and audit intervals", () => {
		expect(() =>
			getTool("analytics_get").buildRequest({ project, from: "2026-10-01" }),
		).toThrow("together");
		expect(() =>
			getTool("analytics_get").buildRequest({
				project,
				from: "2026-02-30",
				to: "2026-03-02",
			}),
		).toThrow();
		expect(() =>
			getTool("logs_list").buildRequest({
				project,
				from: "2026-10-28T00:00:00Z",
				to: "2026-10-01T00:00:00Z",
			}),
		).toThrow("precede");
		expect(
			getTool("analytics_get").buildRequest({
				project,
				from: "2026-10-01",
				to: "2026-10-27",
			}).query,
		).toMatchObject({ from: "2026-10-01", to: "2026-10-27" });
	});

	it("marks every credential-returning operation for explicit sensitive-tool opt-in", () => {
		for (const name of [
			"project_create",
			"project_proxy_secret_rotate",
			"webhook_create",
			"webhook_secret_rotate",
			"platform_oauth_client_create",
			"scim_connection_create",
			"scim_credential_rotate",
		]) {
			expect(getTool(name).sensitive, name).toBe(true);
		}
		expect(
			tools.some((entry) =>
				/impersonat|password_reset|raw_request|execute_sql/.test(entry.name),
			),
		).toBe(false);
	});

	it("requires an explicit workspace and secure production origin when provisioning", () => {
		const input = {
			workspaceId: uuid,
			name: "Sample",
			slug: project,
			primaryOrigin: "https://app.example.com",
			environment: "production",
		};
		expect(getTool("project_create").buildRequest(input).body).toEqual({
			...input,
			origins: [],
		});
		expect(() =>
			getTool("project_create").buildRequest({
				...input,
				workspaceId: undefined,
			}),
		).toThrow();
		expect(() =>
			getTool("project_create").buildRequest({
				...input,
				primaryOrigin: "http://localhost:3000",
			}),
		).toThrow("HTTPS");
		expect(() =>
			getTool("project_create").buildRequest({
				...input,
				primaryOrigin: "http://app.example.com",
			}),
		).toThrow();
	});

	it("constructs bounded multipart branding uploads without arbitrary file reads", async () => {
		const input = {
			project,
			version: 1,
			kind: "logo",
			contentType: "image/png",
			data: "aGVsbG8=",
		};
		const request = getTool("branding_asset_upload").buildRequest(input);
		expect(request.body).toBeInstanceOf(FormData);
		const form = request.body as FormData;
		expect(form.get("kind")).toBe("logo");
		expect(form.get("version")).toBe("1");
		const file = form.get("file") as File;
		expect(file.name).toBe("asset.png");
		expect(file.type).toBe("image/png");
		expect(await file.text()).toBe("hello");
		expect(() =>
			getTool("branding_asset_upload").buildRequest({
				...input,
				data: "data:image/png;base64,aGVsbG8=",
			}),
		).toThrow();
		expect(() =>
			getTool("branding_asset_upload").buildRequest({
				...input,
				data: btoa("a".repeat(2097153)),
			}),
		).toThrow("2 MB");
		expect(() =>
			getTool("branding_asset_upload").buildRequest({
				...input,
				kind: "favicon",
				contentType: "image/jpeg",
			}),
		).toThrow("format");
	});
});
