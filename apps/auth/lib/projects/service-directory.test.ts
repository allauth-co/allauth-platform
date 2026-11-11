import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it } from "vitest";
import { serviceDirectory } from "./service-directory";
import { handleServiceDirectoryRequest } from "./service-directory-transport";

const serviceKey = `aabk_11111111-1111-4111-8111-111111111111_${"k".repeat(43)}`;
const origin = "https://allauth.example";
const basePath = "/api/projects/fixture-production/auth";
async function fixture() {
	let enabled = true;
	const state = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			logger: { disabled: true },
			user: {
				additionalFields: {
					twoFactorEnabled: {
						type: "boolean",
						defaultValue: false,
						input: false,
					},
					directoryDisabled: {
						type: "boolean",
						defaultValue: false,
						input: false,
					},
				},
			},
			plugins: [
				admin(),
				organization({ dynamicAccessControl: { enabled: true } }),
				serviceDirectory({
					project: "fixture-production",
					projectId: "project-a",
					environment: "production",
					authorize: async (headers) => {
						if (!enabled || headers.get("allauth-backend-key") !== serviceKey)
							throw new APIError("UNAUTHORIZED");
					},
				}),
			],
		},
		{ disableTestUser: true },
	);
	const context = await state.auth.$context;
	const user = await state.auth.api.signUpEmail({
		body: {
			email: "member@example.test",
			name: "Member",
			password: "test-password-private",
		},
	});
	const company = await context.adapter.create<{ id: string }>({
		model: "organization",
		data: { name: "Company", slug: "company", createdAt: new Date() },
	});
	await context.adapter.create({
		model: "member",
		data: {
			organizationId: company.id,
			userId: user.user.id,
			role: "owner",
			createdAt: new Date(),
		},
	});
	const request = (path: string, key = serviceKey) =>
		state.auth.handler(
			new Request(`${origin}${basePath}/service-directory/${path}`, {
				headers: { "allauth-backend-key": key },
			}),
		);
	return {
		...state,
		context,
		userId: user.user.id,
		organizationId: company.id,
		request,
		revoke: () => {
			enabled = false;
		},
	};
}

describe("scoped native service directory", () => {
	let state: Awaited<ReturnType<typeof fixture>>;
	beforeEach(async () => {
		state = await fixture();
	});
	it("serves actual native API reads behind verified-key admission without passing browser credentials", async () => {
		const response = await handleServiceDirectoryRequest(
			new Request(
				`${origin}${basePath}/service-directory/users?userId=${state.userId}`,
				{
					headers: {
						"allauth-backend-key": serviceKey,
						cookie: "untrusted=ignored",
					},
				},
			),
			{ id: "project-a", slug: "fixture-production" },
			{
				authorize: async (headers) => {
					if (headers.get("allauth-backend-key") !== serviceKey)
						throw new APIError("UNAUTHORIZED");
				},
				consume: async () => ({ allowed: true, retryAfter: 0 }),
				read: async (operation, headers, query) =>
					runWithAdapter(state.context.adapter, async () => {
						const endpoint: unknown = Reflect.get(state.auth.api, operation);
						if (typeof endpoint !== "function")
							throw new Error("Missing native read");
						return Reflect.apply(endpoint, state.auth.api, [
							{ headers, query, asResponse: true },
						]) as Promise<Response>;
					}),
			},
		);
		expect(response?.status).toBe(200);
		expect(await response?.json()).toMatchObject({
			projectId: "project-a",
			users: [{ id: state.userId }],
		});
		expect(response?.headers.getSetCookie()).toEqual([]);
	});
	it("requires independent scoped credentials and returns only public identity fields", async () => {
		expect((await state.request("users", "")).status).toBe(401);
		const response = await state.request(`users?userId=${state.userId}`);
		expect(response.status).toBe(200);
		expect(response.headers.get("cache-control")).toBe("no-store");
		const data = await response.json();
		expect(data).toMatchObject({
			project: "fixture-production",
			projectId: "project-a",
			environment: "production",
			total: 1,
			users: [{ id: state.userId, email: "member@example.test" }],
		});
		expect(JSON.stringify(data)).not.toMatch(
			/password|credential|privateMetadata|session|accountId/,
		);
		state.revoke();
		expect((await state.request("users")).status).toBe(401);
	});
	it("pages exact environment users and represents missing/deleted identities as empty", async () => {
		await state.auth.api.signUpEmail({
			body: {
				email: "second@example.test",
				name: "Second",
				password: "test-password-private",
			},
		});
		const first = (await (
			await state.request("users?limit=1&offset=0")
		).json()) as { users: { id: string }[] };
		const second = (await (
			await state.request("users?limit=1&offset=1")
		).json()) as { users: { id: string }[] };
		expect(first.users).toHaveLength(1);
		expect(second.users).toHaveLength(1);
		expect(first.users[0].id).not.toBe(second.users[0].id);
		expect(
			await (await state.request("users?userId=foreign-user")).json(),
		).toMatchObject({ users: [], total: 0 });
		expect((await state.request("users?limit=101")).status).toBe(400);
	});
	it("reads current org membership and role registry without manufacturing user authority", async () => {
		expect(
			await (
				await state.request(
					`organizations?organizationId=${state.organizationId}`,
				)
			).json(),
		).toMatchObject({
			organizations: [{ id: state.organizationId, name: "Company" }],
		});
		expect(
			await (
				await state.request(
					`members?organizationId=${state.organizationId}&userId=${state.userId}`,
				)
			).json(),
		).toMatchObject({
			members: [{ userId: state.userId, role: "owner" }],
			total: 1,
		});
		const roles = await (
			await state.request(
				`roles?organizationId=${state.organizationId}&limit=1&offset=1`,
			)
		).json();
		expect(roles).toMatchObject({
			roles: [{ builtIn: true }],
			total: 3,
			limit: 1,
			offset: 1,
		});
		await state.context.adapter.deleteMany({
			model: "member",
			where: [{ field: "userId", value: state.userId }],
		});
		expect(
			await (
				await state.request(`members?organizationId=${state.organizationId}`)
			).json(),
		).toMatchObject({ members: [], total: 0 });
		expect(
			(await state.request("members?organizationId=foreign-org")).status,
		).toBe(404);
		const mutation = await state.auth.handler(
			new Request(`${origin}${basePath}/service-directory/users`, {
				method: "POST",
				headers: {
					"allauth-backend-key": serviceKey,
					"content-type": "application/json",
				},
				body: JSON.stringify({ name: "Changed" }),
			}),
		);
		expect(mutation.status).toBeGreaterThanOrEqual(400);
	});
	it("pages one user's complete native memberships across organisations without an org-by-org scan", async () => {
		const second = await state.context.adapter.create<{ id: string }>({
			model: "organization",
			data: { name: "Second", slug: "second", createdAt: new Date() },
		});
		await state.context.adapter.create({
			model: "member",
			data: {
				organizationId: second.id,
				userId: state.userId,
				role: "member",
				createdAt: new Date(),
			},
		});
		const first = (await (
			await state.request(`members?userId=${state.userId}&limit=1`)
		).json()) as { members: { id: string }[] };
		const last = (await (
			await state.request(`members?userId=${state.userId}&limit=1&offset=1`)
		).json()) as { members: { id: string }[] };
		expect(first).toMatchObject({
			project: "fixture-production",
			projectId: "project-a",
			total: 2,
			limit: 1,
			offset: 0,
		});
		expect(first.members).toHaveLength(1);
		expect(last.members).toHaveLength(1);
		expect(first.members[0].id).not.toBe(last.members[0].id);
		expect((await state.request("members")).status).toBe(400);
		expect(
			await (await state.request("members?userId=foreign-user")).json(),
		).toMatchObject({ members: [], total: 0 });
	});
});
