import { describe, expect, it, vi } from "vitest";
import { APIError } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { createAuthOptions } from "../auth";
import { guardAvatarUserDeletion } from "../avatars/deletion";
const origin = "http://localhost:3000";
describe("owning-realm avatar pre-delete integration", () => {
	it("the actual user-delete endpoint cannot report deletion while the realm cleanup hook is pending", async () => {
		let pending = true;
		const beforeDelete = vi.fn(async () => {
			if (pending)
				throw new APIError("SERVICE_UNAVAILABLE", {
					message:
						"Profile photo erasure is pending. Retry account deletion shortly.",
				});
		});
		const options = createAuthOptions(
			undefined,
			{
				BETTER_AUTH_URL: origin,
				BETTER_AUTH_SECRET: "synthetic-test-secret-at-least-thirty-two",
				SCIM_CREDENTIAL_HASH_SECRET:
					"synthetic-scim-secret-at-least-thirty-two",
			},
			{
				name: "Fixture",
				slug: "avatar-fixture",
				basePath: "/api/auth",
				cookiePrefix: "fixture-avatar",
				primaryOrigin: origin,
				origins: [origin],
				broker: { clientId: "fixture", clientSecret: "fixture-secret" },
				management: { id: "fixture" },
				authorizeAdmin: async () => null,
				beforeDeleteUser: beforeDelete,
			},
		);
		const f = await getTestInstance({
			user: {
				deleteUser: {
					enabled: true,
					beforeDelete: options.user.deleteUser.beforeDelete,
				},
			},
		});
		guardAvatarUserDeletion(
			(await f.auth.$context).internalAdapter,
			beforeDelete,
		);
		const login = await f.auth.api.signInEmail({
			body: { email: f.testUser.email, password: f.testUser.password },
			asResponse: true,
		});
		const cookie = login.headers
			.getSetCookie()
			.map((value) => value.split(";")[0])
			.join("; ");
		const call = () =>
			f.auth.handler(
				new Request(`${origin}/api/auth/delete-user`, {
					method: "POST",
					headers: { origin, cookie, "content-type": "application/json" },
					body: JSON.stringify({ password: f.testUser.password }),
				}),
			);
		const denied = await call();
		expect(denied.status).toBe(503);
		expect(beforeDelete).toHaveBeenCalledTimes(1);
		const ctx = await f.auth.$context;
		expect(
			await ctx.internalAdapter.findUserByEmail(f.testUser.email),
		).not.toBeNull();
		pending = false;
		expect((await call()).status).toBe(200);
		expect(beforeDelete).toHaveBeenCalledTimes(3);
		expect(
			await ctx.internalAdapter.findUserByEmail(f.testUser.email),
		).toBeNull();
	});
	it("the internal user-deletion path used by project administrators invokes the same hook", async () => {
		const beforeDelete = vi.fn(async () => {
			throw new APIError("SERVICE_UNAVAILABLE", {
				message: "Profile photo erasure is pending.",
			});
		});
		const f = await getTestInstance({}),
			ctx = await f.auth.$context,
			found = await ctx.internalAdapter.findUserByEmail(f.testUser.email);
		if (!found) throw Error("Fixture user absent");
		guardAvatarUserDeletion(ctx.internalAdapter, beforeDelete);
		await expect(
			ctx.internalAdapter.deleteUser(found.user.id),
		).rejects.toMatchObject({ statusCode: 503 });
		expect(beforeDelete).toHaveBeenCalledWith(found.user.id);
		expect(
			await ctx.internalAdapter.findUserById(found.user.id),
		).not.toBeNull();
		expect(
			(
				await f.auth.api.signInEmail({
					body: { email: f.testUser.email, password: f.testUser.password },
					asResponse: true,
				})
			).status,
		).toBe(200);
	});
});
