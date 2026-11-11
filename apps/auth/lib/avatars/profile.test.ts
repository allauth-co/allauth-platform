import { describe, expect, it } from "vitest";
import { guardOwnedAvatarProfileImage } from "./profile";
import { getTestInstance } from "better-auth/test";
import { createAuthOptions } from "../auth";
const origin = "http://localhost:3000",
	url =
		"https://assets.allauth.co/avatars/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002/00000000-0000-4000-8000-000000000003/00000000-0000-4000-8000-000000000004.png";
const aliases = [
	url + "#avatar",
	url + "?alias=1",
	url.replace("https:", "HTTPS:"),
	url.replace("https:", ""),
	" \t" + url + " \n",
	url.replace("/avatars/", "/unused/../avatars/"),
	url.replace("/avatars/", "/unused/%2e%2e/avatars/"),
	url.replaceAll("/", "\\"),
];
describe("owning avatar URL normalization boundary", () => {
	it("rejects every initial owned image and canonicalizes browser aliases before recognizing reserved paths", () => {
		for (const value of [url, ...aliases])
			expect(() =>
				guardOwnedAvatarProfileImage(value, "create", origin),
			).toThrow("original profile photo");
		for (const value of aliases)
			expect(() =>
				guardOwnedAvatarProfileImage(value, "update", origin),
			).toThrow("original profile photo");
		expect(() =>
			guardOwnedAvatarProfileImage(url, "update", origin),
		).not.toThrow();
	});
	it("preserves ordinary external, legacy branding, removal and omitted image fields", () => {
		for (const value of [
			null,
			undefined,
			"https://cdn.fixture.example/person.png",
			"https://assets.allauth.co/branding/legacy.png",
		])
			for (const operation of ["create", "update"] as const)
				expect(() =>
					guardOwnedAvatarProfileImage(value, operation, origin),
				).not.toThrow();
	});
	it("the actual signup route cannot create a user with a foreign owned-avatar alias", async () => {
		const options = createAuthOptions(
			undefined,
			{
				BETTER_AUTH_URL: origin,
				SCIM_CREDENTIAL_HASH_SECRET:
					"synthetic-scim-secret-at-least-thirty-two",
			},
			{
				name: "Fixture",
				basePath: "/api/auth",
				cookiePrefix: "fixture",
				primaryOrigin: origin,
				origins: [origin],
				broker: { clientId: "fixture", clientSecret: "fixture" },
				management: { id: "fixture" },
				authorizeAdmin: async () => null,
			},
		);
		const f = await getTestInstance({
			databaseHooks: { user: options.databaseHooks.user },
		});
		for (const image of [url, ...aliases]) {
			const response = await f.auth.api.signUpEmail({
				body: {
					name: "Fictional",
					email: "alias@fixture.example",
					password: "fixture-password-long-enough",
					image,
				},
				asResponse: true,
			});
			expect(response.status).toBe(400);
		}
		const context = await f.auth.$context;
		expect(
			await context.internalAdapter.findUserByEmail("alias@fixture.example"),
		).toBeNull();
		expect(
			(
				await f.auth.api.signUpEmail({
					body: {
						name: "Fictional",
						email: "allowed@fixture.example",
						password: "fixture-password-long-enough",
						image: "https://cdn.fixture.example/person.png",
					},
					asResponse: true,
				})
			).status,
		).toBe(200);
	});
});
