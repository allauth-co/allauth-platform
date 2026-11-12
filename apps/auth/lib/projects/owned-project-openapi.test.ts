import { expect, it } from "vitest";
import {
	ownedProjectOpenApi,
	projectOpenApiPath,
} from "./owned-project-openapi";

it("describes only documented browser operations supported by the project candidate", () => {
	const input = {
		serverURL: "https://fixture-api.example/api/auth",
		cookieName: "__Secure-allauth_project_fixture.session_token",
	};
	const schema = ownedProjectOpenApi(input);
	expect(schema).toMatchObject({
		openapi: "3.1.1",
		servers: [{ url: input.serverURL }],
		components: {
			securitySchemes: {
				sessionCookie: { type: "apiKey", in: "cookie", name: input.cookieName },
			},
		},
		paths: {
			[projectOpenApiPath]: { get: { security: [{ sessionCookie: [] }] } },
		},
	});
	expect(Object.keys(schema.paths).sort()).toEqual([
		"/account/sessions",
		"/account/sessions/revoke",
		"/get-session",
		"/open-api/generate-schema",
		"/organization/list",
		"/sign-out",
	]);
	expect(schema.paths["/get-session"]).not.toHaveProperty("post");
	const password = ownedProjectOpenApi({ ...input, passwordMaxLength: 128 });
	expect(password.paths["/sign-in/email"]?.post).toMatchObject({
		security: [],
		requestBody: {
			content: {
				"application/json": {
					schema: {
						properties: { password: { maxLength: 128, writeOnly: true } },
					},
				},
			},
		},
	});
	expect(password.paths).toHaveProperty(["/sign-in/username", "post"]);
	expect(Object.keys(password.paths)).toHaveLength(
		Object.keys(schema.paths).length + 2,
	);
	const json = JSON.stringify(password);
	for (const internal of [
		"privateMetadata",
		"refreshToken",
		"clientSecret",
		"accessToken",
		"schemaName",
	])
		expect(json).not.toContain(internal);
});
