export const projectOpenApiPath = "/open-api/generate-schema";

type Schema = Record<string, unknown>;

const string = { type: "string" };
const boolean = { type: "boolean" };
const timestamp = { type: "string", format: "date-time" };
const nullableString = { type: ["string", "null"] };
const success = {
	type: "object",
	properties: { success: { const: true } },
	required: ["success"],
};
const session = { $ref: "#/components/schemas/Session" };
const user = { $ref: "#/components/schemas/User" };
const sessionCookie = { sessionCookie: [] };

function response(description: string, schema: Schema = { type: "object" }) {
	return { description, content: { "application/json": { schema } } };
}

function body(schema: Schema) {
	return { required: true, content: { "application/json": { schema } } };
}

function passwordSignIn(identifier: "email" | "username", maxLength: number) {
	const identity =
		identifier === "email"
			? { type: "string", format: "email", maxLength: 320 }
			: {
					type: "string",
					minLength: 3,
					maxLength: 30,
					pattern: "^[A-Za-z0-9_.]+$",
				};
	return {
		operationId: identifier === "email" ? "signInEmail" : "signInUsername",
		summary: `Sign in with ${identifier} and password`,
		security: [],
		requestBody: body({
			type: "object",
			additionalProperties: false,
			properties: {
				[identifier]: identity,
				password: {
					type: "string",
					format: "password",
					minLength: 1,
					maxLength,
					writeOnly: true,
				},
				callbackURL: { type: "string", maxLength: 2048 },
				rememberMe: boolean,
			},
			required: [identifier, "password"],
		}),
		responses: {
			200: response("Signed in or awaiting MFA", {
				oneOf: [
					{
						type: "object",
						properties: { user, redirect: boolean, url: string },
						required: ["user", "redirect"],
					},
					{
						type: "object",
						properties: {
							twoFactorRedirect: { const: true },
							twoFactorMethods: { type: "array", items: string },
						},
						required: ["twoFactorRedirect", "twoFactorMethods"],
					},
				],
			}),
			302: { description: "Continue the MFA challenge at the callback URL" },
			400: response("Invalid sign-in request"),
			401: response("Invalid credentials"),
			403: response("Sign-in forbidden by project policy"),
			429: response("Sign-in rate limit exceeded"),
		},
	};
}

/** The documented browser operations supported by this candidate configuration. */
export function ownedProjectOpenApi({
	serverURL,
	cookieName,
	passwordMaxLength,
}: {
	serverURL: string;
	cookieName: string;
	passwordMaxLength?: number;
}) {
	return {
		openapi: "3.1.1",
		info: {
			title: "AllAuth Project API",
			version: "1.0.0",
			description:
				"Browser endpoints documented for this AllAuth project engine. Other enabled features may be documented separately.",
		},
		servers: [{ url: serverURL }],
		components: {
			securitySchemes: {
				sessionCookie: { type: "apiKey", in: "cookie", name: cookieName },
			},
			schemas: {
				Session: {
					type: "object",
					properties: {
						id: string,
						userId: string,
						expiresAt: timestamp,
						createdAt: timestamp,
						updatedAt: timestamp,
						activeOrganizationId: nullableString,
						activeTeamId: nullableString,
					},
					required: ["id", "userId", "expiresAt", "createdAt", "updatedAt"],
				},
				User: {
					type: "object",
					properties: {
						id: string,
						name: string,
						email: { type: "string", format: "email" },
						emailVerified: boolean,
						image: nullableString,
						username: nullableString,
						displayUsername: nullableString,
						createdAt: timestamp,
						updatedAt: timestamp,
					},
					required: [
						"id",
						"name",
						"email",
						"emailVerified",
						"createdAt",
						"updatedAt",
					],
				},
			},
		},
		paths: {
			[projectOpenApiPath]: {
				get: {
					operationId: "getProjectOpenApi",
					summary:
						"Read the project API schema as a verified realm administrator",
					security: [sessionCookie],
					responses: {
						200: response("OpenAPI document"),
						403: response("Project administrator session required"),
					},
				},
			},
			"/get-session": {
				get: {
					operationId: "getSession",
					summary: "Read or refresh the browser session",
					security: [sessionCookie, {}],
					parameters: [
						{ name: "disableRefresh", in: "query", schema: boolean },
					],
					responses: {
						200: response("Current session or null", {
							oneOf: [
								{
									type: "object",
									properties: { session, user },
									required: ["session", "user"],
								},
								{ type: "null" },
							],
						}),
						403: response("Untrusted browser request"),
					},
				},
			},
			"/sign-out": {
				post: {
					operationId: "signOut",
					summary: "End the browser session",
					security: [sessionCookie, {}],
					responses: {
						200: response("Signed out", success),
						403: response("Untrusted browser request"),
					},
				},
			},
			"/account/sessions": {
				get: {
					operationId: "listAccountSessions",
					summary: "List sessions for the verified current account",
					security: [sessionCookie],
					responses: {
						200: response("Account sessions", {
							type: "object",
							properties: {
								sessions: {
									type: "array",
									items: {
										type: "object",
										properties: {
											id: string,
											createdAt: timestamp,
											expiresAt: timestamp,
											ipAddress: nullableString,
											userAgent: nullableString,
										},
										required: ["id", "createdAt", "expiresAt"],
									},
								},
								currentSessionId: string,
							},
							required: ["sessions", "currentSessionId"],
						}),
						401: response("Authentication required"),
						403: response("Verified browser session required"),
					},
				},
			},
			"/account/sessions/revoke": {
				post: {
					operationId: "revokeAccountSession",
					summary: "Revoke a session belonging to the verified current account",
					security: [sessionCookie],
					requestBody: body({
						type: "object",
						additionalProperties: false,
						properties: {
							id: { type: "string", minLength: 1, maxLength: 160 },
						},
						required: ["id"],
					}),
					responses: {
						200: response("Session revoked", success),
						400: response("Invalid session ID"),
						401: response("Authentication required"),
						403: response("Verified browser session required"),
						404: response("Session does not exist"),
					},
				},
			},
			"/organization/list": {
				get: {
					operationId: "listOrganizations",
					summary: "List organizations for the current account",
					security: [sessionCookie],
					responses: {
						200: response("Organizations", {
							type: "array",
							items: { type: "object" },
						}),
						401: response("Authentication required"),
						403: response("Organization access forbidden"),
					},
				},
			},
			...(passwordMaxLength === undefined
				? {}
				: {
						"/sign-in/email": {
							post: passwordSignIn("email", passwordMaxLength),
						},
						"/sign-in/username": {
							post: passwordSignIn("username", passwordMaxLength),
						},
					}),
		},
	};
}
