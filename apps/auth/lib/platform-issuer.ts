import type { Pool, PoolClient } from "pg";
import { authPolicyRepository } from "./auth-policy/storage";
import type { AuthEnvironment } from "./configuration";
import {
	authOrigin,
	projectEmailEnvironment,
	setting,
	trustedOrigins,
} from "./configuration";
import { authenticationEmail } from "./email/authentication";
import { emailConfigured, sendAuthEmail } from "./email/send";
import {
	platformIssuerDevicePath,
	routePlatformIssuerDevice,
} from "./platform-issuer-device-routing";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { createPlatformIssuerLogout } from "./platform-issuer-logout";
import { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import { createPlatformIssuerSigner } from "./platform-issuer-signing";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { createPlatformMcpDeviceToken } from "./platform-mcp-device-token";
import { createPlatformMfaEnrollment } from "./platform-mfa-enrollment";
import { createPlatformPasswordSignIn } from "./platform-password-sign-in";
import { createPlatformPendingMfa } from "./platform-pending-mfa";
import { createPlatformSessionIssuer } from "./platform-session-issuance";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import { createOwnedPendingMfa } from "./projects/owned-mfa";
import { createOwnedProjectIssuerAuthorization } from "./projects/owned-project-issuer-authorization";
import { createIssuerClientAuthenticator } from "./projects/owned-project-issuer-client";
import { createOwnedProjectConsentManagement } from "./projects/owned-project-issuer-consent-management";
import { createOwnedProjectIssuerDevice } from "./projects/owned-project-issuer-device";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { createOwnedProjectIssuerIntrospection } from "./projects/owned-project-issuer-introspection";
import { createOwnedProjectIssuerToken } from "./projects/owned-project-issuer-token";
import { createOwnedProjectIssuerUserInfo } from "./projects/owned-project-issuer-userinfo";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import { timedProjectProtocolStream } from "./projects/project-protocol-body";
import { isNodeRuntime } from "./runtime";

const protocolRoutes = new Map([
	["/oauth2/authorize", { methods: ["GET", "POST"], max: 30 }],
	["/oauth2/continue", { methods: ["POST"], max: 100 }],
	["/oauth2/consent", { methods: ["POST"], max: 100 }],
	["/oauth2/get-consent", { methods: ["GET"], max: 100 }],
	["/oauth2/get-consents", { methods: ["GET"], max: 100 }],
	["/oauth2/update-consent", { methods: ["POST"], max: 100 }],
	["/oauth2/delete-consent", { methods: ["POST"], max: 100 }],
	["/oauth2/token", { methods: ["POST"], max: 20 }],
	["/oauth2/introspect", { methods: ["POST"], max: 100 }],
	["/oauth2/revoke", { methods: ["POST"], max: 30 }],
	["/oauth2/userinfo", { methods: ["GET", "POST"], max: 60 }],
	["/oauth2/end-session", { methods: ["GET", "POST"], max: 100 }],
	["/oauth2/end-session/confirm", { methods: ["POST"], max: 100 }],
	["/jwks", { methods: ["GET"], max: 100 }],
]);

async function readBrowserBody(request: Request): Promise<unknown> {
	if (
		request.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== "application/json"
	)
		return;
	const reader =
		request.body && timedProjectProtocolStream(request.body).stream.getReader();
	if (!reader) return;
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let size = 0;
	let body = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) return JSON.parse(body + decoder.decode());
			size += value.byteLength;
			if (size > 24 * 1024) {
				void reader.cancel().catch(() => {});
				return;
			}
			body += decoder.decode(value, { stream: true });
		}
	} catch {
		return;
	} finally {
		reader.releaseLock();
	}
}

/** Assemble shared OAuth handlers against the installed platform tables and keys. */
export function createPlatformIssuer(database: Pool, env: AuthEnvironment) {
	const issuer = authOrigin(env);
	const endpointBase = `${issuer}/api/auth`;
	const secure = issuer.startsWith("https:");
	const cookiePrefix = `${secure ? "__Secure-" : ""}better-auth.`;
	const { signingSecret, encryptionKeys } = readLegacyProjectKeyring(
		setting(env, "ALLAUTH_AUTH_SECRET"),
		setting(env, "BETTER_AUTH_SECRETS"),
	);
	const store = createPlatformIssuerStore(database);
	const policy = authPolicyRepository(database);
	const readSession = createPlatformIssuerSessionReader(env);
	const signer = createPlatformIssuerSigner({ database, env });
	const keyring = {
		async existingPublicKeys(client: PoolClient) {
			return (await readPlatformIssuerJwks(client)).document;
		},
	};
	const authenticateClient = createIssuerClientAuthenticator(
		issuer,
		new Set(trustedOrigins(env)),
	);
	const consentManagement = createOwnedProjectConsentManagement({
		store,
		readBody: readBrowserBody,
		async authorize(client, request, write) {
			if (
				request.headers.has("authorization") ||
				(write && request.headers.get("origin") !== issuer)
			)
				return null;
			const session = await readSession(request.headers, client);
			return !session ||
				session.user.banned ||
				session.user.directoryDisabled ||
				session.session.impersonatedBy
				? null
				: session.user.id;
		},
	});
	const authorization = createOwnedProjectIssuerAuthorization({
		database,
		schemaName: store.schemaName,
		store,
		issuer,
		endpointBase,
		loginPage: "/oauth/login",
		allowImpersonatedSession: true,
		signingSecret,
		readBody: readBrowserBody,
		async readSession(request, client) {
			const session = await readSession(request.headers, client);
			return session?.user.banned || session?.user.directoryDisabled
				? null
				: session;
		},
		async readAuthenticatedSession(client, identity) {
			const session = await readSession.readAuthenticated(client, identity);
			return session?.user.banned || session?.user.directoryDisabled
				? null
				: session;
		},
	});
	const token = createOwnedProjectIssuerToken({
		database,
		schemaName: store.schemaName,
		keys: encryptionKeys,
		store,
		issuer,
		endpointBase,
		authenticateClient,
		keyring: {
			signingKey: (client, pin) =>
				signer.resolveSigningKey(
					{ signingKeyId: pin?.kid, signingAlgorithm: pin?.alg },
					client,
				),
		},
	});
	const { activeAccess, introspect, revoke } =
		createOwnedProjectIssuerIntrospection({
			store,
			keyring,
			issuer,
			endpointBase,
			authenticateClient,
		});
	const userinfo = createOwnedProjectIssuerUserInfo({
		store,
		issuer,
		endpointBase,
		activeAccess,
	});
	const trustedIP = (request: Request) =>
		request.headers.get(isNodeRuntime(env) ? "x-real-ip" : "cf-connecting-ip");
	const sessions = createPlatformSessionIssuer({
		issuer,
		signingSecret,
		trustedIP,
	});
	const readPolicy = async () => (await policy.read("platform")).policy;
	const email = projectEmailEnvironment(env);
	const securitySecret = setting(env, "ALLAUTH_AUTH_SECRET");
	const notifyNewDevice = emailConfigured(email)
		? async (user: { name: string; email: string }, request: Request) => {
				const ip = trustedIP(request);
				await sendAuthEmail(email, {
					to: user.email,
					subject: "New sign-in to AllAuth",
					fromName: "AllAuth",
					react: authenticationEmail({
						title: "New device signed in",
						description: `Hello ${user.name}, a new device signed in to AllAuth.${ip ? ` IP address: ${ip}.` : ""} If this was unexpected, review your sessions and change your password.`,
						url: `${issuer}/account`,
						actionLabel: "Review account security",
					}),
				});
			}
		: undefined;
	const credentialOptions = {
		issuer,
		signingSecret,
		securitySecret,
		store,
		sessions,
		readPolicy,
		readBody: readBrowserBody,
		trustedIP,
		requireTrustedIP: isNodeRuntime(env),
		trustedOrigins: trustedOrigins(env),
		notifyNewDevice,
		continueAuthenticated: authorization.continueAuthenticated,
	};
	const manageMfa = createPlatformMfaEnrollment({
		...credentialOptions,
		keys: encryptionKeys,
		readSession,
	});
	const verifyPendingMfa = createPlatformPendingMfa({
		...credentialOptions,
		keys: encryptionKeys,
		readSession,
	});
	const signInWithPassword = createPlatformPasswordSignIn({
		...credentialOptions,
		database,
		deviceCookies:
			securitySecret === signingSecret
				? sessions
				: createPlatformSessionIssuer({
						issuer,
						signingSecret: securitySecret,
						trustedIP,
					}),
		mfa: createOwnedPendingMfa({
			schema: store.schemaName,
			cookiePrefix: "better-auth",
			transaction: store.transaction,
			signingSecret,
			secureCookies: secure,
			keys: encryptionKeys,
		}),
	});
	const deviceOptions = {
		database,
		schemaName: store.schemaName,
		store,
		issuer,
		endpointBase,
		platformOrigin: issuer,
		trustedOrigins: trustedOrigins(env),
		trustedIP,
		authenticateClient,
		readBody: readBrowserBody,
		readSession: (request: Request, client: PoolClient) =>
			readSession(request.headers, client),
	};
	const device = createOwnedProjectIssuerDevice(deviceOptions);
	const mcpDevice = createOwnedProjectIssuerDevice({
		...deviceOptions,
		standalonePlatformMcp: true,
		trustedOrigins: [],
		requireBrowserMfa: async () =>
			(await policy.read("platform")).policy.mfaMode === "required",
	});
	const mcpDeviceToken = createPlatformMcpDeviceToken({
		issuer,
		store,
		trustedIP,
		policy: readPolicy,
		sessions,
	});
	async function dispatchDevice(request: Request) {
		const selected = await routePlatformIssuerDevice(database, request);
		if (!selected) return;
		if (selected.kind === "response") return selected;
		const standalonePath = platformIssuerDevicePath(selected.request);
		const response =
			selected.kind === "oauth"
				? await device(selected.path, selected.request, selected.prepared)
				: standalonePath
					? await mcpDevice(standalonePath, selected.request, selected.prepared)
					: await mcpDeviceToken(selected.request);
		if (!response)
			throw new Error("The shared OAuth device route is unavailable.");
		return { kind: "response" as const, response };
	}

	async function logout(
		path: "/oauth2/end-session" | "/oauth2/end-session/confirm",
		request: Request,
	) {
		const { policy: current } = await policy.read("platform");
		return createPlatformIssuerLogout({
			store,
			signer,
			env,
			requireMfa: current.mfaMode === "required",
			readBody: readBrowserBody,
			clearBrowserSession(headers, incoming) {
				const names = new Set(
					["session_token", "session_data", "dont_remember"].map(
						(name) => cookiePrefix + name,
					),
				);
				for (const pair of (incoming.headers.get("cookie") ?? "").split(";")) {
					const name = pair.split("=", 1)[0]?.trim();
					if (
						name?.startsWith(`${cookiePrefix}session_data.`) &&
						/^\d+$/.test(name.slice(`${cookiePrefix}session_data.`.length))
					)
						names.add(name);
				}
				for (const name of names)
					headers.append(
						"set-cookie",
						`${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`,
					);
			},
		})(path, request);
	}

	async function dispatch(request: Request): Promise<Response | undefined> {
		const url = new URL(request.url);
		if (url.origin !== issuer || !url.pathname.startsWith("/api/auth/")) return;
		const path = url.pathname.slice("/api/auth".length);
		const primary = await signInWithPassword(request);
		if (primary) return primary;
		const mfa = (await manageMfa(request)) ?? (await verifyPendingMfa(request));
		if (mfa) return mfa;
		const route = protocolRoutes.get(path);
		if (!route?.methods.includes(request.method)) return;
		if (path.startsWith("/oauth2/") && request.headers.has("cookie")) {
			const { policy: configured } = await policy.read("platform");
			if (configured.mfaMode === "required") {
				const session = await readSession(request.headers, database);
				if (
					session &&
					!session.session.impersonatedBy &&
					(!session.user.emailVerified || !session.user.twoFactorEnabled)
				)
					return issuerJSON(
						{
							message:
								"This application requires an already verified account enrolled in MFA.",
						},
						403,
					);
			}
		}
		const ip = trustedIP(request);
		const denied = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, ip, path, {
				max: route.max,
				windowMs: 60_000,
			}),
		);
		if (denied) return denied;
		switch (path) {
			case "/oauth2/token":
				return token(request);
			case "/oauth2/introspect":
				return introspect(request);
			case "/oauth2/revoke":
				return revoke(request);
			case "/oauth2/userinfo":
				return userinfo(request);
			case "/oauth2/end-session":
			case "/oauth2/end-session/confirm":
				return logout(path, request);
			case "/oauth2/get-consent":
			case "/oauth2/get-consents":
			case "/oauth2/update-consent":
			case "/oauth2/delete-consent":
				return consentManagement(path, request);
			case "/jwks": {
				let keys = await readPlatformIssuerJwks(database);
				if (keys.keyStoreEmpty) {
					await signer.resolveSigningKey();
					keys = await readPlatformIssuerJwks(database);
				}
				return issuerJSON(keys.document);
			}
			default:
				return authorization(path, request);
		}
	}

	return {
		dispatch,
		dispatchDevice,
		continueAuthenticated: authorization.continueAuthenticated,
	};
}
