import type { Pool, PoolClient } from "pg";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, setting, trustedOrigins } from "./configuration";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import { createPlatformIssuerSigner } from "./platform-issuer-signing";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import { createOwnedProjectIssuerAuthorization } from "./projects/owned-project-issuer-authorization";
import { createIssuerClientAuthenticator } from "./projects/owned-project-issuer-client";
import { issuerJSON } from "./projects/owned-project-issuer-http";
import { createOwnedProjectIssuerIntrospection } from "./projects/owned-project-issuer-introspection";
import { createOwnedProjectIssuerToken } from "./projects/owned-project-issuer-token";
import { createOwnedProjectIssuerUserInfo } from "./projects/owned-project-issuer-userinfo";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";
import { isNodeRuntime } from "./runtime";

const protocolRoutes = new Map([
	["/oauth2/authorize", { methods: ["GET", "POST"], max: 30 }],
	["/oauth2/continue", { methods: ["POST"], max: 100 }],
	["/oauth2/consent", { methods: ["POST"], max: 100 }],
	["/oauth2/token", { methods: ["POST"], max: 20 }],
	["/oauth2/introspect", { methods: ["POST"], max: 100 }],
	["/oauth2/revoke", { methods: ["POST"], max: 30 }],
	["/oauth2/userinfo", { methods: ["GET", "POST"], max: 60 }],
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
	const reader = request.body?.getReader();
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
	const { signingSecret, encryptionKeys } = readLegacyProjectKeyring(
		setting(env, "ALLAUTH_AUTH_SECRET"),
		setting(env, "BETTER_AUTH_SECRETS"),
	);
	const store = createPlatformIssuerStore(database);
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

	async function dispatch(request: Request): Promise<Response | undefined> {
		const url = new URL(request.url);
		if (url.origin !== issuer || !url.pathname.startsWith("/api/auth/")) return;
		const path = url.pathname.slice("/api/auth".length);
		const route = protocolRoutes.get(path);
		if (!route?.methods.includes(request.method)) return;
		const ip = request.headers.get(
			isNodeRuntime(env) ? "x-real-ip" : "cf-connecting-ip",
		);
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

	return { dispatch };
}
