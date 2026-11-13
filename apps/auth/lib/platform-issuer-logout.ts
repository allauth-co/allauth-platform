import { randomBytes } from "node:crypto";
import type { PoolClient } from "pg";
import type { AuthEnvironment } from "./configuration";
import { authOrigin, setting } from "./configuration";
import { readPlatformIssuerJwks } from "./platform-issuer-jwks";
import type { createPlatformIssuerSigner } from "./platform-issuer-signing";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { readLegacyProjectKeyring } from "./projects/legacy-project-keyring";
import type { ProjectBackchannelTarget } from "./projects/owned-project-backchannel-logout";
import {
	projectBackchannelTargetsSql,
	recordOwnedProjectEvent,
} from "./projects/owned-project-engine-store";
import {
	fetchPublicProjectHttps,
	publicProjectHttpsURL,
} from "./projects/owned-project-https";
import { ProjectOAuthError } from "./projects/owned-project-issuer-http";
import type { OwnedProjectIssuerLogoutOptions } from "./projects/owned-project-issuer-logout";
import { createOwnedProjectIssuerLogout } from "./projects/owned-project-issuer-logout";

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";
const lifetimeSeconds = 120;
const timeoutMs = 5000;

interface Options
	extends Pick<
		OwnedProjectIssuerLogoutOptions,
		"requireMfa" | "readBody" | "clearBrowserSession"
	> {
	store: ReturnType<typeof createPlatformIssuerStore>;
	signer: Pick<
		ReturnType<typeof createPlatformIssuerSigner>,
		"resolveSigningKey"
	>;
	env: AuthEnvironment;
	defer?(delivery: () => Promise<void>): void;
	post?(request: Request): Promise<Response>;
}

/** Revoke one admitted platform session and deliver its RP notifications after commit. */
export function createPlatformIssuerLogout(options: Options) {
	const { env, signer } = options;
	const issuer = authOrigin(env);
	const { signingSecret } = readLegacyProjectKeyring(
		setting(env, "ALLAUTH_AUTH_SECRET"),
		setting(env, "BETTER_AUTH_SECRETS"),
	);
	if (signingSecret.length < 32)
		throw new Error("A platform session signing key is required.");
	const sessionCookie = `${issuer.startsWith("https:") ? "__Secure-" : ""}better-auth.session_token`;
	const post =
		options.post ??
		((request: Request) =>
			fetchPublicProjectHttps(request, { timeoutMs, headersOnly: true }));
	const pending = new WeakMap<PoolClient, ProjectBackchannelTarget[]>();

	async function deliver(targets: readonly ProjectBackchannelTarget[]) {
		try {
			const signing = await signer.resolveSigningKey();
			const iat = Math.floor(Date.now() / 1000);
			const results = await Promise.allSettled(
				targets.map(async (target) => {
					const url = publicProjectHttpsURL(target.url, true);
					const token = await signing.sign(
						{
							iss: issuer,
							aud: target.clientId,
							sub: target.userId,
							sid: target.sessionId,
							iat,
							exp: iat + lifetimeSeconds,
							jti: randomBytes(16).toString("hex"),
							events: { [logoutEvent]: {} },
						},
						{ typ: "logout+jwt" },
					);
					const response = await post(
						new Request(url, {
							method: "POST",
							body: new URLSearchParams({ logout_token: token }),
							headers: { accept: "application/json" },
							redirect: "error",
							signal: AbortSignal.timeout(timeoutMs),
						}),
					);
					if (response.status !== 200 && response.status !== 204)
						throw new Error("The relying party did not accept logout.");
				}),
			);
			if (results.some(({ status }) => status === "rejected"))
				console.warn("Platform issuer back-channel logout delivery failed.");
		} catch {
			console.warn("Platform issuer back-channel logout delivery failed.");
		}
	}

	return createOwnedProjectIssuerLogout({
		issuer,
		endpointBase: `${issuer}/api/auth`,
		signingSecret,
		sessionCookie,
		requireMfa: options.requireMfa,
		readBody: options.readBody,
		clearBrowserSession: options.clearBrowserSession,
		keyring: {
			async existingPublicKeys(client) {
				return (await readPlatformIssuerJwks(client)).document;
			},
		},
		store: {
			async transaction(work) {
				const targets: ProjectBackchannelTarget[] = [];
				const result = await options.store.transaction(async (client) => {
					pending.set(client, targets);
					try {
						return await work(client);
					} finally {
						pending.delete(client);
					}
				});
				if (targets.length) {
					let delivery: Promise<void> | undefined;
					const run = () => (delivery ??= deliver(targets));
					if (!options.defer) await run();
					else {
						try {
							options.defer(run);
						} catch {
							await run();
						}
					}
				}
				return result;
			},
		},
		async revokeSession(client, _request, session, path, actorId) {
			const targets = pending.get(client);
			if (!targets)
				throw new Error("A platform logout transaction is required.");
			const { rowCount } = await client.query(
				'SELECT 1 FROM public."session" WHERE id=$1 AND "userId"=$2 AND token=$3 FOR UPDATE',
				[session.id, session.userId, session.token],
			);
			if (rowCount !== 1)
				throw new ProjectOAuthError(
					"server_error",
					"Unable to complete logout",
					503,
				);
			// The foreign keys detach grants when the session disappears.
			const { rows } = await client.query<ProjectBackchannelTarget>(
				projectBackchannelTargetsSql,
				[[session.id]],
			);
			await client.query(
				`UPDATE public."oauthAccessToken" SET revoked=statement_timestamp()
				 WHERE "sessionId"=$1 AND revoked IS NULL`,
				[session.id],
			);
			await client.query(
				`UPDATE public."oauthRefreshToken" SET revoked=statement_timestamp()
				 WHERE "sessionId"=$1 AND revoked IS NULL AND NOT (scopes ? 'offline_access')`,
				[session.id],
			);
			await client.query('DELETE FROM public."session" WHERE id=$1', [
				session.id,
			]);
			await recordOwnedProjectEvent(client, {
				type: "session.deleted",
				outcome: "success",
				actorId: actorId ?? undefined,
				userId: session.userId,
				targetId: session.id,
				metadata: { path },
			});
			targets.push(...rows);
		},
	});
}
