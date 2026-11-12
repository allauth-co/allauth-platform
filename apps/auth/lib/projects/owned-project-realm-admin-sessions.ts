import type { PoolClient } from "pg";
import * as z from "zod";
import {
	accountLinkError,
	accountLinkHeaders,
	accountLinkJson,
} from "./owned-project-account-links";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import {
	realmAdministratorRequestGuard,
	recordOwnedRealmAdminEvent,
} from "./owned-project-realm-admin-audit";

const singlePath = "/admin/revoke-user-session";
const bulkPath = "/admin/revoke-user-sessions";
const inputs = {
	[singlePath]: z.object({ sessionToken: z.string() }),
	[bulkPath]: z.object({ userId: z.coerce.string() }),
};
const deniedCode = "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS";

type RevocationPath = keyof typeof inputs;
type RevocationSelector = { tokens: string[] } | { userId: string };
type Store = ReturnType<typeof createProjectEngineStore>;
type RealmSession = NonNullable<Awaited<ReturnType<Store["session"]>>>;

/** Accept only a verified browser administrator from the selected project realm. */
export function createOwnedProjectRealmAdminSessions(options: {
	store: Store;
	readBody(request: Request): Promise<unknown>;
	checkOrigin(request: Request): Response | null;
	readCookie(headers: Headers): string | null;
	clearCookies(headers: Headers): void;
	readSession(token: string, client: PoolClient): ReturnType<Store["session"]>;
	renew(
		request: Request,
		current: RealmSession & { token: string },
		client: PoolClient,
		headers: Headers,
	): Promise<void>;
	trustedIP(request: Request): string | null;
	requireMfa: boolean;
	revoke(
		client: PoolClient,
		request: Request,
		selector: RevocationSelector,
		path: RevocationPath,
		actorId: string,
	): Promise<void>;
}) {
	const { store } = options;
	return async (path: string, request: Request) => {
		if (request.method !== "POST" || (path !== singlePath && path !== bulkPath))
			return undefined;
		const originFailure = options.checkOrigin(request);
		if (originFailure) return originFailure;
		const body = await options.readBody(request);
		const input = inputs[path].safeParse(body);
		if (!input.success)
			return accountLinkError(
				400,
				"VALIDATION_ERROR",
				input.error.issues
					.map(
						({ path, message }) =>
							`[body${path.length ? `.${path.join(".")}` : ""}] ${message}`,
					)
					.join("; "),
			);
		const selector =
			"userId" in input.data
				? { userId: input.data.userId }
				: { tokens: [input.data.sessionToken] };
		// The native route coerces the selector, but its after-hook audits the raw ID.
		const targetId =
			path === bulkPath &&
			typeof body === "object" &&
			body !== null &&
			"userId" in body &&
			typeof body.userId === "string"
				? body.userId
				: undefined;
		const token = options.readCookie(request.headers);
		const ipAddress = options.trustedIP(request) ?? undefined;
		return store.transaction(async (client) => {
			if (ipAddress) {
				const limited = await admitOwnedProjectNativeRoute(
					client,
					ipAddress,
					path,
					{
						max: 100,
						windowMs: 60_000,
					},
				);
				if (limited) return limited;
			}
			const current = token ? await options.readSession(token, client) : null;
			const guarded = current && realmAdministratorRequestGuard(current);
			if (guarded) return guarded;
			if (request.headers.has("authorization"))
				return accountLinkJson(
					{ message: "Use your signed-in browser session for this action." },
					403,
				);
			const requireEnrollment = () =>
				accountLinkJson(
					{
						message:
							"This application requires an already verified account enrolled in MFA.",
					},
					403,
				);
			if (options.requireMfa && current && !current.user.twoFactorEnabled)
				return requireEnrollment();
			const headers = accountLinkHeaders();
			const actorId = current?.user.id;
			const record = (errorCode?: string) =>
				recordOwnedRealmAdminEvent(store, client, path, {
					actorId,
					userId: targetId || actorId,
					targetId,
					ipAddress,
					userAgent: request.headers.get("user-agent") ?? undefined,
					errorCode,
				});
			if (!current || !token) {
				if (token) options.clearCookies(headers);
				await record("AUTHENTICATION_FAILED");
				return new Response(null, { status: 401, headers });
			}
			const denied = async () => {
				await record(deniedCode);
				return accountLinkJson(
					{
						code: deniedCode,
						message: "You are not allowed to revoke users sessions",
					},
					403,
					headers,
				);
			};
			if (!current.user.role?.split(",").includes("admin")) return denied();
			const targetUserId =
				"userId" in selector
					? selector.userId
					: (
							await client.query<{ userId: string }>(
								'SELECT "userId" FROM "session" WHERE token=$1',
								[selector.tokens[0]],
							)
						).rows[0]?.userId;
			// Acquire actor and target in a stable order before locking sessions/grants.
			const users = new Set([current.user.id]);
			if (targetUserId) users.add(targetUserId);
			let administrator = null;
			for (const userId of [...users].sort()) {
				const user = await store.lockUser(client, userId);
				if (userId === current.user.id) administrator = user;
			}
			if (
				!administrator ||
				administrator.banned ||
				administrator.directoryDisabled ||
				!(await store.lockSession(client, token, administrator.id, false))
			)
				return denied();
			const lockedGuard = realmAdministratorRequestGuard({
				...current,
				user: administrator,
			});
			if (lockedGuard) return lockedGuard;
			if (options.requireMfa && !administrator.twoFactorEnabled)
				return requireEnrollment();
			if (!administrator.role?.split(",").includes("admin")) return denied();
			await options.renew(request, { ...current, token }, client, headers);
			await options.revoke(client, request, selector, path, administrator.id);
			await record();
			return accountLinkJson({ success: true }, 200, headers);
		});
	};
}
