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
import { readRealmAdminUser } from "./owned-project-realm-admin-directory";

const singlePath = "/admin/revoke-user-session";
const bulkPath = "/admin/revoke-user-sessions";
const rolePath = "/admin/set-role";
const banPath = "/admin/ban-user";
const unbanPath = "/admin/unban-user";
const userId = z.coerce.string();
const inputs = {
	[singlePath]: z
		.object({ sessionToken: z.string() })
		.transform((data) => ({ ...data, path: singlePath }) as const),
	[bulkPath]: z
		.object({ userId })
		.transform((data) => ({ ...data, path: bulkPath }) as const),
	[rolePath]: z
		.object({ userId, role: z.union([z.string(), z.array(z.string())]) })
		.transform((data) => ({ ...data, path: rolePath }) as const),
	[banPath]: z
		.object({
			userId,
			banReason: z.string().optional(),
			banExpiresIn: z.number().optional(),
		})
		.transform((data) => ({ ...data, path: banPath }) as const),
	[unbanPath]: z
		.object({ userId })
		.transform((data) => ({ ...data, path: unbanPath }) as const),
};
const revokeDenied = [
	"YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
	"You are not allowed to revoke users sessions",
] as const;
const banDenied = [
	"YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
	"You are not allowed to ban users",
] as const;
const permissionDenied = {
	[singlePath]: revokeDenied,
	[bulkPath]: revokeDenied,
	[rolePath]: [
		"YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
		"You are not allowed to change users role",
	],
	[banPath]: banDenied,
	[unbanPath]: banDenied,
};

type MutationPath = keyof typeof inputs;
type RevocationSelector = { tokens: string[] } | { userId: string };
type Store = ReturnType<typeof createProjectEngineStore>;
type RealmSession = NonNullable<Awaited<ReturnType<Store["session"]>>>;

/** Accept only a verified browser administrator from the selected project realm. */
export function createOwnedProjectRealmAdminMutations(options: {
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
		path: MutationPath,
		actorId: string,
	): Promise<void>;
}) {
	const { store } = options;
	return async (route: string, request: Request) => {
		if (request.method !== "POST" || !Object.hasOwn(inputs, route))
			return undefined;
		const path = route as MutationPath;
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
		const mutation = input.data;
		// The native endpoint coerces the selector, but its after-hook audits the raw ID.
		const targetId =
			path !== singlePath &&
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
				const [deniedCode, message] = permissionDenied[path];
				await record(deniedCode);
				return accountLinkJson({ code: deniedCode, message }, 403, headers);
			};
			if (!current.user.role?.split(",").includes("admin")) return denied();
			const targetUserId =
				"userId" in mutation
					? mutation.userId
					: (
							await client.query<{ userId: string }>(
								'SELECT "userId" FROM "session" WHERE token=$1',
								[mutation.sessionToken],
							)
						).rows[0]?.userId;
			// Acquire actor and target in a stable order before locking sessions/grants.
			const users = new Set([current.user.id]);
			if (targetUserId) users.add(targetUserId);
			let administrator = null;
			let target = null;
			for (const userId of [...users].sort()) {
				const user = await store.lockUser(client, userId);
				if (userId === current.user.id) administrator = user;
				if (userId === targetUserId) target = user;
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
			if (mutation.path === singlePath || mutation.path === bulkPath) {
				const selector =
					mutation.path === singlePath
						? { tokens: [mutation.sessionToken] }
						: { userId: mutation.userId };
				await options.revoke(client, request, selector, path, administrator.id);
				await record();
				return accountLinkJson({ success: true }, 200, headers);
			}
			const reject = async (status: number, code: string, message: string) => {
				await record(code);
				return accountLinkJson({ code, message }, status, headers);
			};
			if (!target) return reject(404, "USER_NOT_FOUND", "User not found");
			if (mutation.path === rolePath) {
				const role =
					typeof mutation.role === "string"
						? mutation.role
						: mutation.role.join(",");
				await client.query(
					'UPDATE "user" SET role=$2,"updatedAt"=statement_timestamp() WHERE id=$1',
					[target.id, role],
				);
			} else {
				const banned = mutation.path === banPath;
				if (banned && target.id === administrator.id)
					return reject(
						400,
						"YOU_CANNOT_BAN_YOURSELF",
						"You cannot ban yourself",
					);
				const banExpires =
					banned && mutation.banExpiresIn
						? new Date(Date.now() + mutation.banExpiresIn * 1000)
						: null;
				if (banExpires && !Number.isFinite(banExpires.getTime()))
					return reject(
						400,
						"VALIDATION_ERROR",
						"The ban expiration is outside the supported date range.",
					);
				await client.query(
					`UPDATE "user" SET banned=$2,"banReason"=$3,"banExpires"=$4,"updatedAt"=statement_timestamp() WHERE id=$1`,
					[
						target.id,
						banned,
						banned ? mutation.banReason || "No reason" : null,
						banExpires,
					],
				);
			}
			await store.record(
				client,
				"user.updated",
				"success",
				path,
				target.id,
				target.id,
				administrator.id,
			);
			if (mutation.path === banPath)
				await options.revoke(
					client,
					request,
					{ userId: target.id },
					path,
					administrator.id,
				);
			const user = await readRealmAdminUser(client, target.id);
			if (!user)
				throw new Error("The updated realm account could not be read.");
			await record();
			return accountLinkJson({ user }, 200, headers);
		});
	};
}
