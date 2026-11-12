import type { PoolClient } from "pg";
import * as z from "zod";
import type { PasswordPolicy } from "../auth-policy/password";
import { passwordPolicyError } from "../auth-policy/password";
import { reservedProjectEmailError } from "../project-email-alias-config";
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
import type { RealmAdminPasswordSafety } from "./owned-project-realm-admin-password";
import {
	prepareRealmAdminPassword,
	realmAdminPasswordPath,
	realmAdminPasswordUnavailable,
	writeRealmAdminPassword,
} from "./owned-project-realm-admin-password";
import type { RealmAdminUserFailure } from "./owned-project-realm-admin-users";
import {
	insertRealmAdminUser,
	realmAdminCreateUserInput,
	realmAdminCreateUserPath,
	realmAdminDuplicateEmail,
	realmAdminDuplicateUsername,
	realmAdminEmailInUse,
	realmAdminUpdateUserInput,
	realmAdminUpdateUserPath,
	realmAdminUserFields,
	realmAdminUsernameInUse,
	updateRealmAdminUser,
} from "./owned-project-realm-admin-users";
import { preserveProjectBeforeHookError } from "./project-error-localization";

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
	[realmAdminPasswordPath]: z
		.object({
			userId: userId.nonempty("userId cannot be empty"),
			newPassword: z.string(),
		})
		.transform((data) => ({ ...data, path: realmAdminPasswordPath }) as const),
	[realmAdminCreateUserPath]: realmAdminCreateUserInput.transform(
		(data) => ({ ...data, path: realmAdminCreateUserPath }) as const,
	),
	[realmAdminUpdateUserPath]: realmAdminUpdateUserInput.transform(
		(data) => ({ ...data, path: realmAdminUpdateUserPath }) as const,
	),
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
	[realmAdminPasswordPath]: [
		"YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
		"You are not allowed to set users password",
	],
	[realmAdminCreateUserPath]: [
		"YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
		"You are not allowed to create users",
	],
	[realmAdminUpdateUserPath]: [
		"YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
		"You are not allowed to update users",
	],
};

type MutationPath = keyof typeof inputs;
type RevocationSelector = { tokens: string[] } | { userId: string };
type Store = ReturnType<typeof createProjectEngineStore>;
type RealmSession = NonNullable<Awaited<ReturnType<Store["session"]>>>;
type PasswordAuthority = { sessionId: string; targetCreatedAt: number | null };
type PasswordAttempt = PasswordAuthority & {
	result: Awaited<ReturnType<typeof prepareRealmAdminPassword>>;
};

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
	passwordPolicy: PasswordPolicy;
	checkPasswordSafety?: RealmAdminPasswordSafety;
	primaryOrigin: string;
	reservedEmail?(email: string): boolean;
	blockAdminCreation(
		client: PoolClient,
		request: Request,
		email: string,
		reportMonitor: boolean,
	): Promise<boolean>;
	clearUserAuthentication(client: PoolClient, userId: string): Promise<void>;
	revoke(
		client: PoolClient,
		request: Request,
		selector: RevocationSelector,
		path: MutationPath,
		actorId: string,
		authentication?: "all" | "linked",
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
		const password =
			mutation.path === realmAdminPasswordPath
				? mutation.newPassword
				: mutation.path === realmAdminCreateUserPath
					? (mutation.password ?? null)
					: null;
		// The native endpoint coerces the selector, but its after-hook audits the raw ID.
		const targetId =
			path !== singlePath &&
			path !== realmAdminCreateUserPath &&
			typeof body === "object" &&
			body !== null &&
			"userId" in body &&
			typeof body.userId === "string"
				? body.userId
				: undefined;
		const token = options.readCookie(request.headers);
		const ipAddress = options.trustedIP(request) ?? undefined;
		async function perform(
			client: PoolClient,
			attempt?: PasswordAttempt,
		): Promise<Response | PasswordAuthority> {
			if (ipAddress && !attempt) {
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
			if (password !== null && !attempt) {
				const rules = options.passwordPolicy;
				const message = passwordPolicyError(password, rules);
				if (message)
					return preserveProjectBeforeHookError(
						accountLinkError(
							400,
							password.length < rules.minLength
								? "PASSWORD_TOO_SHORT"
								: password.length > rules.maxLength
									? "PASSWORD_TOO_LONG"
									: "PASSWORD_REQUIREMENTS_NOT_MET",
							message,
						),
					);
			}
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
					: mutation.path === singlePath
						? (
								await client.query<{ userId: string }>(
									'SELECT "userId" FROM "session" WHERE token=$1',
									[mutation.sessionToken],
								)
							).rows[0]?.userId
						: undefined;
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
			if (mutation.path === realmAdminPasswordPath && target && !attempt)
				return {
					sessionId: current.session.id,
					targetCreatedAt: new Date(target.createdAt).getTime(),
				};
			const preparingCreation =
				mutation.path === realmAdminCreateUserPath &&
				password !== null &&
				!attempt;
			if (!preparingCreation)
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
			const reject = async (
				status: number,
				code: string,
				message: string,
				exposeCode = true,
			) => {
				await record(code);
				return accountLinkJson(
					exposeCode ? { code, message } : { message },
					status,
					headers,
				);
			};
			async function userFailure({
				status,
				code,
				message,
				exposeCode,
			}: RealmAdminUserFailure) {
				return reject(status, code, message, exposeCode);
			}
			if (mutation.path === realmAdminCreateUserPath) {
				const resolved = realmAdminUserFields(mutation, options.primaryOrigin);
				if (resolved.failure) return userFailure(resolved.failure);
				const { fields } = resolved;
				if (!fields.email)
					throw new Error("A realm administrator creation email was expected.");
				if (await realmAdminEmailInUse(client, fields.email))
					return userFailure(realmAdminDuplicateEmail);
				if (options.reservedEmail?.(fields.email))
					return userFailure(reservedProjectEmailError);
				if (
					await options.blockAdminCreation(
						client,
						request,
						fields.email,
						!preparingCreation,
					)
				)
					return reject(403, "validation_failed", "User validation failed");
				if (
					fields.username &&
					(await realmAdminUsernameInUse(client, fields.username))
				)
					return userFailure(realmAdminDuplicateUsername);
				if (preparingCreation)
					return { sessionId: current.session.id, targetCreatedAt: null };
				if (attempt && current.session.id !== attempt.sessionId)
					return reject(
						409,
						"PASSWORD_CHANGE_UNAVAILABLE",
						"The administrator session changed while preparing the password. Try again.",
					);
				if (attempt?.result.failure) return userFailure(attempt.result.failure);
				const id = await insertRealmAdminUser(client, fields);
				if (!id)
					return userFailure(
						fields.username !== undefined &&
							fields.username !== null &&
							(await realmAdminUsernameInUse(client, fields.username))
							? realmAdminDuplicateUsername
							: realmAdminDuplicateEmail,
					);
				await store.record(
					client,
					"user.created",
					"success",
					path,
					id,
					id,
					administrator.id,
				);
				if (
					attempt?.result.hash &&
					!(await writeRealmAdminPassword(client, store, {
						userId: id,
						actorId: administrator.id,
						hash: attempt.result.hash,
						path,
					}))
				)
					throw new Error("The new realm credential could not be written.");
				const user = await readRealmAdminUser(client, id);
				if (!user)
					throw new Error("The created realm account could not be read.");
				await record();
				return accountLinkJson({ user }, 200, headers);
			}
			if (mutation.path === realmAdminUpdateUserPath) {
				const resolved = realmAdminUserFields(mutation, options.primaryOrigin);
				if (resolved.failure) return userFailure(resolved.failure);
				const { fields } = resolved;
				if (fields.banned === true && mutation.userId === administrator.id)
					return reject(
						400,
						"YOU_CANNOT_BAN_YOURSELF",
						"You cannot ban yourself",
					);
				if (
					fields.email &&
					(await realmAdminEmailInUse(client, fields.email, mutation.userId))
				)
					return userFailure(realmAdminDuplicateEmail);
				if (!target) return reject(404, "USER_NOT_FOUND", "User not found");
				if (
					fields.username &&
					(await realmAdminUsernameInUse(
						client,
						fields.username,
						administrator.id,
					))
				)
					return userFailure(realmAdminDuplicateUsername);
				const failure = await updateRealmAdminUser(client, target.id, fields);
				if (failure) return userFailure(failure);
				await store.record(
					client,
					"user.updated",
					"success",
					path,
					target.id,
					target.id,
					administrator.id,
				);
				if (fields.banned === true)
					await options.revoke(
						client,
						request,
						{ userId: target.id },
						path,
						administrator.id,
						"linked",
					);
				const user = await readRealmAdminUser(client, target.id);
				if (!user)
					throw new Error("The updated realm account could not be read.");
				await record();
				return accountLinkJson(user, 200, headers);
			}
			if (!target) return reject(404, "USER_NOT_FOUND", "User not found");
			if (mutation.path === realmAdminPasswordPath) {
				if (!attempt)
					throw new Error(
						"A prepared realm administrator password was expected.",
					);
				if (
					current.session.id !== attempt.sessionId ||
					new Date(target.createdAt).getTime() !== attempt.targetCreatedAt
				)
					return reject(
						409,
						"PASSWORD_CHANGE_UNAVAILABLE",
						"The account changed while preparing the password. Try again.",
					);
				if (attempt.result.failure) {
					const { status, code, message } = attempt.result.failure;
					return reject(status, code, message);
				}
				if (
					!(await writeRealmAdminPassword(client, store, {
						userId: target.id,
						actorId: administrator.id,
						hash: attempt.result.hash,
					}))
				) {
					const { status, code, message } = realmAdminPasswordUnavailable;
					return reject(status, code, message);
				}
				await options.clearUserAuthentication(client, target.id);
				await record();
				return accountLinkJson({ status: true }, 200, headers);
			}
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
		}
		const first = await store.transaction((client) => perform(client));
		if (first instanceof Response) return first;
		if (password === null) throw new Error("A password mutation was expected.");
		const result = await prepareRealmAdminPassword(
			password,
			options.checkPasswordSafety,
		);
		const committed = await store.transaction((client) =>
			perform(client, { ...first, result }),
		);
		if (!(committed instanceof Response))
			throw new Error("The realm administrator password was not finalized.");
		return committed;
	};
}
