import type { PoolClient } from "pg";
import * as z from "zod";
import { isPlatformAdmin, rolesInclude } from "../configuration";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import type {
	createProjectEngineStore,
	ProjectSession,
	ProjectUser,
} from "./owned-project-engine-store";
import { projectUserResponse } from "./owned-project-engine-store";
import { projectSupportStore } from "./owned-project-support-store";

const targetInput = z.object({ userId: z.string().min(1).max(160) });
const sessionToken = /^[A-Za-z0-9_-]{16,128}$/;
const startPath = "/admin/impersonate-user";
const stopPath = "/admin/stop-impersonating";
const unauthorized = () =>
	accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
const missingActor = () =>
	accountLinkError(
		500,
		"INTERNAL_SERVER_ERROR",
		"Failed to find admin session",
	);

function responseSession(
	session: ProjectSession,
	user: ProjectUser,
	headers?: Headers,
	token?: string,
) {
	return accountLinkJson(
		{
			session: {
				...session,
				createdAt: new Date(session.createdAt).toISOString(),
				updatedAt: new Date(session.updatedAt).toISOString(),
				expiresAt: new Date(session.expiresAt).toISOString(),
				...(token ? { token } : {}),
			},
			user: projectUserResponse(user),
		},
		200,
		headers,
	);
}

/** Preserve the same-project administrator proof independently of workspace support handoffs. */
export function createOwnedProjectRealmImpersonation(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	trustedRequest(headers: Headers, write: boolean): boolean;
	readBody(request: Request): Promise<unknown>;
	readCookie(
		headers: Headers,
		kind: "session" | "admin" | "remember",
	): string | null;
	writeCookie(
		headers: Headers,
		kind: "session" | "admin" | "remember",
		value: string,
		maxAge?: number,
	): void;
	clearCookies(headers: Headers): void;
	trustedIP(request: Request): string | null;
	revoke(
		client: PoolClient,
		request: Request,
		token: string,
		actorId: string,
	): Promise<boolean>;
}) {
	const { store } = options;

	async function administratorProof(client: PoolClient, request: Request) {
		const targetToken = options.readCookie(request.headers, "session");
		const authority = options.readCookie(request.headers, "admin")?.split(":");
		const [actorToken, short] = authority ?? [];
		if (
			!targetToken ||
			!actorToken ||
			!sessionToken.test(actorToken) ||
			authority?.length !== 2 ||
			(short !== "" && short !== "true")
		)
			return null;
		const target = await store.session(targetToken, 0, client);
		const actor = await store.session(actorToken, 0, client);
		if (
			!target?.session.impersonatedBy ||
			!actor ||
			target.session.impersonatedBy !== actor.user.id ||
			actor.session.impersonatedBy ||
			actor.user.banned ||
			actor.user.directoryDisabled
		)
			return null;
		return { target, targetToken, actor, actorToken, short: short === "true" };
	}

	async function start(request: Request) {
		const input = targetInput.safeParse(await options.readBody(request));
		if (!input.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"Invalid impersonation request.",
			);
		const actorToken = options.readCookie(request.headers, "session");
		if (!actorToken) return unauthorized();
		return store.transaction(async (client) => {
			const actor = await store.session(actorToken, 0, client);
			if (!actor) return unauthorized();
			const actingUser = await store.lockUser(client, actor.user.id);
			if (
				!actingUser ||
				actingUser.directoryDisabled ||
				!isPlatformAdmin(actingUser, actor.session) ||
				!(await store.lockSession(client, actorToken, actingUser.id, false))
			)
				return accountLinkError(
					403,
					"YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
					"You are not allowed to impersonate users",
				);
			const realm = projectSupportStore(client);
			const target = await realm.target(input.data.userId);
			if (!target)
				return accountLinkError(404, "USER_NOT_FOUND", "User not found");
			if (
				rolesInclude(target.role, "admin") ||
				target.banned ||
				target.directoryDisabled
			)
				return accountLinkError(
					403,
					"YOU_CANNOT_IMPERSONATE_ADMINS",
					"You cannot impersonate this user",
				);
			const current = await realm.createSession(
				target,
				actingUser.id,
				new Date(Date.now() + 15 * 60_000),
				options.trustedIP(request) ?? "",
				request.headers.get("user-agent")?.slice(0, 512) ?? "",
			);
			await store.record(
				client,
				"session.impersonation-started",
				"success",
				startPath,
				target.userId,
				current.id,
				actingUser.id,
			);
			const result = await store.session(current.token, 0, client);
			if (!result)
				throw new Error("The project impersonation session was not created.");
			const headers = new Headers();
			options.clearCookies(headers);
			options.writeCookie(
				headers,
				"admin",
				`${actorToken}:${options.readCookie(request.headers, "remember") === "true" ? "true" : ""}`,
			);
			options.writeCookie(headers, "session", current.token);
			options.writeCookie(headers, "remember", "true");
			return responseSession(
				result.session,
				result.user,
				headers,
				current.token,
			);
		});
	}

	async function stop(request: Request) {
		const token = options.readCookie(request.headers, "session");
		if (!token) return unauthorized();
		return store.transaction(async (client) => {
			const current = await store.session(token, 0, client);
			if (!current) return unauthorized();
			if (!current.session.impersonatedBy)
				return accountLinkError(
					400,
					"BAD_REQUEST",
					"You are not impersonating anyone",
				);
			const proof = await administratorProof(client, request);
			if (!proof) return missingActor();
			const { actor, actorToken, target, targetToken, short } = proof;
			const restoredUser = await store.lockUser(client, actor.user.id);
			if (
				!restoredUser ||
				restoredUser.banned ||
				restoredUser.directoryDisabled ||
				!(await store.lockSession(client, actorToken, restoredUser.id, false))
			)
				return missingActor();
			const realm = projectSupportStore(client);
			const locked = await realm.session(targetToken, "token", {
				lock: "write",
			});
			if (
				!locked ||
				locked.id !== target.session.id ||
				locked.impersonatedBy !== restoredUser.id
			)
				return unauthorized();
			if (
				!(await options.revoke(client, request, targetToken, restoredUser.id))
			)
				return unauthorized();
			await store.record(
				client,
				"session.impersonation-stopped",
				"success",
				stopPath,
				locked.userId,
				locked.id,
				restoredUser.id,
			);
			const headers = new Headers();
			options.clearCookies(headers);
			options.writeCookie(headers, "admin", "", 0);
			options.writeCookie(
				headers,
				"session",
				actorToken,
				short
					? undefined
					: Math.max(
							0,
							Math.ceil(
								(Date.parse(actor.session.expiresAt) - Date.now()) / 1000,
							),
						),
			);
			if (short) options.writeCookie(headers, "remember", "true");
			return responseSession(actor.session, restoredUser, headers, actorToken);
		});
	}

	return {
		async dispatch(path: string, request: Request) {
			if (
				request.method !== "POST" ||
				(path !== startPath && path !== stopPath)
			)
				return;
			if (!options.trustedRequest(request.headers, true)) return unauthorized();
			return path === startPath ? start(request) : stop(request);
		},
		async read(request: Request) {
			if (!options.readCookie(request.headers, "admin")) return;
			return store.transaction(async (client) => {
				const proof = await administratorProof(client, request);
				return proof &&
					isPlatformAdmin(proof.actor.user, proof.actor.session) &&
					!proof.target.user.banned &&
					!proof.target.user.directoryDisabled
					? responseSession(proof.target.session, proof.target.user)
					: accountLinkJson(null);
			});
		},
	};
}
