import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ControlPrincipal } from "../control/types";
import type { OwnedProjectAccountDeletionOptions } from "./owned-project-account-deletion";
import {
	claimProjectUserDeletion,
	eraseLockedProjectUser,
	lockProjectUserDeletion,
	releaseProjectUserDeletion,
} from "./owned-project-account-deletion";
import {
	accountLinkError,
	accountLinkHeaders,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";
import { projectOrigin, projectSlug } from "./validation";

const workspacePath = "/project-admin/remove-user";
const realmPath = "/admin/remove-user";
const workspaceInput = z.strictObject({ userId: z.string().min(1).max(160) });
const realmInput = z.object({
	userId: z.union([z.string(), z.number()]).transform(String),
});
export type ProjectAdministratorDeletionPath =
	| typeof workspacePath
	| typeof realmPath;

export interface OwnedProjectAdminDeletionOptions {
	database: Pool;
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">;
	baseURL: string;
	basePath: string;
	platformOrigin: string;
	trustedOrigins: readonly string[];
	requireMfa: boolean;
	/** The platform engine verifies the original root cookie, before SQL rechecks its authority. */
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	/** The project engine verifies its realm-specific session cookie. */
	readRealmSession(
		request: Request,
		client: PoolClient,
	): Promise<{
		token: string;
		user: ProjectUser;
		session: { id: string };
	} | null>;
	beforeDelete: OwnedProjectAccountDeletionOptions["beforeDelete"];
	/** Keep issuer logout and its after-commit delivery on the same writer. */
	revokeSessions(
		client: PoolClient,
		request: Request,
		userId: string,
		path: ProjectAdministratorDeletionPath,
		actorId: string,
	): Promise<void>;
}

const unavailable = () =>
	accountLinkError(
		503,
		"ACCOUNT_DELETION_UNAVAILABLE",
		"Account deletion is temporarily unavailable.",
	);
const workspaceDenied = () =>
	accountLinkError(
		403,
		"FORBIDDEN",
		"A workspace owner or administrator is required.",
	);
const realmDenied = () =>
	accountLinkError(
		403,
		"YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
		"You are not allowed to delete users",
	);

/** Administrator erasure shares the self-service lease and requires live authority at both transaction boundaries. */
export function createOwnedProjectAdminDeletion(
	options: OwnedProjectAdminDeletionOptions,
) {
	const { project } = options;
	const origin = projectOrigin.parse(options.baseURL);
	const platformOrigin = projectOrigin.parse(options.platformOrigin);
	const directPath = `/api/projects/${projectSlug.parse(project.slug)}/auth`;
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	if (options.basePath !== directPath && options.basePath !== "/api/auth")
		throw new Error("Invalid project administrator route binding.");
	const store = createProjectEngineStore(options.database, project.schemaName);

	function realmAdmin(user: ProjectUser | null): user is ProjectUser {
		return Boolean(
			user &&
				!user.banned &&
				!user.isAnonymous &&
				!user.directoryDisabled &&
				user.role?.split(",").includes("admin") &&
				(!options.requireMfa || (user.emailVerified && user.twoFactorEnabled)),
		);
	}

	async function lockedTarget(
		client: PoolClient,
		request: Request,
		userId: string,
		workspace: ControlPrincipal | null,
	) {
		if (workspace) {
			if (
				!(await lockOwnedProjectWorkspaceAdministrator(
					client,
					project,
					workspace,
				))
			)
				return workspaceDenied();
			const target = await store.lockUser(client, userId);
			return target
				? {
						actorId: workspace.user.id,
						authorityId: workspace.session.id,
						target,
					}
				: accountLinkError(
						404,
						"NOT_FOUND",
						"This user does not exist in the selected project.",
					);
		}
		const session = await options.readRealmSession(request, client);
		if (!session) return accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
		if (!realmAdmin(session.user)) return realmDenied();
		if (userId === session.user.id)
			return accountLinkError(
				400,
				"YOU_CANNOT_REMOVE_YOURSELF",
				"You cannot remove yourself",
			);
		// Acquire both rows in the same order when two administrators act concurrently.
		await client.query(
			`SELECT id FROM "user" WHERE id=ANY($1::text[]) ORDER BY id FOR UPDATE`,
			[[session.user.id, userId]],
		);
		const actor = await store.lockUser(client, session.user.id);
		if (
			!realmAdmin(actor) ||
			!(await store.lockSession(client, session.token, actor.id, false))
		)
			return realmDenied();
		const target = await store.lockUser(client, userId);
		return target
			? { actorId: actor.id, authorityId: session.session.id, target }
			: accountLinkError(404, "USER_NOT_FOUND", "User not found");
	}

	async function event(
		client: PoolClient,
		path: ProjectAdministratorDeletionPath,
		type: string,
		actorId: string,
		userId: string,
		targetId: string,
		provider?: string,
	) {
		await client.query(
			`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","userId","targetId","createdAt",metadata)
			 VALUES ($1,$2,'success',$3,$4,$5,statement_timestamp(),jsonb_strip_nulls(jsonb_build_object('path',$6::text,'signal',$7::text,'provider',$8::text)))`,
			[
				randomUUID(),
				type,
				actorId,
				userId,
				targetId,
				path,
				path === workspacePath ? "platform-project-management" : null,
				provider ?? null,
			],
		);
	}

	return async (
		request: Request,
		path: ProjectAdministratorDeletionPath,
		input: unknown,
	) => {
		const url = new URL(request.url);
		const caller = request.headers.get("origin");
		const isWorkspace = path === workspacePath;
		if (
			request.method !== "POST" ||
			url.origin !== origin ||
			url.pathname !== `${options.basePath}${path}` ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			!caller ||
			(isWorkspace
				? caller !== platformOrigin ||
					origin !== platformOrigin ||
					options.basePath !== directPath
				: !origins.has(caller))
		)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"Project changes require a same-origin request.",
			);
		const parsed = (isWorkspace ? workspaceInput : realmInput).safeParse(input);
		if (!parsed.success)
			return accountLinkError(400, "INVALID_BODY", "Select a project user.");
		const { userId } = parsed.data;
		let workspace: ControlPrincipal | null = null;
		let key: string | null = null;
		const lease = randomUUID();
		try {
			if (isWorkspace) {
				workspace = await options.readWorkspacePrincipal(request.headers);
				if (
					!workspace ||
					workspace.session.userId !== workspace.user.id ||
					workspace.session.impersonatedBy ||
					workspace.user.emailVerified !== true ||
					workspace.user.banned
				)
					return workspaceDenied();
			}
			const claim = await store.transaction(async (client) => {
				const authority = await lockedTarget(
					client,
					request,
					userId,
					workspace,
				);
				if (authority instanceof Response) return authority;
				const reserved = await claimProjectUserDeletion(client, userId, lease);
				return reserved
					? { ...authority, key: reserved }
					: accountLinkError(
							409,
							"DELETION_PENDING",
							"Account deletion is already being processed.",
						);
			});
			if (claim instanceof Response) return claim;
			key = claim.key;
			const fence = await options.beforeDelete({ request, user: claim.target });
			if (fence instanceof Response)
				return new Response(fence.body, {
					status: fence.status,
					headers: accountLinkHeaders(new Headers(fence.headers)),
				});
			const result = await store.transaction(async (client) => {
				const current = await lockedTarget(client, request, userId, workspace);
				if (current instanceof Response) return current;
				if (
					current.actorId !== claim.actorId ||
					current.authorityId !== claim.authorityId ||
					new Date(current.target.createdAt).getTime() !==
						new Date(claim.target.createdAt).getTime() ||
					!(await lockProjectUserDeletion(client, claim.key, lease)) ||
					(fence && !(await fence.verify(client)))
				)
					return unavailable();
				await options.revokeSessions(
					client,
					request,
					userId,
					path,
					current.actorId,
				);
				const accounts = await eraseLockedProjectUser(
					client,
					userId,
					claim.key,
				);
				for (const account of accounts)
					await event(
						client,
						path,
						"account.deleted",
						current.actorId,
						userId,
						account.id,
						account.providerId,
					);
				await event(
					client,
					path,
					"user.deleted",
					current.actorId,
					userId,
					userId,
				);
				if (!isWorkspace) {
					await event(
						client,
						path,
						"admin.remove-user",
						current.actorId,
						userId,
						userId,
					);
					await client.query(
						`INSERT INTO "allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,$2,$3,$4,statement_timestamp())`,
						[randomUUID(), current.actorId, path, userId],
					);
				}
				return accountLinkJson({ success: true }, 200);
			});
			if (result.ok) key = null;
			return result;
		} catch {
			return unavailable();
		} finally {
			const reserved = key;
			if (reserved)
				await store
					.transaction((client) =>
						releaseProjectUserDeletion(client, reserved, lease),
					)
					.catch(() => undefined);
		}
	};
}
