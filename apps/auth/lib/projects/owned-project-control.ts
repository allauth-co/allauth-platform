import { CompiledQuery, Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import * as z from "zod";
import { rolesInclude } from "../configuration";
import { controlEventAttributes } from "../control/event-metadata";
import {
	controlLogDetailQuery,
	controlLogsQuery,
	queryControlLogs,
} from "../control/logs";
import {
	queryControlEvents,
	queryControlOverview,
	queryControlSessions,
} from "../control/queries";
import {
	controlEventsQuery,
	controlIdentifier,
	controlSessionsQuery,
} from "../control/read-input";
import {
	defaultSecurityPolicy,
	securityPolicySchema,
} from "../control/security-policy";
import type {
	ControlDatabase,
	ControlEventFilters,
	ControlPrincipal,
} from "../control/types";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

const queries = {
	"/control/overview": undefined,
	"/control/events": controlEventsQuery,
	"/control/sessions": controlSessionsQuery,
	"/control/logs": controlLogsQuery,
	"/control/logs/detail": controlLogDetailQuery,
};
type ControlPath = keyof typeof queries;
const revokePath = "/control/revoke-session";
const revokeInput = z.object({ id: controlIdentifier }).strict();

type ProjectControlSession = {
	id: string;
	userId: string;
};

export function createOwnedProjectControl(options: {
	database: Pool;
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">;
	origin: string;
	basePath: string;
	platformOrigin: string;
	trustedIP(request: Request): string | null;
	readBody(request: Request): Promise<unknown>;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	readProjectSession(headers: Headers): Promise<ProjectControlSession | null>;
}) {
	const { project } = options;
	const schema = checkedProjectSchema(project.schemaName);
	const direct = `/api/projects/${project.slug}/auth`;
	const store = createProjectEngineStore(options.database, schema);
	const database: ControlDatabase = new Kysely({
		dialect: new PostgresDialect({ pool: options.database }),
	});
	const forbidden = () =>
		accountLinkError(
			403,
			"FORBIDDEN",
			"A verified workspace administrator is required.",
		);

	async function checkProjectScope(
		transaction: ControlDatabase,
		current: ProjectControlSession,
		filters: ControlEventFilters,
	) {
		const result = await sql<{
			verified: boolean;
			banned: boolean | null;
			directoryDisabled: boolean | null;
			impersonatedBy: string | null;
		}>`SELECT u."emailVerified" AS verified,u.banned,u."directoryDisabled",s."impersonatedBy"
			FROM "user" u JOIN session s ON s."userId"=u.id
			WHERE s.id=${current.id} AND u.id=${current.userId} AND s."expiresAt">clock_timestamp()
			FOR SHARE OF u,s`.execute(transaction);
		const user = result.rows[0];
		if (!user)
			return accountLinkError(401, "UNAUTHORIZED", "Sign in to continue.");
		if (!user.verified || user.banned || user.directoryDisabled)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"A verified, active account is required.",
			);
		if (filters.scope === "organization") {
			if (!filters.organizationId)
				return accountLinkError(400, "BAD_REQUEST", "Choose an organization.");
			if (user.impersonatedBy)
				return accountLinkError(
					403,
					"FORBIDDEN",
					"Organization audit history is unavailable during impersonation.",
				);
			const member = await sql<{ role: string }>`SELECT role FROM member
				WHERE "userId"=${current.userId} AND "organizationId"=${filters.organizationId}
				FOR SHARE`.execute(transaction);
			const role = member.rows[0]?.role;
			if (
				!role ||
				(!rolesInclude(role, "owner") && !rolesInclude(role, "admin"))
			)
				return accountLinkError(
					403,
					"FORBIDDEN",
					"An organization owner or administrator is required.",
				);
			return;
		}
		if (filters.userId && filters.userId !== current.userId)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"Only your own account history is available.",
			);
		if (filters.organizationId)
			return accountLinkError(
				400,
				"BAD_REQUEST",
				"Use organization scope for organization audit history.",
			);
		filters.userId = current.userId;
	}

	async function revokeSession(
		transaction: ControlDatabase,
		request: Request,
		principal: ControlPrincipal,
		id: string,
	) {
		const absent = () =>
			accountLinkError(404, "NOT_FOUND", "This session no longer exists.");
		const {
			rows: [target],
		} = await sql<{ userId: string }>`
			SELECT "userId" FROM session WHERE id=${id}
		`.execute(transaction);
		if (!target) return absent();
		const { userId } = target;
		const user =
			await sql`SELECT id FROM "user" WHERE id=${userId} FOR UPDATE`.execute(
				transaction,
			);
		if (!user.rows.length) return absent();
		const removed =
			await sql`DELETE FROM session WHERE id=${id} AND "userId"=${userId}
			RETURNING id`.execute(transaction);
		if (!removed.rows.length) return absent();
		await sql`DELETE FROM "oauthAccessToken" WHERE "userId"=${userId}`.execute(
			transaction,
		);
		await sql`DELETE FROM "oauthRefreshToken" WHERE "userId"=${userId}`.execute(
			transaction,
		);
		await sql`DELETE FROM verification WHERE value=${userId}
			AND (starts_with(identifier,'trust-device-') OR starts_with(identifier,'2fa-'))`.execute(
			transaction,
		);
		const { ipAddress, userAgent } = controlEventAttributes({
			ipAddress: options.trustedIP(request) ?? undefined,
			userAgent: request.headers.get("user-agent") ?? undefined,
		});
		await sql`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","userId","targetId",
			"ipAddress","userAgent","createdAt",metadata)
			VALUES (${crypto.randomUUID()},'session.deleted','success',NULL,${userId},${id},NULL,NULL,
			        statement_timestamp(),${JSON.stringify({ path: revokePath })}::jsonb),
			       (${crypto.randomUUID()},'session.revoked','success',${principal.user.id},${userId},${id},
			        ${ipAddress ?? null},${userAgent ?? null},statement_timestamp(),'{}'::jsonb)`.execute(
			transaction,
		);
		return accountLinkJson({ success: true });
	}

	return async function control(request: Request, path: string) {
		const revoking = path === revokePath;
		if (
			(!revoking && !Object.hasOwn(queries, path)) ||
			request.method !== (revoking ? "POST" : "GET")
		)
			return null;
		const url = new URL(request.url);
		if (
			url.origin !== options.origin ||
			url.pathname !== options.basePath + path
		)
			return forbidden();

		const limited = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		const parsed = queries[path as ControlPath]?.safeParse(
			Object.fromEntries(url.searchParams),
		);
		const target = revoking
			? revokeInput.safeParse(await options.readBody(request))
			: undefined;
		if ((parsed && !parsed.success) || (target && !target.success))
			return accountLinkError(
				400,
				"BAD_REQUEST",
				"The request contains invalid fields.",
			);
		const filters: ControlEventFilters = {
			scope: "admin",
			limit: 25,
			offset: 0,
			...parsed?.data,
		};

		let workspacePrincipal: ControlPrincipal | null = null;
		let projectSession: ProjectControlSession | null = null;
		if (filters.scope === "admin") {
			if (
				options.basePath !== direct ||
				url.origin !== options.platformOrigin ||
				request.headers.has("authorization")
			)
				return forbidden();
			workspacePrincipal = await options.readWorkspacePrincipal(
				request.headers,
			);
			if (!workspacePrincipal) return forbidden();
			if (
				revoking &&
				(request.headers.get("origin") !== options.platformOrigin ||
					request.headers.get("sec-fetch-site") === "cross-site")
			)
				return accountLinkError(
					403,
					"FORBIDDEN",
					"Control changes require a same-origin request.",
				);
		} else {
			projectSession = await options.readProjectSession(request.headers);
			if (!projectSession)
				return accountLinkError(401, "UNAUTHORIZED", "Sign in to continue.");
		}

		return database.transaction().execute(async (transaction) => {
			await sql`SET LOCAL search_path TO ${sql.id(schema)}`.execute(
				transaction,
			);
			if (workspacePrincipal) {
				if (
					!(await lockOwnedProjectWorkspaceAdministrator(
						{
							query: (text, values) =>
								transaction.executeQuery(CompiledQuery.raw(text, values)),
						},
						project,
						workspacePrincipal,
					))
				)
					return forbidden();
				if (target?.success)
					return revokeSession(
						transaction,
						request,
						workspacePrincipal,
						target.data.id,
					);
			} else if (projectSession) {
				const denied = await checkProjectScope(
					transaction,
					projectSession,
					filters,
				);
				if (denied) return denied;
			}

			if (path === "/control/sessions")
				return accountLinkJson(
					await queryControlSessions(undefined, transaction, filters),
				);
			const {
				rows: [policy],
			} = await sql<{ policy: unknown }>`
				SELECT policy FROM "allauthSecurityPolicy" WHERE id='default'
			`.execute(transaction);
			const retention = policy
				? securityPolicySchema.parse(policy.policy).logRetentionDays
				: defaultSecurityPolicy.logRetentionDays;
			if (path === "/control/overview")
				return accountLinkJson(
					await queryControlOverview(undefined, transaction, retention),
				);
			if (path === "/control/events")
				return accountLinkJson(
					await queryControlEvents(undefined, transaction, filters, retention),
				);
			const detail = path === "/control/logs/detail";
			const logs = await queryControlLogs(
				undefined,
				transaction,
				detail
					? { ...parsed?.data, ...filters, limit: 1, offset: 0 }
					: { ...parsed?.data, ...filters },
				retention,
			);
			if (!detail) return accountLinkJson(logs);
			return logs.events[0]
				? accountLinkJson({ event: logs.events[0] })
				: accountLinkError(
						404,
						"NOT_FOUND",
						"This log entry is unavailable in this scope or outside retention.",
					);
		});
	};
}
