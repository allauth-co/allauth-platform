import { APIError } from "better-auth";
import { CompiledQuery, Kysely, PostgresDialect, sql } from "kysely";
import type { Pool } from "pg";
import {
	analyticsEntitiesQuery,
	analyticsQuery,
	queryControlAnalytics,
	queryControlAnalyticsEntities,
} from "../control/analytics";
import {
	createAuthenticatedActivityCollector,
	isControlActivityMutation,
} from "../control/analytics-activity";
import type {
	AnalyticsEntitiesFilters,
	AnalyticsFilters,
} from "../control/analytics-types";
import { isPrimaryAuthenticationPath } from "../control/events";
import { canonicalIP } from "../control/security-policy";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import { accountLinkJson } from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

const summaryPath = "/control/analytics";
const entitiesPath = "/control/analytics/entities";
const publicMutations = new Set([
	"/request-password-reset",
	"/reset-password",
	"/phone-number/send-otp",
	"/phone-number/request-password-reset",
	"/phone-number/reset-password",
]);

function hasCohort(
	filters: AnalyticsFilters | AnalyticsEntitiesFilters,
): filters is AnalyticsEntitiesFilters {
	return "cohort" in filters;
}

/** Public recovery and sign-in responses cannot establish activity for an incoming cookie. */
export function isOwnedProjectActivityMutation(path: string, method: string) {
	return (
		isControlActivityMutation(path, method) &&
		!path.startsWith("/organization/") &&
		!isPrimaryAuthenticationPath(path) &&
		!publicMutations.has(path)
	);
}

/** Project analytics reads and collection share the scope used by the selected writer. */
export function createOwnedProjectAnalytics(options: {
	database: Pool;
	project: Pick<Project, "slug" | "schemaName">;
	workspace?: {
		project: Pick<Project, "id" | "slug" | "schemaName" | "workspaceId">;
		platformOrigin: string;
		readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	};
	origin: string;
	basePath: string;
	trustedIP(request: Request): string | null;
}) {
	const schema = checkedProjectSchema(options.project.schemaName);
	const direct = `/api/projects/${options.project.slug}/auth`;
	if (
		options.workspace &&
		(options.workspace.project.schemaName !== schema ||
			options.workspace.project.slug !== options.project.slug)
	)
		throw new Error("Analytics workspace does not match its project.");
	const store = createProjectEngineStore(options.database, schema);
	const database: ControlDatabase = new Kysely({
		dialect: new PostgresDialect({ pool: options.database }),
	});
	const activity = createAuthenticatedActivityCollector(database, schema);

	/** Derived analytics can be retried by another successful request on the same UTC day. */
	async function collect(work: () => Promise<void> | undefined) {
		try {
			await work();
		} catch {
			console.warn("AllAuth project analytics activity could not be recorded.");
		}
	}

	async function read(request: Request, path: string) {
		if (
			request.method !== "GET" ||
			(path !== summaryPath && path !== entitiesPath)
		)
			return;
		const url = new URL(request.url);
		const workspace = options.workspace;
		const forbidden = () =>
			accountLinkJson(
				{ message: "A verified workspace administrator is required." },
				403,
			);
		if (
			!workspace ||
			options.basePath !== direct ||
			options.origin !== workspace.platformOrigin ||
			url.origin !== workspace.platformOrigin ||
			url.pathname !== direct + path ||
			request.headers.has("authorization")
		)
			return forbidden();
		const ip = canonicalIP(options.trustedIP(request));
		if (ip) {
			const limited = await store.transaction((client) =>
				admitOwnedProjectNativeRoute(client, ip, path, {
					max: 100,
					windowMs: 60_000,
				}),
			);
			if (limited) return limited;
		}
		const query = Object.fromEntries(url.searchParams);
		const parsed = (
			path === summaryPath ? analyticsQuery : analyticsEntitiesQuery
		).safeParse(query);
		if (!parsed.success)
			return accountLinkJson(
				{
					code: "VALIDATION_ERROR",
					message: parsed.error.issues
						.map(
							({ path, message }) =>
								`[query${path.length ? `.${path.join(".")}` : ""}] ${message}`,
						)
						.join("; "),
				},
				400,
			);
		const actor = await workspace.readWorkspacePrincipal(request.headers);
		if (!actor || actor.user.id !== actor.session.userId) return forbidden();
		const filters = parsed.data;
		try {
			return await database.transaction().execute(async (transaction) => {
				const authorized = await lockOwnedProjectWorkspaceAdministrator(
					{
						query: (text, values) =>
							transaction.executeQuery(CompiledQuery.raw(text, values)),
					},
					workspace.project,
					actor,
				);
				if (!authorized) return forbidden();
				await sql`SET LOCAL search_path TO ${sql.id(schema)}`.execute(
					transaction,
				);
				const result = hasCohort(filters)
					? await queryControlAnalyticsEntities(transaction, filters)
					: await queryControlAnalytics(transaction, filters);
				return accountLinkJson(result);
			});
		} catch (error) {
			if (error instanceof APIError)
				return accountLinkJson(error.body, error.statusCode);
			throw error;
		}
	}

	return {
		read,
		session(...input: Parameters<typeof activity.session>) {
			return collect(() => activity.session(...input));
		},
		mutation(token: string) {
			return collect(() => activity.byToken(token));
		},
	};
}
