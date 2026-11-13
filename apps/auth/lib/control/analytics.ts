import type {
	GenericEndpointContext,
	HookEndpointContext,
} from "@better-auth/core";
import { APIError } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import {
	activityOrganizationTarget,
	createAuthenticatedActivityCollector,
	isControlActivityMutation,
} from "./analytics-activity";
import {
	analyticsEntitiesQuery,
	analyticsQuery,
	AnalyticsQueryError,
	queryControlAnalytics,
	queryControlAnalyticsEntities,
} from "./analytics-queries";
import { isPrimaryAuthenticationPath } from "./event-contract";
import { controlResponseFailure } from "./events";
import type { ControlDatabase, ControlPrincipal } from "./types";

export type * from "./analytics-types";
export { createActivityRecorder } from "./analytics-activity";
export {
	analyticsDefinitions,
	analyticsEntitiesQuery,
	analyticsQuery,
	analyticsWindow,
	queryControlAnalytics,
	queryControlAnalyticsEntities,
} from "./analytics-queries";

async function readLegacyAnalytics<T>(read: () => Promise<T>): Promise<T> {
	try {
		return await read();
	} catch (error) {
		if (error instanceof AnalyticsQueryError)
			throw new APIError(error.status, { message: error.message });
		throw error;
	}
}

/** Native analytics endpoints and bounded activity hook; each project uses its own database. */
export function createControlAnalytics(options: {
	database: ControlDatabase;
	requireAdmin: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>;
}) {
	const activity = createAuthenticatedActivityCollector(options.database);
	const noCache = (ctx: GenericEndpointContext) => {
		ctx.setHeader("cache-control", "no-store");
		ctx.setHeader("pragma", "no-cache");
	};
	const endpoints = {
		controlAnalytics: createAuthEndpoint(
			"/control/analytics",
			{ method: "GET", requireHeaders: true, query: analyticsQuery },
			async (ctx) => {
				noCache(ctx);
				await options.requireAdmin(ctx);
				return ctx.json(
					await readLegacyAnalytics(() =>
						queryControlAnalytics(options.database, ctx.query),
					),
				);
			},
		),
		controlAnalyticsEntities: createAuthEndpoint(
			"/control/analytics/entities",
			{ method: "GET", requireHeaders: true, query: analyticsEntitiesQuery },
			async (ctx) => {
				noCache(ctx);
				await options.requireAdmin(ctx);
				return ctx.json(
					await readLegacyAnalytics(() =>
						queryControlAnalyticsEntities(options.database, ctx.query),
					),
				);
			},
		),
	};
	const hook = {
		matcher: (ctx: HookEndpointContext) =>
			Boolean(
				ctx.path &&
					(ctx.path === "/get-session" ||
						ctx.path === "/sign-up/email" ||
						isPrimaryAuthenticationPath(ctx.path) ||
						isControlActivityMutation(ctx.path, ctx.method)),
			),
		handler: createAuthMiddleware(async (ctx) => {
			const outcome = controlResponseFailure(
				ctx.context.returned,
				ctx.context.responseHeaders,
			);
			if (outcome.failed || outcome.pendingMFA) return;
			// Incoming cookies during a failed/pending primary login are not proof that
			// the new authentication completed; only its surviving new session is.
			const body =
				ctx.body && typeof ctx.body === "object"
					? (ctx.body as Record<string, unknown>)
					: undefined;
			const primary = isPrimaryAuthenticationPath(ctx.path || "", body);
			if (primary && !ctx.context.newSession) return;
			const principal = ctx.context.newSession || ctx.context.session;
			if (!principal || principal.session.impersonatedBy) return;
			const source = ctx.path === "/get-session" ? 2 : primary ? 1 : 4;
			const path = ctx.path || "";
			const organizationAction = path.startsWith("/organization/");
			await activity.session(
				principal.session,
				source,
				organizationAction
					? activityOrganizationTarget(path, body, ctx.context.returned)
					: undefined,
				organizationAction,
			);
		}),
	};
	return { endpoints, hook, recorder: activity.recorder };
}
