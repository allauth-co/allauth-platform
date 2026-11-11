// cspell:words organisation
import type {
	BetterAuthPlugin,
	GenericEndpointContext,
} from "@better-auth/core";
import type { Where } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { defaultRoles } from "better-auth/plugins/organization/access";
import * as z from "zod";

export interface ServiceDirectoryOptions {
	project: string;
	projectId: string;
	environment: "development" | "production";
	authorize: (headers: Headers) => Promise<void>;
}
const id = z.string().min(1).max(160);
const page = {
	limit: z.coerce.number().int().min(1).max(100).default(25),
	offset: z.coerce.number().int().min(0).max(100000).default(0),
};
/** Explicit projections never expose credentials or confer management authority. */
export function serviceDirectory(options: ServiceDirectoryOptions) {
	const authorize = async (ctx: GenericEndpointContext) => {
		ctx.setHeader("cache-control", "no-store");
		ctx.setHeader("pragma", "no-cache");
		await options.authorize(
			ctx.headers || ctx.request?.headers || new Headers(),
		);
	};
	const envelope = {
		project: options.project,
		projectId: options.projectId,
		environment: options.environment,
	};
	const read = async (
		ctx: GenericEndpointContext,
		model: string,
		collection: string,
		fields: string[],
		where: Where[],
		limit: number,
		offset: number,
	) => {
		const [rows, total] = await Promise.all([
			ctx.context.adapter.findMany({
				model,
				where,
				select: fields,
				limit,
				offset,
				sortBy: { field: "id", direction: "asc" },
			}),
			ctx.context.adapter.count({ model, where }),
		]);
		return ctx.json({ ...envelope, [collection]: rows, total, limit, offset });
	};
	const organization = async (
		ctx: GenericEndpointContext,
		organizationId: string,
	) => {
		if (
			!(await ctx.context.adapter.findOne({
				model: "organization",
				where: [{ field: "id", value: organizationId }],
				select: ["id"],
			}))
		)
			throw new APIError("NOT_FOUND");
	};
	return {
		id: "allauth-service-directory",
		endpoints: {
			serviceDirectoryUsers: createAuthEndpoint(
				"/service-directory/users",
				{
					method: "GET",
					requireHeaders: true,
					query: z
						.object({ userId: id.optional(), ...page })
						.strict()
						.prefault({}),
				},
				async (ctx) => {
					await authorize(ctx);
					return read(
						ctx,
						"user",
						"users",
						[
							"id",
							"name",
							"email",
							"emailVerified",
							"twoFactorEnabled",
							"image",
							"banned",
							"banExpires",
							"directoryDisabled",
							"createdAt",
							"updatedAt",
						],
						ctx.query.userId ? [{ field: "id", value: ctx.query.userId }] : [],
						ctx.query.limit,
						ctx.query.offset,
					);
				},
			),
			serviceDirectoryOrganizations: createAuthEndpoint(
				"/service-directory/organizations",
				{
					method: "GET",
					requireHeaders: true,
					query: z
						.object({ organizationId: id.optional(), ...page })
						.strict()
						.prefault({}),
				},
				async (ctx) => {
					await authorize(ctx);
					return read(
						ctx,
						"organization",
						"organizations",
						["id", "name", "slug", "logo", "createdAt"],
						ctx.query.organizationId
							? [{ field: "id", value: ctx.query.organizationId }]
							: [],
						ctx.query.limit,
						ctx.query.offset,
					);
				},
			),
			serviceDirectoryMembers: createAuthEndpoint(
				"/service-directory/members",
				{
					method: "GET",
					requireHeaders: true,
					query: z
						.object({
							organizationId: id.optional(),
							userId: id.optional(),
							...page,
						})
						.strict()
						.refine(
							(value) => Boolean(value.organizationId || value.userId),
							"Choose a user or organisation.",
						),
				},
				async (ctx) => {
					await authorize(ctx);
					if (ctx.query.organizationId)
						await organization(ctx, ctx.query.organizationId);
					return read(
						ctx,
						"member",
						"members",
						["id", "organizationId", "userId", "role", "createdAt"],
						[
							...(ctx.query.organizationId
								? [{ field: "organizationId", value: ctx.query.organizationId }]
								: []),
							...(ctx.query.userId
								? [{ field: "userId", value: ctx.query.userId }]
								: []),
						],
						ctx.query.limit,
						ctx.query.offset,
					);
				},
			),
			serviceDirectoryRoles: createAuthEndpoint(
				"/service-directory/roles",
				{
					method: "GET",
					requireHeaders: true,
					query: z.object({ organizationId: id, ...page }).strict(),
				},
				async (ctx) => {
					await authorize(ctx);
					await organization(ctx, ctx.query.organizationId);
					const builtIns = Object.entries(defaultRoles).map(
						([role, value]) => ({
							id: role,
							role,
							permission: value.statements,
							builtIn: true,
						}),
					);
					const where = [
						{ field: "organizationId", value: ctx.query.organizationId },
					];
					const total =
						builtIns.length +
						(await ctx.context.adapter.count({
							model: "organizationRole",
							where,
						}));
					const native = await ctx.context.adapter.findMany<{
						id: string;
						role: string;
						permission: string;
					}>({
						model: "organizationRole",
						where,
						select: ["id", "role", "permission"],
						sortBy: { field: "role", direction: "asc" },
						limit: Math.max(
							1,
							ctx.query.limit - Math.max(0, builtIns.length - ctx.query.offset),
						),
						offset: Math.max(0, ctx.query.offset - builtIns.length),
					});
					const roles = [
						...builtIns.slice(
							ctx.query.offset,
							ctx.query.offset + ctx.query.limit,
						),
						...native.map((row) => ({
							...row,
							permission: JSON.parse(row.permission) as unknown,
							builtIn: false,
						})),
					].slice(0, ctx.query.limit);
					return ctx.json({
						...envelope,
						roles,
						total,
						limit: ctx.query.limit,
						offset: ctx.query.offset,
					});
				},
			),
		},
	} satisfies BetterAuthPlugin;
}
