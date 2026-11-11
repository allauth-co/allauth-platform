import { APIError } from "better-auth";
import * as z from "zod";
import type { WorkspaceDatabase } from "./authorization";
import type { WorkspaceRole } from "./types";

export interface PlatformWorkspaceDirectoryRow {
	id: string;
	slug: string;
	name: string;
	createdAt: string;
	protected: boolean;
	owners: { id: string; name: string; email: string }[];
	memberCount: number;
	applicationCount: number;
	environmentCount: number;
	membershipRole: WorkspaceRole | null;
}

export interface PlatformWorkspaceDirectoryPage {
	workspaces: PlatformWorkspaceDirectoryRow[];
	total: number;
	offset: number;
	limit: number;
}

const integerParam = z.string().regex(/^\d{1,6}$/).transform(Number);
const workspaceDirectoryQuery = z.strictObject({
	search: z.string().trim().max(128).refine((value) => !value.includes("\0")).default(""),
	offset: integerParam.pipe(z.number().min(0).max(100_000)).default(0),
	limit: integerParam.pipe(z.number().min(1).max(100)).default(25),
	accountId: z.string().min(1).max(160).refine((value) => value.trim().length > 0 && !value.includes("\0")).optional(),
});

/** Accept only singleton directory filters, including when a scope hint is empty. */
export function parsePlatformWorkspaceDirectoryQuery(parameters: URLSearchParams) {
	const values: Record<string, string> = {};
	for (const [name, value] of parameters) {
		if (!Object.hasOwn(workspaceDirectoryQuery.shape, name) || Object.hasOwn(values, name)) {
			throw new APIError("BAD_REQUEST", { message: "The request contains invalid fields." });
		}
		values[name] = value;
	}
	return workspaceDirectoryQuery.parse(values);
}

/** Read one page of control-plane workspaces and its total in a single database snapshot. */
export async function listPlatformWorkspaces(database: WorkspaceDatabase, query: z.infer<typeof workspaceDirectoryQuery>): Promise<PlatformWorkspaceDirectoryPage> {
	const { accountId, search, limit, offset } = query;
	const pattern = search ? `%${search.replace(/[!%_]/g, (character) => `!${character}`)}%` : null;
	const { rows: [result] } = await database.query<Pick<PlatformWorkspaceDirectoryPage, "total" | "workspaces">>(`
		WITH matches AS (
			SELECT w.id, w.name, w.slug, w.protected, w."createdAt", selected.role AS "membershipRole"
			FROM public."allauthWorkspace" AS w
			LEFT JOIN public."allauthWorkspaceMember" AS selected
				ON selected."workspaceId" = w.id AND selected."userId" = $1
			WHERE ($1::text IS NULL OR selected.id IS NOT NULL)
				AND ($2::text IS NULL OR w.name ILIKE $2 ESCAPE '!' OR w.slug ILIKE $2 ESCAPE '!'
					OR EXISTS (
						SELECT 1
						FROM public."allauthWorkspaceMember" AS m
						JOIN public."user" AS owner ON owner.id = m."userId"
						WHERE m."workspaceId" = w.id AND m.role = 'owner'
							AND (owner.name ILIKE $2 ESCAPE '!' OR owner.email ILIKE $2 ESCAPE '!')
					))
		), page AS (
			SELECT * FROM matches ORDER BY "createdAt" DESC, id LIMIT $3 OFFSET $4
		)
		SELECT (SELECT count(*)::int FROM matches) AS total,
			COALESCE(jsonb_agg(to_jsonb(workspace) ORDER BY workspace."createdAt" DESC, workspace.id), '[]'::jsonb) AS workspaces
		FROM (
			SELECT page.*, members."memberCount", members.owners, projects."applicationCount", projects."environmentCount"
			FROM page
			CROSS JOIN LATERAL (
				SELECT count(*)::int AS "memberCount",
					COALESCE(jsonb_agg(jsonb_build_object('id', owner.id, 'name', owner.name, 'email', owner.email)
						ORDER BY lower(owner.name), owner.id) FILTER (WHERE owner.id IS NOT NULL), '[]'::jsonb) AS owners
				FROM public."allauthWorkspaceMember" AS m
				LEFT JOIN public."user" AS owner ON owner.id = m."userId" AND m.role = 'owner'
				WHERE m."workspaceId" = page.id
			) AS members
			CROSS JOIN LATERAL (
				SELECT count(DISTINCT p."applicationId")::int AS "applicationCount", count(*)::int AS "environmentCount"
				FROM public."allauthProject" AS p
				WHERE p."workspaceId" = page.id
			) AS projects
		) AS workspace
	`, [accountId ?? null, pattern, limit, offset]);
	return {
		workspaces: result!.workspaces.map((row) => ({ ...row, createdAt: new Date(row.createdAt).toISOString() })),
		total: result!.total,
		offset,
		limit,
	};
}
