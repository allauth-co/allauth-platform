import type { PoolClient } from "pg";
import * as z from "zod";
import type { OrganizationSession } from "./owned-project-organization";
import {
	organizationFailure as failure,
	organizationJson as json,
} from "./owned-project-organization-response";
import type { projectOrganizations } from "./owned-project-organization-store";

const fields = {
	id: "id",
	organizationId: '"organizationId"',
	userId: '"userId"',
	role: "role",
	createdAt: '"createdAt"',
} as const;
const fieldName = z.enum([
	"id",
	"organizationId",
	"userId",
	"role",
	"createdAt",
]);
const text = z
	.string()
	.max(2048)
	.refine((value) => !value.includes("\0"));
const scalar = z.union([text, z.number(), z.boolean()]);
const comparators = {
	eq: "=",
	ne: "<>",
	lt: "<",
	lte: "<=",
	gt: ">",
	gte: ">=",
} as const;
const operators = z.enum([
	"eq",
	"ne",
	"lt",
	"lte",
	"gt",
	"gte",
	"in",
	"not_in",
	"contains",
	"starts_with",
	"ends_with",
]);
const queryInput = z.object({
	organizationId: text.optional(),
	organizationSlug: text.optional(),
	limit: z.coerce.number().int().min(0).optional(),
	offset: z.coerce.number().int().min(0).optional(),
	sortBy: fieldName.optional(),
	sortDirection: z.enum(["asc", "desc"]).optional(),
	filterField: fieldName.optional(),
	filterOperator: operators.optional(),
	filterValue: z.union([scalar, z.array(scalar)]).optional(),
});

type MemberQuery = z.infer<typeof queryInput>;

function filterValue(
	value: z.infer<typeof scalar>,
	field: z.infer<typeof fieldName>,
) {
	const text = String(value);
	if (field !== "createdAt") return text;
	const timestamp = Date.parse(text);
	return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function filterFor(query: MemberQuery) {
	const filterField = query.filterField;
	if (!filterField) return { sql: "", value: undefined };
	const field = fields[filterField];
	const operator = query.filterOperator ?? "eq";
	const input = query.filterValue;
	if (input === undefined) return null;
	if (operator === "in" || operator === "not_in") {
		const type = filterField === "createdAt" ? "timestamptz[]" : "text[]";
		const values = (Array.isArray(input) ? input : [input]).map((value) =>
			filterValue(value, filterField),
		);
		if (values.includes(null)) return null;
		return {
			sql: ` AND m.${field} ${operator === "in" ? "= ANY" : "<> ALL"}($4::${type})`,
			value: values,
		};
	}
	if (Array.isArray(input)) return null;
	const value = filterValue(input, filterField);
	if (value === null) return null;
	if (
		operator === "contains" ||
		operator === "starts_with" ||
		operator === "ends_with"
	) {
		if (filterField === "createdAt") return null;
		const prefix = operator === "starts_with" ? "" : "%";
		const suffix = operator === "ends_with" ? "" : "%";
		return { sql: ` AND m.${field} LIKE $4`, value: prefix + value + suffix };
	}
	return { sql: ` AND m.${field} ${comparators[operator]} $4`, value };
}

/** Preserve repeated filter values for the HTTP list endpoint. */
export function organizationMembersQuery(request: Request) {
	const params = new URL(request.url).searchParams;
	const values = params.getAll("filterValue");
	return {
		...Object.fromEntries(params),
		...(values.length > 1 && { filterValue: values }),
	};
}

/** List only the public member projection in the authorized organization. */
export async function listProjectOrganizationMembers(
	client: PoolClient,
	realm: ReturnType<typeof projectOrganizations>,
	principal: OrganizationSession,
	input: unknown,
) {
	const parsed = queryInput.safeParse(input);
	if (!parsed.success)
		return failure(400, "BAD_REQUEST", "Invalid organization member query.");
	const query = parsed.data;
	const slug = query.organizationSlug;
	const organization = slug ? await realm.organization(slug, "slug") : null;
	if (slug && !organization)
		return failure(400, "ORGANIZATION_NOT_FOUND", "Organization not found");
	const organizationId =
		organization?.id ||
		query.organizationId ||
		principal.session.activeOrganizationId;
	if (!organizationId)
		return failure(400, "NO_ACTIVE_ORGANIZATION", "No active organization");
	if (!(await realm.member(principal.user.id, organizationId, true)))
		return failure(
			403,
			"YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
			"You are not a member of this organization",
		);

	const filter = filterFor(query);
	if (!filter)
		return failure(400, "BAD_REQUEST", "Invalid organization member filter.");
	const sort = fields[query.sortBy ?? "createdAt"];
	const order = query.sortBy && query.sortDirection === "desc" ? "DESC" : "ASC";
	const { rows } = await client.query<{
		total: string;
		members: { createdAt: string }[];
	}>(
		`WITH matching AS MATERIALIZED (
			SELECT m.id, m."organizationId", m."userId", m.role, m."createdAt" FROM "member" m
			 WHERE m."organizationId" = $1${filter.sql}
		), selected AS (
			SELECT * FROM matching ORDER BY ${sort} ${order}, id ASC LIMIT $2 OFFSET $3
		), page AS (
			SELECT selected.*,
			 json_build_object('id', u.id, 'name', u.name, 'email', u.email, 'image', u.image) AS "user"
			 FROM selected JOIN "user" u ON u.id = selected."userId"
		)
		SELECT (SELECT count(*) FROM matching) AS total,
		 COALESCE((SELECT json_agg(page ORDER BY ${sort} ${order}, id ASC) FROM page), '[]') AS members`,
		[
			organizationId,
			query.limit || 100,
			query.offset || 0,
			...(filter.value === undefined ? [] : [filter.value]),
		],
	);
	return json({
		total: Number(rows[0]?.total ?? 0),
		members: (rows[0]?.members ?? []).map((member) => ({
			...member,
			createdAt: new Date(member.createdAt).toISOString(),
		})),
	});
}
