import type { PoolClient } from "pg";
import * as z from "zod";
import type { ProjectUser } from "./owned-project-engine-store";
import { projectUserResponse } from "./owned-project-engine-store";

const textFields = [
	"id",
	"name",
	"email",
	"image",
	"role",
	"banReason",
	"username",
	"displayUsername",
] as const;
const dateFields = ["createdAt", "updatedAt", "banExpires"] as const;
const booleanFields = [
	"emailVerified",
	"banned",
	"twoFactorEnabled",
	"isAnonymous",
] as const;
type ColumnType = "text" | "date" | "boolean" | "json";
const columns = new Map<string, ColumnType>([
	...textFields.map((key) => [key, "text"] as const),
	...dateFields.map((key) => [key, "date"] as const),
	...booleanFields.map((key) => [key, "boolean"] as const),
	["publicMetadata", "json"] as const,
]);
const projection = [...columns.keys()]
	.map((column) => `"${column}"`)
	.join(", ");
const patterns = ["contains", "starts_with", "ends_with"] as const;
const comparisons = {
	eq: "=",
	ne: "<>",
	gt: ">",
	gte: ">=",
	lt: "<",
	lte: "<=",
} as const;

export const realmAdminListQuery = z.object({
	searchValue: z.string().optional(),
	searchField: z.enum(["email", "name"]).optional(),
	searchOperator: z.enum(patterns).optional(),
	limit: z.string().optional(),
	offset: z.string().optional(),
	sortBy: z.string().optional(),
	sortDirection: z.enum(["asc", "desc"]).optional(),
	filterField: z.string().optional(),
	filterValue: z.union([z.string(), z.array(z.string())]).optional(),
	filterOperator: z
		.enum(["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", ...patterns])
		.optional(),
});

type DirectoryQuery = z.infer<typeof realmAdminListQuery>;
type DirectoryRow = ProjectUser & {
	banReason: string | null;
	banExpires: Date | null;
};
const empty = { users: [], total: 0 };

function publicUser(user: DirectoryRow) {
	return {
		...projectUserResponse(user),
		banReason: user.banReason,
		banExpires: user.banExpires?.toISOString() ?? null,
	};
}

export async function readRealmAdminUser(client: PoolClient, userId: string) {
	const {
		rows: [user],
	} = await client.query<DirectoryRow>(
		`SELECT ${projection} FROM "user" WHERE id=$1`,
		[userId],
	);
	return user ? publicUser(user) : null;
}

function pattern(operator: (typeof patterns)[number], value: string) {
	return `${operator === "starts_with" ? "" : "%"}${value}${operator === "ends_with" ? "" : "%"}`;
}

function valueMatchesType(value: string, type: ColumnType) {
	if (value.includes("\0")) return false;
	if (type === "boolean")
		return /^(?:true|false|t|f|yes|no|y|n|on|off|1|0)$/i.test(value.trim());
	if (type === "date") return Number.isFinite(Date.parse(value));
	if (type === "json") {
		try {
			JSON.parse(value);
		} catch {
			return false;
		}
	}
	return true;
}

export async function listRealmAdminUsers(
	client: PoolClient,
	input: DirectoryQuery,
) {
	const limit = Number(input.limit) || undefined;
	const offset = Number(input.offset) || undefined;
	if (
		[limit, offset].some(
			(number) =>
				number !== undefined && (!Number.isSafeInteger(number) || number < 0),
		)
	)
		return empty;
	if (input.sortBy && !columns.has(input.sortBy)) return empty;

	const terms: string[] = [];
	const parameters: (string | string[] | number)[] = [];
	const bind = (value: (typeof parameters)[number]) =>
		`$${parameters.push(value)}`;
	if (input.searchValue) {
		if (input.searchValue.includes("\0")) return empty;
		terms.push(
			`"${input.searchField ?? "email"}" LIKE ${bind(pattern(input.searchOperator ?? "contains", input.searchValue))}`,
		);
	}
	if (input.filterValue !== undefined) {
		const field = input.filterField || "email";
		const type = columns.get(field);
		if (!type) return empty;
		const operator = input.filterOperator ?? "eq";
		const values = [input.filterValue].flat();
		if (operator === "in" || operator === "not_in") {
			if (
				!values.length ||
				!values.every((value) => valueMatchesType(value, type))
			)
				return empty;
			terms.push(
				`"${field}" ${operator === "in" ? "= ANY" : "<> ALL"}(${bind(values)})`,
			);
		} else if (
			operator === "contains" ||
			operator === "starts_with" ||
			operator === "ends_with"
		) {
			if (type !== "text" || values.some((value) => value.includes("\0")))
				return empty;
			terms.push(
				`"${field}" LIKE ${bind(pattern(operator, String(input.filterValue)))}`,
			);
		} else {
			if (
				typeof input.filterValue !== "string" ||
				!valueMatchesType(input.filterValue, type)
			)
				return empty;
			terms.push(
				`"${field}" ${comparisons[operator]} ${bind(input.filterValue)}`,
			);
		}
	}
	const where = terms.length ? ` WHERE ${terms.join(" AND ")}` : "";
	const total = await client.query<{ total: string }>(
		`SELECT count(*) AS total FROM "user"${where}`,
		[...parameters],
	);
	const sort = input.sortBy
		? ` ORDER BY "${input.sortBy}" ${input.sortDirection === "desc" ? "DESC" : "ASC"}`
		: "";
	const pageLimit = limit === undefined ? "" : ` LIMIT ${bind(limit)}`;
	const pageOffset = offset === undefined ? "" : ` OFFSET ${bind(offset)}`;
	const page = await client.query<DirectoryRow>(
		`SELECT ${projection} FROM "user"${where}${sort}${pageLimit}${pageOffset}`,
		parameters,
	);
	return {
		users: page.rows.map(publicUser),
		total: Number(total.rows[0]?.total ?? 0),
		limit,
		offset,
	};
}
