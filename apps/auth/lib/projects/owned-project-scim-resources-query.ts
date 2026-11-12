import * as z from "zod";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
	scimGroupSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";

export type SCIMResource = "User" | "Group";
type SCIMFilterAttribute =
	| "id"
	| "externalId"
	| "userName"
	| "displayName"
	| "emails.value"
	| "emails.work.value";

const projectionSchema = z.object({
	attributes: z.union([z.string(), z.array(z.string())]).optional(),
	excludedAttributes: z.union([z.string(), z.array(z.string())]).optional(),
});
const collectionSchema = projectionSchema.extend({
	filter: z.string().optional(),
	startIndex: z.union([z.string(), z.number()]).optional(),
	count: z.union([z.string(), z.number()]).optional(),
});

type ResourceQuery = z.infer<typeof collectionSchema>;
export type AttributeProjection =
	| { mode: "default" }
	| {
			mode: "include" | "exclude";
			paths: string[];
	  };

export function readSCIMQuery(
	params: URLSearchParams,
	collection: boolean,
): ResourceQuery {
	const entries = Object.fromEntries(
		["attributes", "excludedAttributes", "filter", "startIndex", "count"].map(
			(key) => {
				const values = params.getAll(key);
				return [key, values.length > 1 ? values : values[0]];
			},
		),
	);
	const parsed = (collection ? collectionSchema : projectionSchema).safeParse(
		entries,
	);
	if (!parsed.success)
		throw ownedSCIMError(
			400,
			parsed.error.issues
				.map((issue) => `[query.${issue.path.join(".")}] ${issue.message}`)
				.join("; "),
			"invalidValue",
		);
	return parsed.data;
}

function stripCorePrefix(resource: SCIMResource, attribute: string) {
	const prefix = `${resource === "User" ? scimUserSchema : scimGroupSchema}:`;
	return attribute.toLowerCase().startsWith(prefix.toLowerCase())
		? attribute.slice(prefix.length)
		: attribute;
}

function projectionPath(resource: SCIMResource, attribute: string) {
	const normalized = attribute.toLowerCase();
	const extension = scimEnterpriseUserSchema.toLowerCase();
	if (resource === "User") {
		if (normalized.startsWith(`${extension}:`))
			return `${extension}.${normalized.slice(extension.length + 1)}`;
		if (normalized === "manager" || normalized.startsWith("manager."))
			return `${extension}.${normalized}`;
	}
	return stripCorePrefix(resource, attribute).toLowerCase();
}

export function readAttributeProjection(
	resource: SCIMResource,
	query: ResourceQuery,
): AttributeProjection {
	function normalize(key: "attributes" | "excludedAttributes") {
		const input = query[key];
		const values = typeof input === "string" ? [input] : (input ?? []);
		const paths = new Set<string>();
		for (const value of values) {
			if (!value.trim()) continue;
			for (const part of value.split(",")) {
				const attribute = part.trim();
				if (!attribute || !/^\S+$/.test(attribute))
					throw ownedSCIMError(
						400,
						`${key} must be a comma-separated list of attribute paths`,
						"invalidValue",
					);
				paths.add(projectionPath(resource, attribute));
			}
		}
		return [...paths];
	}

	const included = normalize("attributes");
	const excluded = normalize("excludedAttributes");
	if (included.length && excluded.length)
		throw ownedSCIMError(
			400,
			"attributes and excludedAttributes cannot be used together",
			"invalidValue",
		);
	if (included.length) return { mode: "include", paths: included };
	if (excluded.length) return { mode: "exclude", paths: excluded };
	return { mode: "default" };
}

function filterAttribute(
	resource: SCIMResource,
	attribute: string,
): SCIMFilterAttribute | undefined {
	const name = stripCorePrefix(resource, attribute);
	if (/^emails\[\s*type\s+eq\s+"work"\s*\]\.value$/i.test(name))
		return resource === "User" ? "emails.work.value" : undefined;
	switch (name.toLowerCase()) {
		case "id":
			return "id";
		case "externalid":
			return "externalId";
		case "username":
			return resource === "User" ? "userName" : undefined;
		case "emails.value":
			return resource === "User" ? "emails.value" : undefined;
		case "displayname":
			return resource === "Group" ? "displayName" : undefined;
	}
}

function invalidFilter(detail: string): never {
	throw ownedSCIMError(400, detail, "invalidFilter");
}

/** Finds operators outside quoted JSON strings and SCIM value paths. */
function filterWords(filter: string) {
	const words: { start: number; end: number; value: string }[] = [];
	let brackets = 0;
	let quoted = false;
	for (let index = 0; index < filter.length; index++) {
		const character = filter[index];
		if (quoted && character === "\\") {
			index++;
			continue;
		}
		if (character === '"') quoted = !quoted;
		if (quoted) continue;
		if (character === "[") brackets++;
		if (character === "]") brackets--;
		if (brackets < 0)
			invalidFilter("filter contains malformed quotes or brackets");
		if (brackets || !character || !/[A-Za-z]/.test(character)) continue;
		const start = index;
		while (/[A-Za-z]/.test(filter[index + 1] ?? "")) index++;
		const end = index + 1;
		if (/\s/.test(filter[start - 1] ?? "") && /\s/.test(filter[end] ?? ""))
			words.push({ start, end, value: filter.slice(start, end) });
	}
	if (quoted || brackets)
		invalidFilter("filter contains malformed quotes or brackets");
	return words;
}

function equalityFilters(resource: SCIMResource, filter: string | undefined) {
	if (!filter?.trim()) return [];
	const conjunctions = filterWords(filter).filter(
		(word) => word.value.toLowerCase() === "and",
	);
	let start = 0;
	const expressions = conjunctions.map((word) => {
		const expression = filter.slice(start, word.start).trim();
		if (!expression) invalidFilter("filter contains an invalid conjunction");
		start = word.end;
		return expression;
	});
	const final = filter.slice(start).trim();
	if (!final) invalidFilter("filter contains an invalid conjunction");
	if (expressions.length >= 10)
		invalidFilter("filter supports at most 10 equality expressions");
	expressions.push(final);
	return expressions.map((expression) => {
		const operator = filterWords(expression)[0];
		if (!operator)
			invalidFilter('filter must use the form attribute eq "value"');
		if (operator.value.toLowerCase() !== "eq")
			invalidFilter(`filter operator ${operator.value} is not supported`);
		const raw = expression.slice(0, operator.start).trim();
		const attribute = filterAttribute(resource, raw);
		if (!attribute)
			invalidFilter(`filter attribute ${raw} is not supported for ${resource}`);
		let value: unknown;
		try {
			value = JSON.parse(expression.slice(operator.end).trim());
		} catch {
			invalidFilter("filter equality value must be a valid quoted JSON string");
		}
		if (typeof value !== "string")
			invalidFilter("filter equality value must be a quoted string");
		return { attribute, value };
	});
}

export function readSCIMCollectionQuery(
	resource: SCIMResource,
	query: ResourceQuery,
) {
	function integer(key: "count" | "startIndex", fallback: number) {
		const input = query[key];
		if (input === undefined) return fallback;
		const value =
			typeof input === "number"
				? input
				: /^-?\d+$/.test(input.trim())
					? Number(input)
					: NaN;
		if (!Number.isSafeInteger(value))
			throw ownedSCIMError(400, `${key} must be an integer`, "invalidValue");
		return value;
	}
	const startIndex = Math.max(integer("startIndex", 1), 1);
	const count = Math.min(Math.max(integer("count", 100), 0), 100);
	return {
		startIndex,
		count,
		filters: equalityFilters(resource, query.filter),
		projection: readAttributeProjection(resource, query),
	};
}

export type SCIMFilter = ReturnType<
	typeof readSCIMCollectionQuery
>["filters"][number];

function projectValue(
	value: unknown,
	paths: readonly string[][],
	include: boolean,
): unknown {
	if (paths.some((path) => path.length === 0))
		return include ? value : undefined;
	if (paths.length === 0) return include ? undefined : value;
	if (Array.isArray(value)) {
		const projected = value
			.map((item: unknown) => projectValue(item, paths, include))
			.filter((item) => item !== undefined);
		return include && projected.length === 0 ? undefined : projected;
	}
	if (!value || typeof value !== "object") return include ? undefined : value;
	const projected = Object.fromEntries(
		Object.entries(value).flatMap(([key, child]) => {
			const name = key.toLowerCase();
			const children = paths.flatMap((path) =>
				path[0] === name ? [path.slice(1)] : [],
			);
			const result = projectValue(child, children, include);
			return result === undefined ? [] : [[key, result]];
		}),
	);
	return include && Object.keys(projected).length === 0 ? undefined : projected;
}

export function projectSCIMResource<
	Resource extends { id: string; schemas: string[] },
>(resource: Resource, projection: AttributeProjection): object {
	if (projection.mode === "default") return resource;
	const projected: Record<string, unknown> = {
		schemas: resource.schemas,
		id: resource.id,
	};
	for (const [key, value] of Object.entries(resource)) {
		if (key === "schemas" || key === "id") continue;
		const name = key.toLowerCase();
		const paths = projection.paths.flatMap((path) => {
			if (path === name) return [[]];
			if (!path.startsWith(`${name}.`)) return [];
			const suffix = path.slice(name.length + 1);
			return [suffix ? suffix.split(".") : []];
		});
		const selected = projectValue(value, paths, projection.mode === "include");
		if (selected !== undefined) projected[key] = selected;
	}
	return projected;
}
