import * as z from "zod";
import {
	ownedSCIMError,
	ownedSCIMUserAttributeDescriptors,
	scimEnterpriseUserSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";

type PatchOp = "add" | "remove" | "replace";
type Document = Record<string, unknown>;
type Selection = { type?: string; primary?: boolean };
const extension = scimEnterpriseUserSchema.toLowerCase();
const core = `${scimUserSchema.toLowerCase()}:`;
const valuePath =
	/^([A-Za-z$][\w$-]*)\s*\[\s*type\s+eq\s+"([^"]+)"\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$/i;
const primaryPath =
	/^([A-Za-z$][\w$-]*)\s*\[\s*primary\s+eq\s+"?(true|false)"?\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$/i;
const managerSchema = z.object({
	value: z.string().trim().min(1).max(256).optional(),
	$ref: z.string().trim().min(1).max(2048).optional(),
	displayName: z.string().trim().min(1).max(1024).optional(),
});

function record(value: unknown): value is Document {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalid(detail: string): never {
	throw ownedSCIMError(400, detail, "invalidValue");
}

function invalidPath(path: string): never {
	throw ownedSCIMError(
		400,
		`User PATCH path ${path} is not supported`,
		"invalidPath",
	);
}

export function normalizeOwnedSCIMBoolean(value: unknown): unknown {
	if (typeof value !== "string") return value;
	if (value.toLowerCase() === "true") return true;
	if (value.toLowerCase() === "false") return false;
	return value;
}

function normalizeElement(value: unknown) {
	return record(value) && Object.hasOwn(value, "primary")
		? { ...value, primary: normalizeOwnedSCIMBoolean(value.primary) }
		: value;
}

function many(value: unknown) {
	return (Array.isArray(value) ? value : [value]).map(normalizeElement);
}

function setPrimary(values: unknown[], primary: number) {
	if (primary < 0) return values;
	return values.map((item, index) =>
		index !== primary && record(item) && item.primary === true
			? { ...item, primary: false }
			: item,
	);
}

function isPrimary(item: unknown) {
	return record(item) && item.primary === true;
}

function selected(item: unknown, selection: Selection) {
	if (selection.primary !== undefined)
		return record(item) && item.primary === selection.primary;
	if (selection.type)
		return (
			record(item) &&
			typeof item.type === "string" &&
			item.type.trim().toLowerCase() === selection.type
		);
	return true;
}

function applyList(
	container: Document,
	field: string,
	sub: string | undefined,
	selection: Selection,
	op: PatchOp,
	input: unknown,
	path: string,
) {
	const existing = container[field];
	const values: unknown[] = Array.isArray(existing) ? existing : [];
	const filtered =
		selection.type !== undefined || selection.primary !== undefined;
	if (!filtered && !sub) {
		if (op === "remove") {
			container[field] = undefined;
			return;
		}
		const additions = many(input);
		const base = op === "add" ? values : [];
		const primary = additions.findIndex(isPrimary);
		container[field] = setPrimary(
			[...base, ...additions],
			primary < 0 ? -1 : base.length + primary,
		);
		return;
	}
	const matched = values.map((item) => selected(item, selection));
	const index = matched.findIndex(Boolean);
	const value = sub === "primary" ? normalizeOwnedSCIMBoolean(input) : input;
	if (index < 0) {
		if (op === "remove") return;
		const additions = sub ? [{ [sub]: value }] : many(value);
		const withSelection = additions.map((item) =>
			record(item)
				? {
						...item,
						...(selection.type ? { type: selection.type } : {}),
						...(selection.primary === undefined
							? {}
							: { primary: selection.primary }),
						...(sub ? { [sub]: value } : {}),
					}
				: item,
		);
		const primary =
			sub && sub !== "primary" ? -1 : withSelection.findIndex(isPrimary);
		container[field] = setPrimary(
			[...values, ...withSelection],
			primary < 0 ? -1 : values.length + primary,
		);
		return;
	}
	if (!sub) {
		if (op === "remove") {
			const remaining = values.filter((_, position) => !matched[position]);
			container[field] = remaining.length ? remaining : undefined;
			return;
		}
		const replacements = many(value);
		const replacement = replacements[0];
		if (replacements.length !== 1 || !record(replacement))
			invalid(`User PATCH path ${path} requires one complex value`);
		const result = values.map((item, position) => {
			if (!matched[position]) return item;
			if (!record(item)) invalid(`${field} must contain objects`);
			return { ...item, ...replacement };
		});
		container[field] = setPrimary(
			result,
			replacement.primary === true ? index : -1,
		);
		return;
	}
	const result = values.map((item, position) => {
		if (!matched[position]) return item;
		if (!record(item)) invalid(`${field} must contain objects`);
		if (op !== "remove") return { ...item, [sub]: value };
		const { [sub]: _removed, ...remaining } = item;
		return remaining;
	});
	container[field] = setPrimary(
		result,
		op !== "remove" && sub === "primary" && value === true ? index : -1,
	);
}

function manager(input: unknown): Document | undefined {
	const value = Array.isArray(input) && input.length === 1 ? input[0] : input;
	const parsed = managerSchema.safeParse(
		typeof value === "string" ? { value } : value,
	);
	if (!parsed.success) invalid("manager must contain value or $ref");
	const { value: id, $ref } = parsed.data;
	return id || $ref
		? { ...(id ? { value: id } : {}), ...($ref ? { $ref } : {}) }
		: undefined;
}

function declareExtension(document: Document, present: boolean) {
	const schemas = Array.isArray(document.schemas)
		? document.schemas.filter((item) => item !== scimEnterpriseUserSchema)
		: [];
	document.schemas = present ? [...schemas, scimEnterpriseUserSchema] : schemas;
}

function replaceExtension(document: Document, op: PatchOp, value: unknown) {
	if (op === "remove") {
		document[scimEnterpriseUserSchema] = undefined;
		declareExtension(document, false);
		return;
	}
	if (!record(value)) invalid(`${scimEnterpriseUserSchema} must be an object`);
	const previous = document[scimEnterpriseUserSchema];
	const next = record(previous) ? { ...previous } : {};
	const fields = ownedSCIMUserAttributeDescriptors(true);
	for (const [key, field] of Object.entries(value)) {
		const descriptor = fields.find(
			(item) => item.name.toLowerCase() === key.toLowerCase(),
		);
		if (!descriptor) invalidPath(`${scimEnterpriseUserSchema}:${key}`);
		if (descriptor.name !== key) continue;
		if (key === "manager") {
			const change = manager(field);
			if (change)
				next.manager = {
					...(record(next.manager) ? next.manager : {}),
					...change,
				};
		} else next[key] = field;
	}
	document[scimEnterpriseUserSchema] = next;
	declareExtension(document, true);
}

/** Applies the SCIM discovery schema's mutable structured paths to the working profile. */
export function applyOwnedSCIMUserPatchField(
	document: Document,
	op: PatchOp,
	path: string,
	value: unknown,
) {
	const name = path.trim().toLowerCase();
	if (name === extension || name === "enterprise")
		return replaceExtension(document, op, value);
	const prefix = name.startsWith(`${extension}:`)
		? `${extension}:`
		: name.startsWith("enterprise.")
			? "enterprise."
			: "";
	const enterprise =
		Boolean(prefix) || name === "manager" || name.startsWith("manager.");
	const relative = prefix
		? name.slice(prefix.length)
		: name.startsWith(core)
			? name.slice(core.length)
			: name;
	const byType = valuePath.exec(relative);
	const byPrimary = byType ? null : primaryPath.exec(relative);
	const filter = byType ?? byPrimary;
	const segments = relative.split(".");
	if (!filter && (segments.length > 2 || segments.some((segment) => !segment)))
		invalidPath(path);
	const field = filter ? filter[1] : segments[0];
	const child = filter ? filter[3] : segments[1];
	const attribute = ownedSCIMUserAttributeDescriptors(enterprise).find(
		(item) => item.name.toLowerCase() === field,
	);
	const sub = attribute?.subAttributes?.find(
		(item) => item.name.toLowerCase() === child,
	);
	if (
		!attribute ||
		(child && !sub) ||
		(!enterprise && (attribute.name === "emails" || attribute.name === "name"))
	)
		invalidPath(path);
	if (attribute.mutability === "readOnly" || sub?.mutability === "readOnly")
		throw ownedSCIMError(400, `${path} is read-only`, "mutability");
	if (filter && !attribute.multiValued)
		throw ownedSCIMError(
			400,
			`User PATCH path ${path} is not a multi-valued attribute`,
			"invalidPath",
		);
	const previous = document[scimEnterpriseUserSchema];
	if (enterprise && op === "remove" && !record(previous)) return;
	const container = enterprise
		? record(previous)
			? { ...previous }
			: {}
		: document;
	const key = attribute.name;
	if (attribute.multiValued) {
		const selection: Selection = {
			type: byType?.[2]?.trim(),
			primary: byPrimary ? byPrimary[2] === "true" : undefined,
		};
		applyList(container, key, sub?.name, selection, op, value, path);
	} else if (sub) {
		const current = container[key];
		if (op === "remove") {
			if (!record(current)) return;
			const { [sub.name]: _removed, ...remaining } = current;
			container[key] = Object.keys(remaining).length ? remaining : undefined;
		} else
			container[key] = {
				...(record(current) ? current : {}),
				[sub.name]: value,
			};
	} else if (
		op === "remove" ||
		(enterprise && key === "manager" && value === "")
	)
		container[key] = undefined;
	else if (enterprise && key === "manager") {
		const change = manager(value);
		if (!change) invalid("manager must contain value or $ref");
		const current = container[key];
		container[key] = { ...(record(current) ? current : {}), ...change };
	} else container[key] = value;
	if (enterprise) {
		const remaining = Object.fromEntries(
			Object.entries(container).filter(([, item]) => item !== undefined),
		);
		const present = Object.keys(remaining).length > 0;
		document[scimEnterpriseUserSchema] = present ? remaining : undefined;
		declareExtension(document, present);
	}
}
