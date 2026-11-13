import * as z from "zod";
import {
	ownedSCIMError,
	scimGroupSchema,
} from "./owned-project-scim-discovery";
import type { parseOwnedSCIMPatch } from "./owned-project-scim-mutation";
import { ownedSCIMBodyValidation } from "./owned-project-scim-mutation";

export const ownedSCIMGroupMemberLimit = 1000;
const entraMarker =
	"http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
const groupSchema = z.object({
	schemas: z
		.array(z.literal(scimGroupSchema))
		.length(1, "schemas must contain only the core SCIM Group schema"),
	externalId: z.string().min(1).optional(),
	displayName: z.string().trim().min(1),
	members: z
		.array(
			z.object({
				value: z.string().min(1),
				type: z
					.string()
					.refine((type) => type.toLowerCase() === "user")
					.optional(),
			}),
		)
		.max(ownedSCIMGroupMemberLimit)
		.optional(),
});

export interface OwnedSCIMGroupInput {
	displayName: string;
	externalId: string | null;
	memberIds: string[];
}

function record(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalid(detail: string): never {
	throw ownedSCIMError(400, detail, "invalidValue");
}

function memberIds(values: readonly unknown[]) {
	const ids = new Set<string>();
	for (const value of values) {
		if (
			!record(value) ||
			typeof value.value !== "string" ||
			!value.value.trim() ||
			(typeof value.type === "string" && value.type.toLowerCase() !== "user")
		)
			invalid("Group members must reference a SCIM User");
		ids.add(value.value);
	}
	return [...ids];
}

export function assertOwnedSCIMGroupCardinality(size: number) {
	if (size > ownedSCIMGroupMemberLimit)
		invalid(
			`Groups cannot contain more than ${ownedSCIMGroupMemberLimit} direct members`,
		);
}

export function normalizeOwnedSCIMGroupMarker(
	input: unknown,
	create: boolean,
): unknown {
	let body = input;
	if (record(input)) {
		if (Object.hasOwn(input, entraMarker))
			invalid(
				"The Microsoft Entra Group compatibility schema cannot contain attributes",
			);
		if (create && Array.isArray(input.schemas)) {
			const schemas = input.schemas.filter((value) => value !== entraMarker);
			const markers = input.schemas.length - schemas.length;
			if (markers > 1)
				invalid(
					"The Microsoft Entra Group compatibility schema must not be duplicated",
				);
			if (markers === 1) body = { ...input, schemas };
		}
	}
	return body;
}

export function parseOwnedSCIMGroup(input: unknown): OwnedSCIMGroupInput {
	const parsed = groupSchema.safeParse(input);
	if (!parsed.success) invalid(ownedSCIMBodyValidation(parsed.error.issues));
	return {
		displayName: parsed.data.displayName,
		externalId: parsed.data.externalId ?? null,
		memberIds: memberIds(parsed.data.members ?? []),
	};
}

function patchMemberIds(value: unknown) {
	if (!Array.isArray(value)) invalid("members must be an array");
	assertOwnedSCIMGroupCardinality(value.length);
	return memberIds(value);
}

function pathName(value: string) {
	const path = value.trim();
	const prefix = `${scimGroupSchema}:`;
	return path.toLowerCase().startsWith(prefix.toLowerCase())
		? path.slice(prefix.length)
		: path;
}

function selectedMember(path: string): string | undefined {
	const quoted = /^members\s*\[\s*value\s+eq\s+("(?:\\.|[^"\\])*")\s*\]$/i.exec(
		path,
	)?.[1];
	if (!quoted) return;
	try {
		const value: unknown = JSON.parse(quoted);
		if (typeof value === "string" && value) return value;
	} catch {
		return;
	}
}

type PatchOperation = ReturnType<typeof parseOwnedSCIMPatch>[number];

export function patchOwnedSCIMGroup(
	group: { id: string; displayName: string; externalId: string | null },
	currentMembers: readonly string[],
	operations: readonly PatchOperation[],
) {
	const members = new Set(currentMembers);
	const addedByPatch = new Set<string>();
	const targeted = new Set<string>();
	let incremental = true;
	let displayName = group.displayName;
	let externalId = group.externalId;

	function apply(op: PatchOperation["op"], rawPath: string, value: unknown) {
		const path = pathName(rawPath);
		const key = path.toLowerCase();
		if (key === "members") {
			if (op === "replace" || value === undefined) incremental = false;
			if (op === "remove" && value === undefined) {
				members.clear();
				return;
			}
			if (op === "replace") members.clear();
			for (const id of patchMemberIds(value)) {
				targeted.add(id);
				if (op === "remove") members.delete(id);
				else {
					members.add(id);
					addedByPatch.add(id);
				}
			}
			return;
		}
		const member = op === "remove" ? selectedMember(path) : undefined;
		if (member) {
			targeted.add(member);
			members.delete(member);
			return;
		}
		incremental = false;
		if (
			key === "id" ||
			key === "schemas" ||
			key === "meta" ||
			key.startsWith("meta.")
		)
			throw ownedSCIMError(400, `${rawPath} is read-only`, "mutability");
		if (key !== "displayname" && key !== "externalid")
			throw ownedSCIMError(400, "Unsupported Group PATCH path", "invalidPath");
		if (op === "remove") {
			if (key === "displayname")
				throw ownedSCIMError(
					400,
					"displayName is required and cannot be removed",
					"mutability",
				);
			externalId = null;
			return;
		}
		const scalar =
			Array.isArray(value) && value.length === 1 ? value[0] : value;
		if (typeof scalar !== "string" || !scalar.trim())
			invalid(
				`${key === "displayname" ? "displayName" : "externalId"} must be a non-empty string`,
			);
		if (key === "displayname") displayName = scalar.trim();
		else externalId = scalar.trim();
	}

	for (const operation of operations) {
		if (operation.path?.trim()) {
			apply(operation.op, operation.path, operation.value);
			continue;
		}
		incremental = false;
		if (operation.op === "remove")
			throw ownedSCIMError(
				400,
				"A pathless remove operation has no target",
				"noTarget",
			);
		if (!record(operation.value))
			invalid("A pathless Group PATCH value must be an object");
		for (const [attribute, value] of Object.entries(operation.value)) {
			const key = attribute.toLowerCase();
			if (key === "id") {
				if (value !== group.id)
					throw ownedSCIMError(
						400,
						"A Group PATCH cannot change id",
						"mutability",
					);
			} else if (key !== "schemas" && key !== "meta") {
				if (
					key !== "members" &&
					pathName(attribute).toLowerCase() === "members"
				)
					throw ownedSCIMError(
						400,
						"Unsupported Group PATCH path",
						"invalidPath",
					);
				apply(operation.op, attribute, value);
			}
		}
	}
	assertOwnedSCIMGroupCardinality(members.size);
	return {
		displayName,
		externalId,
		memberIds: [...members],
		validateIds: incremental ? [...addedByPatch] : [...members],
		targets: incremental
			? [...targeted]
			: [...new Set([...currentMembers, ...members])],
	};
}
