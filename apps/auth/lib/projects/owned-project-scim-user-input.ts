import * as z from "zod";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";
import type { parseOwnedSCIMPatch } from "./owned-project-scim-mutation";
import { ownedSCIMBodyValidation } from "./owned-project-scim-mutation";
import type { OwnedSCIMUserRow } from "./owned-project-scim-resources";
import {
	ownedSCIMStoredUserAttributes,
	readOwnedSCIMUserAttributes,
} from "./owned-project-scim-resources-user";
import {
	applyOwnedSCIMUserPatchField,
	normalizeOwnedSCIMBoolean,
} from "./owned-project-scim-user-patch-fields";

const short = z.string().trim().min(1).max(256);
const long = z.string().trim().min(1).max(1024);
const nameFields = [
	"formatted",
	"givenName",
	"familyName",
	"middleName",
	"honorificPrefix",
	"honorificSuffix",
] as const;
const optionalScalars = [
	"title",
	"userType",
	"preferredLanguage",
	"locale",
	"timezone",
] as const;
const structuredFields = [
	"emails",
	"phoneNumbers",
	"addresses",
	"roles",
	"entitlements",
] as const;
const email = z.email().max(254);
const inputEmail = z.object({
	value: email,
	type: short.optional(),
	primary: z.boolean().optional(),
});
const basic = z.object({
	userName: z.string().trim().min(1).max(512),
	externalId: long.optional(),
	displayName: long.optional(),
	active: z.boolean().optional(),
	name: z
		.object({
			formatted: long.optional(),
			givenName: short.optional(),
			familyName: short.optional(),
			middleName: short.optional(),
			honorificPrefix: short.optional(),
			honorificSuffix: short.optional(),
		})
		.optional(),
	emails: z.array(inputEmail).max(20).optional(),
});

function record(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalar(value: unknown) {
	return Array.isArray(value) && value.length === 1 ? value[0] : value;
}

function primaryValues(value: unknown) {
	return Array.isArray(value)
		? value.map((entry: unknown) =>
				record(entry) && Object.hasOwn(entry, "primary")
					? { ...entry, primary: normalizeOwnedSCIMBoolean(entry.primary) }
					: entry,
			)
		: value;
}

function invalid(detail: string): never {
	throw ownedSCIMError(400, detail, "invalidValue");
}

type EmailValue = z.output<typeof inputEmail>;

function normalizeEmail(value: EmailValue) {
	return {
		value: value.value.trim().toLowerCase(),
		...(value.type ? { type: value.type.trim().toLowerCase() } : {}),
		primary: value.primary === true,
	};
}

function emailTuple(value: EmailValue) {
	return JSON.stringify([value.type ?? null, value.value]);
}

function normalizeEmailSet(input: readonly EmailValue[], prefix = "") {
	const values = input.map(normalizeEmail);
	if (values.filter((value) => value.primary).length > 1)
		invalid(`${prefix}emails cannot contain multiple primary values`);
	if (new Set(values.map(emailTuple)).size !== values.length)
		invalid(`${prefix}emails cannot contain duplicate type and value pairs`);
	const types = values.flatMap((value) => (value.type ? [value.type] : []));
	if (new Set(types).size !== types.length)
		invalid(`${prefix}emails cannot contain duplicate defined types`);
	const explicit = values.findIndex((value) => value.primary);
	const work = values.findIndex((value) => value.type === "work");
	const primary = explicit >= 0 ? explicit : work >= 0 ? work : 0;
	return values.map((value, index) => ({
		...value,
		primary: index === primary,
	}));
}

const patchEmails = z.array(inputEmail).min(1).max(20);

function readPatchEmails(value: unknown) {
	const parsed = patchEmails.safeParse(primaryValues(value));
	if (!parsed.success)
		invalid("emails must contain between 1 and 20 valid emails");
	return parsed.data;
}

/** Converts SCIM User input into the canonical fields used by the existing rows and read path. */
export function parseOwnedSCIMUser(input: unknown, patch = false) {
	if (!record(input)) invalid("[body] Invalid input: expected object");
	function schemaError(issues: readonly z.core.$ZodIssue[]) {
		const issue = issues[0];
		return patch && issue
			? `${issue.path.join(".") || "User"}: ${issue.message}`
			: ownedSCIMBodyValidation(issues);
	}
	const normalized = {
		...input,
		active: normalizeOwnedSCIMBoolean(input.active),
		emails: primaryValues(input.emails),
	};
	const data = basic.safeParse(normalized);
	if (!data.success) invalid(schemaError(data.error.issues));
	const { userName, externalId, name, displayName, active } = data.data;
	const values = data.data.emails ?? [];
	if (!values.length && !email.safeParse(userName).success)
		invalid(
			"[body.emails] emails must contain an email when userName is not an email address",
		);
	if (!values.length)
		values.push({ value: userName.toLowerCase(), primary: true });
	const emails = normalizeEmailSet(values, patch ? "" : "[body.emails] ");
	const primaryEmail = emails.find((value) => value.primary)!.value;
	const formatted =
		name?.formatted ??
		displayName ??
		([name?.givenName, name?.familyName].filter(Boolean).join(" ") ||
			primaryEmail);
	const enterpriseValue = input[scimEnterpriseUserSchema];
	const enterprise = record(enterpriseValue)
		? { ...enterpriseValue }
		: enterpriseValue;
	if (record(enterprise)) {
		const manager = scalar(enterprise.manager);
		if (typeof manager === "string") enterprise.manager = { value: manager };
		else if (record(manager))
			enterprise.manager =
				manager.value === undefined && manager.$ref === undefined
					? undefined
					: manager;
	}
	const attrs = ownedSCIMStoredUserAttributes.safeParse({
		schemas: input.schemas,
		name: { ...name, formatted },
		emails,
		...Object.fromEntries(
			optionalScalars.map((field) => [field, scalar(input[field])]),
		),
		...Object.fromEntries(
			structuredFields
				.filter((field) => field !== "emails")
				.map((field) => [field, primaryValues(input[field])]),
		),
		enterprise,
	});
	if (!attrs.success) invalid(schemaError(attrs.error.issues));
	const serializedAttributes = JSON.stringify(attrs.data);
	if (serializedAttributes.length > 65_535)
		invalid("SCIM User attributes exceed the supported serialized size");
	return {
		userName,
		externalId: externalId ?? null,
		active: active !== false,
		displayName: displayName ?? formatted,
		primaryEmail,
		attributes: attrs.data,
		serializedAttributes,
	};
}

export type OwnedSCIMUserInput = ReturnType<typeof parseOwnedSCIMUser>;

/** Applies ordered SCIM User operations to a canonical working profile. */
export function patchOwnedSCIMUser(
	row: OwnedSCIMUserRow,
	operations: ReturnType<typeof parseOwnedSCIMPatch>,
) {
	const current = readOwnedSCIMUserAttributes(row);
	const document: Record<string, unknown> = {
		...current,
		userName: row.userName,
		externalId: row.externalId ?? undefined,
		displayName: row.displayName,
		active: row.active,
	};
	let name = { ...current.name };
	let emails = [...current.emails];
	function setEmails(values: readonly EmailValue[]) {
		emails = normalizeEmailSet(readPatchEmails(values));
	}
	function addEmails(value: unknown) {
		const additions = new Map<string, ReturnType<typeof normalizeEmail>>();
		for (const candidate of readPatchEmails(value).map(normalizeEmail)) {
			const key = emailTuple(candidate);
			const existing = additions.get(key);
			if (!existing || candidate.primary) additions.set(key, candidate);
		}
		if ([...additions.values()].filter((item) => item.primary).length > 1)
			invalid("emails cannot contain multiple primary values");
		const existing = new Set(emails.map(emailTuple));
		const next = [...additions].flatMap(([key, candidate]) =>
			existing.has(key) ? [] : [candidate],
		);
		if (next.length)
			setEmails([
				...(next.some((item) => item.primary)
					? emails.map((item) => ({ ...item, primary: false }))
					: emails),
				...next,
			]);
	}
	const core = `${scimUserSchema.toLowerCase()}:`;
	const setFormatted = (value: string) => {
		if (document.displayName === name.formatted) document.displayName = value;
		name.formatted = value;
	};
	function text(value: unknown, label: string, schema = long) {
		const parsed = schema.safeParse(scalar(value));
		if (!parsed.success) invalid(`${label} must be a non-empty string`);
		return parsed.data;
	}
	function changeName(
		field: (typeof nameFields)[number],
		remove: boolean,
		value: unknown,
	) {
		if (field === "formatted") {
			setFormatted(
				remove
					? [name.givenName, name.familyName].filter(Boolean).join(" ") ||
							String(document.displayName)
					: text(value, "name.formatted"),
			);
		} else if (remove) name[field] = undefined;
		else name[field] = text(value, `name.${field}`, short);
	}
	function apply(
		op: "add" | "remove" | "replace",
		rawPath: string,
		value: unknown,
	) {
		const path = rawPath.trim().toLowerCase();
		const relative = path.startsWith(core) ? path.slice(core.length) : path;
		if (
			["id", "schemas", "meta"].includes(relative) ||
			relative.startsWith("meta.")
		)
			throw ownedSCIMError(400, `${rawPath} is read-only`, "mutability");
		if (relative === "username") {
			if (op === "remove")
				throw ownedSCIMError(400, "userName is read-only", "mutability");
			document.userName = text(value, "userName");
			return;
		}
		if (relative === "externalid" || relative === "displayname") {
			const key = relative === "externalid" ? "externalId" : "displayName";
			document[key] =
				op === "remove"
					? key === "displayName"
						? name.formatted
						: undefined
					: text(value, key);
			return;
		}
		if (relative === "active") {
			const normalized =
				op === "remove" ? true : scalar(normalizeOwnedSCIMBoolean(value));
			if (typeof normalized !== "boolean") invalid("active must be a boolean");
			document.active = normalized;
			return;
		}
		if (relative === "name") {
			if (op === "remove") {
				setFormatted(String(document.displayName));
				name = { formatted: name.formatted };
				return;
			}
			const item = value;
			if (!record(item)) invalid("name must be an object");
			for (const [key, value] of Object.entries(item)) {
				const field = nameFields.find(
					(field) => field.toLowerCase() === key.toLowerCase(),
				);
				if (!field)
					throw ownedSCIMError(
						400,
						`User attribute name.${key} is not supported`,
						"invalidPath",
					);
				changeName(field, false, value);
			}
			return;
		}
		const nameField = nameFields.find(
			(field) => relative === `name.${field.toLowerCase()}`,
		);
		if (nameField) {
			changeName(nameField, op === "remove", value);
			return;
		}
		const selectedEmail =
			/^emails\s*\[\s*type\s+eq\s+"([^"]+)"\s*\]\s*\.\s*value$/i
				.exec(relative)?.[1]
				?.trim();
		const primaryEmail =
			/^emails\s*\[\s*primary\s+eq\s+"?true"?\s*\]\s*\.\s*value$/i.test(
				relative,
			);
		if (selectedEmail || primaryEmail || relative === "emails.value") {
			const matches = (item: { type?: string; primary: boolean }) =>
				selectedEmail
					? item.type === selectedEmail
					: primaryEmail
						? item.primary
						: true;
			if (op === "remove") {
				if (!selectedEmail) invalid("emails.value cannot be removed");
				const remaining = emails.filter((item) => !matches(item));
				if (remaining.length !== emails.length) setEmails(remaining);
				return;
			}
			const parsed = email.safeParse(value);
			if (!parsed.success) invalid("emails.value must be an email");
			if (selectedEmail && !emails.some(matches))
				setEmails([
					...emails,
					{
						value: parsed.data,
						type: selectedEmail,
						primary: false,
					},
				]);
			else
				setEmails(
					emails.map((item) =>
						matches(item) ? { ...item, value: parsed.data } : item,
					),
				);
			return;
		}
		if (relative === "emails") {
			if (op === "remove") invalid("emails cannot be removed");
			if (op === "add") addEmails(value);
			else setEmails(readPatchEmails(value));
			return;
		}
		applyOwnedSCIMUserPatchField(document, op, rawPath, value);
	}
	for (const operation of operations) {
		if (operation.path?.trim())
			apply(operation.op, operation.path, operation.value);
		else {
			if (operation.op === "remove")
				throw ownedSCIMError(
					400,
					"A remove User PATCH operation requires a path",
					"noTarget",
				);
			if (!record(operation.value))
				invalid("A pathless User PATCH value must be an object");
			for (const [key, value] of Object.entries(operation.value))
				apply(operation.op, key, value);
		}
	}
	return parseOwnedSCIMUser({ ...document, name, emails }, true);
}
