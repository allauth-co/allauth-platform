import * as z from "zod";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";
import type { OwnedSCIMUserRow } from "./owned-project-scim-resources";
import {
	ownedSCIMStoredUserAttributes,
	readOwnedSCIMUserAttributes,
} from "./owned-project-scim-resources-user";

const patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
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
const patch = z.object({
	schemas: z
		.array(z.literal(patchSchema))
		.length(1, "schemas must contain only the PatchOp schema"),
	Operations: z.array(
		z.object({
			op: z
				.string()
				.toLowerCase()
				.default("replace")
				.pipe(z.enum(["replace", "add", "remove"])),
			path: z.string().optional(),
			value: z.unknown().optional(),
		}),
	),
});

function record(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalar(value: unknown) {
	return Array.isArray(value) && value.length === 1 ? value[0] : value;
}

function boolean(value: unknown) {
	if (typeof value !== "string") return value;
	if (value.toLowerCase() === "true") return true;
	if (value.toLowerCase() === "false") return false;
	return value;
}

function primaryValues(value: unknown) {
	return Array.isArray(value)
		? value.map((entry: unknown) =>
				record(entry) && Object.hasOwn(entry, "primary")
					? { ...entry, primary: boolean(entry.primary) }
					: entry,
			)
		: value;
}

function invalid(detail: string): never {
	throw ownedSCIMError(400, detail, "invalidValue");
}

function bodyValidation(issues: readonly z.core.$ZodIssue[]) {
	return issues
		.map(
			(issue) =>
				`[body${issue.path.length ? `.${issue.path.join(".")}` : ""}] ${issue.message}`,
		)
		.join("; ");
}

/** Converts SCIM User input into the canonical fields used by the existing rows and read path. */
export function parseOwnedSCIMUser(input: unknown) {
	if (!record(input)) invalid("[body] Invalid input: expected object");
	const normalized = {
		...input,
		active: boolean(input.active),
		emails: primaryValues(input.emails),
	};
	const data = basic.safeParse(normalized);
	if (!data.success) invalid(bodyValidation(data.error.issues));
	const { userName, externalId, name, displayName, active } = data.data;
	const values = (data.data.emails ?? []).map((value) => ({
		...value,
		value: value.value.toLowerCase(),
		...(value.type ? { type: value.type.toLowerCase() } : {}),
	}));
	if (values.filter((value) => value.primary === true).length > 1)
		invalid("[body.emails] emails cannot contain multiple primary values");
	if (!values.length && !email.safeParse(userName).success)
		invalid(
			"[body.emails] emails must contain an email when userName is not an email address",
		);
	if (!values.length)
		values.push({ value: userName.toLowerCase(), primary: true });
	const explicit = values.findIndex((value) => value.primary);
	const work = values.findIndex((value) => value.type === "work");
	const primary = explicit >= 0 ? explicit : work >= 0 ? work : 0;
	const emails = values.map((value, index) => ({
		...value,
		primary: index === primary,
	}));
	const primaryEmail = emails[primary]!.value;
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
	if (!attrs.success) invalid(bodyValidation(attrs.error.issues));
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

export function parseOwnedSCIMUserPatch(input: unknown) {
	const result = patch.safeParse(input);
	if (!result.success) invalid(bodyValidation(result.error.issues));
	return result.data.Operations;
}

/** Applies ordered basic profile, email, identifier and lifecycle PATCH operations. */
export function patchOwnedSCIMUser(
	row: OwnedSCIMUserRow,
	operations: ReturnType<typeof parseOwnedSCIMUserPatch>,
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
			const normalized = op === "remove" ? true : scalar(boolean(value));
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
			const item = scalar(value);
			if (!record(item)) invalid("name must be an object");
			for (const [key, value] of Object.entries(item)) {
				const field = nameFields.find(
					(field) => field.toLowerCase() === key.toLowerCase(),
				);
				if (field) changeName(field, false, value);
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
				emails = emails.filter((item) => !matches(item));
				return;
			}
			const parsed = email.safeParse(scalar(value));
			if (!parsed.success) invalid("Email value must be a valid email address");
			if (selectedEmail && !emails.some(matches))
				emails.push({
					value: parsed.data,
					type: selectedEmail,
					primary: false,
				});
			else
				emails = emails.map((item) =>
					matches(item) ? { ...item, value: parsed.data } : item,
				);
			return;
		}
		if (relative === "emails" && op !== "add") {
			if (op === "remove") emails = [];
			else {
				const parsed = z.array(inputEmail).safeParse(primaryValues(value));
				if (!parsed.success)
					invalid("emails must be an array of valid email values");
				emails = parsed.data.map((item) => ({
					...item,
					primary: item.primary ?? false,
				}));
			}
			return;
		}
		const field = [
			...optionalScalars,
			...structuredFields.filter((item) => item !== "emails"),
		].find((item) => item.toLowerCase() === relative);
		if (field && (op !== "add" || !Array.isArray(document[field]))) {
			document[field] = op === "remove" ? undefined : value;
			return;
		}
		throw ownedSCIMError(
			400,
			"This SCIM User PATCH path is not supported by the candidate",
			"invalidPath",
		);
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
	return parseOwnedSCIMUser({ ...document, name, emails });
}
