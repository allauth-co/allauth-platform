import * as z from "zod";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
	scimUserSchema,
} from "./owned-project-scim-discovery";

const short = z.string().trim().min(1).max(256);
const long = z.string().trim().min(1).max(1024);
const valueType = short.transform((type) => type.toLowerCase());
const typedValue = {
	type: valueType.optional(),
	primary: z.boolean().optional(),
};

function uniqueTypes(values: readonly { type?: string }[]) {
	const types = values.flatMap((value) =>
		value.type === undefined ? [] : [value.type],
	);
	return new Set(types).size === types.length;
}

function structuredValues<
	T extends z.ZodType<{
		type?: string | undefined;
		primary?: boolean | undefined;
	}>,
>(schema: T) {
	return z
		.array(schema)
		.max(10)
		.refine((values) => values.filter((value) => value.primary).length <= 1)
		.refine(uniqueTypes);
}

function singleValue(schema: typeof short) {
	return z
		.preprocess(
			(value) =>
				Array.isArray(value) && value.length === 1 ? value[0] : value,
			schema,
		)
		.optional();
}

const manager = z
	.object({
		value: short.optional(),
		$ref: z.string().trim().min(1).max(2048).optional(),
	})
	.refine((value) => value.value !== undefined || value.$ref !== undefined);
const enterprise = z.object({
	employeeNumber: singleValue(short),
	costCenter: singleValue(short),
	organization: singleValue(long),
	division: singleValue(long),
	department: singleValue(long),
	manager: manager.optional(),
});
const address = z
	.object({
		formatted: long.optional(),
		streetAddress: long.optional(),
		locality: short.optional(),
		region: short.optional(),
		postalCode: short.optional(),
		country: short.optional(),
		...typedValue,
	})
	.refine((value) =>
		Object.entries(value).some(
			([key, field]) =>
				key !== "type" && key !== "primary" && field !== undefined,
		),
	);
const role = z.object({ value: long, display: long.optional(), ...typedValue });
const emails = z
	.array(
		z.object({
			value: z.email().max(254),
			type: valueType.optional(),
			primary: z.boolean(),
		}),
	)
	.min(1)
	.max(20)
	.refine((values) => values.filter((value) => value.primary).length === 1)
	.refine(
		(values) =>
			new Set(
				values.map((value) =>
					JSON.stringify([
						value.type ?? null,
						value.value.trim().toLowerCase(),
					]),
				),
			).size === values.length,
	)
	.refine(uniqueTypes);

export const ownedSCIMStoredUserAttributes = z
	.object({
		schemas: z
			.array(z.enum([scimUserSchema, scimEnterpriseUserSchema]))
			.min(1)
			.max(2)
			.refine(
				(schemas) =>
					schemas.includes(scimUserSchema) &&
					new Set(schemas).size === schemas.length,
			)
			.transform((schemas) =>
				([scimUserSchema, scimEnterpriseUserSchema] as const).filter((schema) =>
					schemas.includes(schema),
				),
			),
		name: z.object({
			formatted: long,
			givenName: short.optional(),
			familyName: short.optional(),
			middleName: short.optional(),
			honorificPrefix: short.optional(),
			honorificSuffix: short.optional(),
		}),
		emails,
		title: long.optional(),
		userType: short.optional(),
		preferredLanguage: short.optional(),
		locale: short.optional(),
		timezone: short.optional(),
		phoneNumbers: structuredValues(
			z.object({ value: long, ...typedValue }),
		).optional(),
		addresses: structuredValues(address).optional(),
		roles: structuredValues(role).optional(),
		entitlements: structuredValues(role).optional(),
		enterprise: enterprise.optional(),
	})
	.refine(
		(value) =>
			value.enterprise === undefined ||
			value.schemas.includes(scimEnterpriseUserSchema),
	);

/** Validates the canonical persisted profile, including the legacy name and email mirrors. */
export function readOwnedSCIMUserAttributes(row: {
	serializedAttributes: string | null;
	formattedName: string;
	givenName: string | null;
	familyName: string | null;
	serializedEmails: string;
}) {
	try {
		if (row.serializedAttributes && row.serializedAttributes.length > 65_535)
			throw new Error("Stored attributes exceed the supported length.");
		const input: unknown = row.serializedAttributes
			? JSON.parse(row.serializedAttributes)
			: {
					schemas: [scimUserSchema],
					name: {
						formatted: row.formattedName,
						...(row.givenName ? { givenName: row.givenName } : {}),
						...(row.familyName ? { familyName: row.familyName } : {}),
					},
					emails: JSON.parse(row.serializedEmails),
				};
		const parsed = ownedSCIMStoredUserAttributes.safeParse(input);
		if (parsed.success) {
			const { enterprise: extension, ...core } = parsed.data;
			return {
				...core,
				...(extension ? { [scimEnterpriseUserSchema]: extension } : {}),
			};
		}
	} catch {
		// Keep persisted attribute values and validation details out of HTTP errors.
	}
	throw ownedSCIMError(500, "Stored SCIM User attribute state is invalid");
}
