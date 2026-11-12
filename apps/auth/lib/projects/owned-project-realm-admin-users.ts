import { randomUUID } from "node:crypto";
import { DatabaseError } from "pg";
import type { PoolClient } from "pg";
import * as z from "zod";
import { validAvatarProfileImage } from "../avatars/protocol";
import { ownedProjectUsernameError } from "./owned-sign-up";

export const realmAdminCreateUserPath = "/admin/create-user";
export const realmAdminUpdateUserPath = "/admin/update-user";
const role = z.union([z.string(), z.array(z.string())]);
const data = z.record(z.string(), z.unknown());
export const realmAdminCreateUserInput = z.object({
	email: z.string(),
	name: z.string(),
	password: z.string().optional(),
	role: role.optional(),
	data: data.optional(),
});
export const realmAdminUpdateUserInput = z.object({
	userId: z.coerce.string(),
	data,
});

const fields = z.strictObject({
	name: z.string().optional(),
	email: z.string().optional(),
	image: z.string().nullable().optional(),
	emailVerified: z.boolean().optional(),
	role: z.unknown().optional(),
	banned: z.boolean().nullable().optional(),
	banReason: z.string().nullable().optional(),
	banExpires: z.iso
		.datetime({ offset: true })
		.transform((value) => new Date(value))
		.nullable()
		.optional(),
	publicMetadata: z.json().optional(),
	username: z.string().nullable().optional(),
	displayUsername: z.string().nullable().optional(),
});
export type RealmAdminUserFailure = {
	status: number;
	code: string;
	message: string;
	exposeCode?: false;
};
export const realmAdminDuplicateEmail = {
	status: 400,
	code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
	message: "User already exists. Use another email.",
};
export const realmAdminDuplicateUsername = {
	status: 400,
	code: "USERNAME_IS_ALREADY_TAKEN",
	message: "Username is already taken",
};
const invalidAvatar = {
	status: 400,
	code: "AUTHENTICATION_FAILED",
	message:
		"Choose the original profile photo uploaded for your current account.",
	exposeCode: false,
} as const;

function invalid(
	code: string,
	message: string,
): { failure: RealmAdminUserFailure } {
	return { failure: { status: 400, code, message } };
}

/** Project only the user fields supported by this realm's administrative route. */
export function realmAdminUserFields(
	input:
		| { data: Record<string, unknown> }
		| z.infer<typeof realmAdminCreateUserInput>,
	primaryOrigin: string,
) {
	const create = "name" in input;
	const source = input.data ?? {};
	if (!create && !Object.keys(source).length)
		return invalid("NO_DATA_TO_UPDATE", "No data to update");
	if (!create && Object.hasOwn(source, "password"))
		return invalid(
			"PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
			"Password cannot be updated through update-user. Use the set-user-password endpoint instead.",
		);
	const extra = Object.keys(source).find(
		(key) => !Object.hasOwn(fields.shape, key),
	);
	if (extra)
		return invalid(
			"FIELD_NOT_ALLOWED",
			"The request contains an unsupported user field.",
		);
	const parsed = fields.safeParse(source);
	if (!parsed.success)
		return invalid(
			"VALIDATION_ERROR",
			"The request contains an invalid user field.",
		);
	const value = parsed.data;
	const requestedRole = create ? (input.role ?? value.role) : value.role;
	const parsedRole = role.optional().safeParse(requestedRole);
	if (!parsedRole.success)
		return invalid("INVALID_ROLE_TYPE", "Invalid role type");
	const roleValue =
		typeof parsedRole.data === "string"
			? parsedRole.data
			: parsedRole.data?.join(",");
	const email = (create ? input.email : value.email)?.toLowerCase();
	if (email !== undefined && !z.email().safeParse(email).success)
		return invalid("INVALID_EMAIL", "Invalid email");
	if (
		!validAvatarProfileImage(
			value.image,
			create ? "create" : "update",
			primaryOrigin,
		)
	)
		return { failure: invalidAvatar };
	const usernameError =
		value.username && ownedProjectUsernameError(value.username);
	if (usernameError) return invalid(usernameError.code, usernameError.message);
	return {
		fields: {
			...value,
			name: create ? input.name : value.name,
			email,
			role: create ? (roleValue ?? "user") : roleValue,
			username: value.username?.toLowerCase() ?? value.username,
			displayUsername:
				create && value.username
					? value.displayUsername || value.username
					: value.displayUsername,
		},
	};
}

type UserFields = Omit<z.infer<typeof fields>, "role"> & { role?: string };
function entries(fields: UserFields) {
	return Object.entries(fields)
		.filter(([, value]) => value !== undefined)
		.map(([field, value]) => ({
			field: `"${field}"`,
			value:
				field === "publicMetadata" && value !== null
					? JSON.stringify(value)
					: value,
		}));
}

export async function realmAdminEmailInUse(
	client: PoolClient,
	email: string,
	except?: string,
) {
	return (
		(
			await client.query(
				'SELECT id FROM "user" WHERE email=$1 AND id IS DISTINCT FROM $2',
				[email, except ?? null],
			)
		).rowCount === 1
	);
}

export async function realmAdminUsernameInUse(
	client: PoolClient,
	username: string,
	except?: string,
) {
	return (
		(
			await client.query(
				'SELECT id FROM "user" WHERE username=$1 AND id IS DISTINCT FROM $2',
				[username, except ?? null],
			)
		).rowCount === 1
	);
}

export async function insertRealmAdminUser(
	client: PoolClient,
	input: UserFields,
) {
	const id = randomUUID();
	const values = entries({
		...input,
		emailVerified: input.emailVerified ?? false,
		banned: input.banned === undefined ? false : input.banned,
	});
	const inserted = await client.query(
		`INSERT INTO "user" (id,"twoFactorEnabled","isAnonymous","directoryManaged","directoryDisabled",${values.map(({ field }) => field).join(",")})
		 VALUES ($1,FALSE,FALSE,FALSE,FALSE,${values.map((_, index) => `$${index + 2}`).join(",")}) ON CONFLICT DO NOTHING`,
		[id, ...values.map(({ value }) => value)],
	);
	return inserted.rowCount === 1 ? id : null;
}

export async function updateRealmAdminUser(
	client: PoolClient,
	id: string,
	input: UserFields,
) {
	const values = entries(input);
	await client.query("SAVEPOINT realm_admin_user_update");
	try {
		await client.query(
			`UPDATE "user" SET ${values.map(({ field }, index) => `${field}=$${index + 2}`).join(",")},"updatedAt"=statement_timestamp() WHERE id=$1`,
			[id, ...values.map(({ value }) => value)],
		);
	} catch (error) {
		if (!(error instanceof DatabaseError)) throw error;
		const failure =
			error.code === "23505" && error.constraint === "user_email_key"
				? realmAdminDuplicateEmail
				: error.code === "23505" && error.constraint === "user_username_uidx"
					? realmAdminDuplicateUsername
					: error.code === "P0001" &&
							error.message ===
								"Choose a current profile photo uploaded for this account."
						? invalidAvatar
						: null;
		if (!failure) throw error;
		await client.query("ROLLBACK TO SAVEPOINT realm_admin_user_update");
		return failure;
	}
	await client.query("RELEASE SAVEPOINT realm_admin_user_update");
	return null;
}
