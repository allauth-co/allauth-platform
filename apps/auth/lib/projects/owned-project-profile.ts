import { DatabaseError } from "pg";
import * as z from "zod";
import { validAvatarProfileImage } from "../avatars/protocol";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { ownedProjectUsernameError } from "./owned-sign-up";

const profile = z.looseObject({
	email: z.unknown().optional(),
	name: z.string().optional(),
	image: z.string().nullable().optional(),
	username: z.string().optional(),
	displayUsername: z.string().optional(),
});

const readOnlyProfileFields = [
	"isAnonymous",
	"publicMetadata",
	"privateMetadata",
	"directoryManaged",
	"directoryDisabled",
	"twoFactorEnabled",
	"role",
	"banned",
	"banReason",
	"banExpires",
] as const;

type Store = ReturnType<typeof createProjectEngineStore>;
type Session = { userId: string; token: string };

export function createOwnedProjectProfile(store: Store, baseURL: string) {
	return async function update(input: unknown, current: Session) {
		const parsed = profile.safeParse(input);
		if (!parsed.success)
			return {
				status: 400,
				code: "INVALID_BODY",
				message: "Invalid profile.",
			} as const;
		const { email, name, image, username, displayUsername } = parsed.data;
		if (email)
			return {
				status: 400,
				code: "EMAIL_CAN_NOT_BE_UPDATED",
				message: "Email can not be updated",
			} as const;
		if (username !== undefined) {
			const error = ownedProjectUsernameError(username);
			if (error) return { status: 400, ...error } as const;
		}
		const readOnly = readOnlyProfileFields.find((field) => parsed.data[field]);
		if (readOnly)
			return {
				status: 400,
				code: "FIELD_NOT_ALLOWED",
				message: `${readOnly} is not allowed to be set`,
			} as const;
		if (!validAvatarProfileImage(image, "update", baseURL)) {
			return {
				status: 400,
				code: "INVALID_PROFILE_IMAGE",
				message:
					"Choose the original profile photo uploaded for your current account.",
			} as const;
		}

		const fields = Object.entries({
			name,
			image,
			username: username?.toLowerCase(),
			displayUsername,
		}).filter(([, value]) => value !== undefined);
		if (!fields.length)
			return {
				status: 400,
				code: "INVALID_BODY",
				message: "No fields to update",
			} as const;

		try {
			return await store.transaction(async (client) => {
				const user = await store.lockUser(client, current.userId);
				if (
					!user ||
					user.banned ||
					user.directoryDisabled ||
					!(await store.lockSession(
						client,
						current.token,
						current.userId,
						false,
					))
				)
					return {
						status: 401,
						code: "UNAUTHORIZED",
						message: "Unauthorized",
					} as const;

				// All column names come from the fixed profile fields above.
				const assignments = fields.map(
					([field], index) => `"${field}" = $${index + 2}`,
				);
				await client.query(
					`UPDATE "user" SET ${assignments.join(", ")}, "updatedAt" = statement_timestamp() WHERE id = $1`,
					[current.userId, ...fields.map(([, value]) => value)],
				);
				return { status: 200 } as const;
			});
		} catch (error) {
			if (
				error instanceof DatabaseError &&
				error.code === "23505" &&
				error.constraint === "user_username_uidx"
			) {
				return {
					status: 400,
					code: "USERNAME_IS_ALREADY_TAKEN",
					message: "Username is already taken",
				} as const;
			}
			if (
				error instanceof DatabaseError &&
				error.code === "P0001" &&
				error.message ===
					"Choose a current profile photo uploaded for this account."
			) {
				return {
					status: 400,
					code: "INVALID_PROFILE_IMAGE",
					message: error.message,
				} as const;
			}
			throw error;
		}
	};
}
