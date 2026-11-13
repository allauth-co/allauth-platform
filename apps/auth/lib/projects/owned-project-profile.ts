import { DatabaseError } from "pg";
import type { PoolClient } from "pg";
import * as z from "zod";
import { validAvatarProfileImage } from "../avatars/protocol";
import type { ControlEventInput } from "../control/types";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { ownedProjectUsernameError } from "./owned-sign-up";

export const ownedProjectProfileBody = z.record(z.string(), z.unknown());

const profile = z.looseObject({
	email: z.unknown().optional(),
	name: z.string().optional(),
	image: z.string().nullable().optional(),
	username: z.string().nullish(),
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
type EventContext = Pick<ControlEventInput, "ipAddress" | "userAgent">;
type ProfileFailure = { status: 400 | 401; code: string; message: string };
const profilePath = "/update-user";
const unauthorized = {
	status: 401,
	code: "UNAUTHORIZED",
	message: "Unauthorized",
} as const;

function profileChange(data: z.infer<typeof profile>, baseURL: string) {
	const { email, name, image, username, displayUsername } = data;
	if (email)
		return {
			status: 400,
			code: "EMAIL_CAN_NOT_BE_UPDATED",
			message: "Email can not be updated",
		} as const;
	if (typeof username === "string") {
		const error = ownedProjectUsernameError(username);
		if (error) return { status: 400, ...error } as const;
	}
	const readOnly = readOnlyProfileFields.find((field) => data[field]);
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
		username: typeof username === "string" ? username.toLowerCase() : username,
		displayUsername,
	}).filter(([, value]) => value !== undefined);
	if (!fields.length)
		return {
			status: 400,
			code: "INVALID_BODY",
			message: "No fields to update",
		} as const;
	return { fields };
}

export function createOwnedProjectProfile(store: Store, baseURL: string) {
	return async function update(
		input: unknown,
		current: Session | null,
		context: EventContext,
	) {
		function record(client: PoolClient, actorId?: string, errorCode?: string) {
			return store.recordEvent(client, {
				type: "user.updated",
				outcome: errorCode ? "failure" : "success",
				actorId,
				userId: actorId,
				...context,
				metadata: { path: profilePath, errorCode },
			});
		}
		async function reject(
			client: PoolClient,
			result: ProfileFailure,
			actorId?: string,
		) {
			const code = ["INVALID_BODY", "INVALID_PROFILE_IMAGE"].includes(
				result.code,
			)
				? "AUTHENTICATION_FAILED"
				: result.code;
			await record(client, actorId, code);
			return result;
		}
		if (!current)
			return store.transaction((client) => reject(client, unauthorized));
		const parsed = profile.safeParse(input);
		if (!parsed.success)
			return {
				status: 400,
				code: "INVALID_BODY",
				message: "Invalid profile.",
			} as const;
		const change = profileChange(parsed.data, baseURL);
		const { userId, token } = current;
		async function authorizedUser(client: PoolClient) {
			const user = await store.lockUser(client, userId);
			return user &&
				!user.banned &&
				!user.directoryDisabled &&
				(await store.lockSession(client, token, userId, false))
				? user
				: null;
		}

		try {
			return await store.transaction(async (client) => {
				const user = await authorizedUser(client);
				if (!user) return reject(client, unauthorized);
				if ("status" in change) return reject(client, change, user.id);

				// All column names come from the fixed profile fields above.
				const assignments = change.fields.map(
					([field], index) => `"${field}" = $${index + 2}`,
				);
				await client.query(
					`UPDATE "user" SET ${assignments.join(", ")}, "updatedAt" = statement_timestamp() WHERE id = $1`,
					[userId, ...change.fields.map(([, value]) => value)],
				);
				// The legacy database hook and authenticated endpoint each emit a distinct event.
				await store.record(
					client,
					"user.updated",
					"success",
					profilePath,
					userId,
					userId,
				);
				await record(client, userId);
				return { status: 200, token } as const;
			});
		} catch (error) {
			let rejected: ProfileFailure;
			if (
				error instanceof DatabaseError &&
				error.code === "23505" &&
				error.constraint === "user_username_uidx"
			) {
				rejected = {
					status: 400,
					code: "USERNAME_IS_ALREADY_TAKEN",
					message: "Username is already taken",
				};
			} else if (
				error instanceof DatabaseError &&
				error.code === "P0001" &&
				error.message ===
					"Choose a current profile photo uploaded for this account."
			) {
				rejected = {
					status: 400,
					code: "INVALID_PROFILE_IMAGE",
					message: error.message,
				};
			} else throw error;
			return store.transaction(async (client) =>
				reject(client, rejected, (await authorizedUser(client))?.id),
			);
		}
	};
}
