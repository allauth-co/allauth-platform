import { APIError } from "better-auth";
import { validAvatarProfileImage } from "./protocol";
/** Resolve browser URL aliases before the SQL owner guard; ordinary external images keep their contract. */
export function guardOwnedAvatarProfileImage(
	image: unknown,
	operation: "create" | "update",
	baseURL: string,
) {
	if (!validAvatarProfileImage(image, operation, baseURL))
		throw new APIError("BAD_REQUEST", {
			message:
				"Choose the original profile photo uploaded for your current account.",
		});
}
