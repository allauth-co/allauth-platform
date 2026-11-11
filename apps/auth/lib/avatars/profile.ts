import { APIError } from "better-auth";
import { validAvatarPath } from "./protocol";
/** Resolve browser URL aliases before the SQL owner guard; ordinary external images keep their contract. */
export function guardOwnedAvatarProfileImage(
	image: unknown,
	operation: "create" | "update",
	baseURL: string,
) {
	if (typeof image !== "string") return;
	let url: URL;
	try {
		url = new URL(image, baseURL);
	} catch {
		return;
	}
	if (!validAvatarPath(url.pathname)) return;
	if (
		operation === "create" ||
		url.protocol !== "https:" ||
		image !== url.origin + url.pathname
	)
		throw new APIError("BAD_REQUEST", {
			message:
				"Choose the original profile photo uploaded for your current account.",
		});
}
