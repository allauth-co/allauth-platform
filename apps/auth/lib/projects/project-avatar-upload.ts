import { APIError } from "better-auth";
import * as z from "zod";
import { avatarMaxBytes } from "../avatars/protocol";
import type { ValidatedBrandingAsset } from "../branding/types";
import { validateBrandingAsset } from "../branding/validation";

export const projectAvatarInput = z.strictObject({
	contentType: z.enum(["image/png", "image/jpeg", "image/webp"]),
	data: z
		.string()
		.min(4)
		.max(Math.ceil(avatarMaxBytes / 3) * 4)
		.regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
});

export function projectAvatarAsset({
	data,
	contentType,
}: z.infer<typeof projectAvatarInput>): ValidatedBrandingAsset {
	const bytes = Uint8Array.from(atob(data), (character) =>
		character.charCodeAt(0),
	);
	if (bytes.byteLength > avatarMaxBytes)
		throw new APIError("BAD_REQUEST", {
			message: "Choose a profile photo no larger than 128 KB after resizing.",
		});
	return validateBrandingAsset("logo", bytes, contentType);
}

export interface ProjectAvatarStorage {
	upload(asset: ValidatedBrandingAsset, userId: string): Promise<string>;
	ownershipAndDeletion?(): Promise<boolean>;
}

export async function uploadProjectAvatar(
	storage: ProjectAvatarStorage | undefined,
	userId: string,
	input: unknown,
): Promise<Response> {
	const respond = (body: unknown, status = 200) =>
		Response.json(body, {
			status,
			headers: { "cache-control": "no-store", pragma: "no-cache" },
		});
	const parsed = projectAvatarInput.safeParse(input);
	if (!parsed.success)
		return respond(
			{ code: "INVALID_BODY", message: "Invalid profile photo." },
			400,
		);
	try {
		if (
			!storage ||
			(storage.ownershipAndDeletion && !(await storage.ownershipAndDeletion()))
		)
			return respond(
				{
					message:
						"Profile photo uploads are not configured for this application.",
				},
				503,
			);
		return respond({
			url: await storage.upload(projectAvatarAsset(parsed.data), userId),
		});
	} catch (error) {
		if (error instanceof APIError && [400, 429, 503].includes(error.statusCode))
			return respond(error.body, error.statusCode);
		return respond(
			{ message: "Profile photo uploads are temporarily unavailable." },
			503,
		);
	}
}
