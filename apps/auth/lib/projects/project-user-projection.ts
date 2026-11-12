/** Explicit user projection excludes private metadata, account passwords and future internal columns. */
export function publicProjectUser(user: Record<string, unknown>) {
	const result: Record<string, unknown> = {};
	for (const field of [
		"id",
		"email",
		"name",
		"emailVerified",
		"role",
		"banned",
		"banReason",
		"banExpires",
		"image",
		"createdAt",
		"updatedAt",
		"publicMetadata",
	] as const)
		if (user[field] !== undefined) result[field] = user[field];
	return result;
}
