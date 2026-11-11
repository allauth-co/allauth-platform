export const workspaceSlugPattern = /^[a-z][a-z0-9-]{1,47}$/;
export const reservedWorkspaceSlugs: readonly string[] = ["allauth-platform", "admin", "platform", "public", "internal"];

/** Explain the same identifier rules used by workspace creation and availability checks. */
export function workspaceSlugError(slug: string): string | undefined {
	if (!workspaceSlugPattern.test(slug)) return "Use 2–48 lowercase letters, numbers, or hyphens, starting with a letter.";
	if (reservedWorkspaceSlugs.includes(slug)) return "This workspace slug is reserved. Choose another slug.";
	return undefined;
}

/** Suggest a valid public identifier while keeping arbitrary workspace names unchanged. */
export function suggestWorkspaceSlug(name: string): string {
	let slug = name.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
	if (!slug) slug = "workspace";
	else if (!/^[a-z]/.test(slug)) slug = `workspace-${slug}`;
	if (slug.length < 2 || reservedWorkspaceSlugs.includes(slug)) slug = `${slug}-workspace`;
	return slug.slice(0, 48).replace(/-+$/g, "");
}

/** Number repeated suggestions without exceeding the database identifier limit. */
export function workspaceSlugCandidate(base: string, attempt: number): string {
	if (attempt === 1) return base;
	const suffix = `-${attempt}`;
	return `${base.slice(0, 48 - suffix.length).replace(/-+$/g, "")}${suffix}`;
}
