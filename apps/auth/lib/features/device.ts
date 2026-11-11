import { projectSlug } from "../projects/validation";

/** Repeated or invalid project selectors never fall back to the platform realm. */
export function deviceProject(
	value: string | string[] | undefined,
): string | undefined {
	if (value === undefined) return undefined;
	if (Array.isArray(value))
		throw new Error("Choose one project to approve this device.");
	return projectSlug.parse(value);
}

/** Keep a local, explicit review link; visiting it alone never approves a code. */
export function deviceReviewPath(code: string, project?: string): string {
	const query = new URLSearchParams();
	if (code) query.set("user_code", code);
	if (project) query.set("project", projectSlug.parse(project));
	return `/device${query.size ? `?${query}` : ""}`;
}

/** Distinguish session admission failures from authoritative device-code errors. */
export function deviceRequestError(error: {
	status?: number;
	error_description?: unknown;
	message?: unknown;
}): string {
	if (error.status === 401 || error.status === 403)
		return "Sign in again with a verified account, then review this request. A recent sign-in is required to approve access.";
	for (const value of [error.error_description, error.message]) {
		if (typeof value === "string" && value.trim()) return value.trim();
	}
	return "The device request could not be completed. Please try again.";
}
