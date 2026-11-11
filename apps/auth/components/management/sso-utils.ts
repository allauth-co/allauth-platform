export function hasOrganizationAdminRole(
	role: string | null | undefined,
): boolean {
	return Boolean(
		role
			?.split(",")
			.some((entry) => entry.trim() === "owner" || entry.trim() === "admin"),
	);
}

export function requireHTTPSURL(value: string, label: string): string {
	const exact = value.trim();
	let url: URL;
	try {
		url = new URL(exact);
	} catch {
		throw new Error(`${label} must be an absolute HTTPS URL.`);
	}
	if (url.protocol !== "https:" || url.username || url.password || url.hash)
		throw new Error(
			`${label} must be an HTTPS URL without credentials or fragments.`,
		);
	return exact;
}
