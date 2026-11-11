const consolePaths = new Set([
	"/admin/workspaces",
	"/admin/projects",
	"/admin/overview",
	"/admin/users",
	"/admin/organizations",
	"/admin/audit-logs",
	"/admin/configure",
	"/admin/configure/organizations",
	"/admin/settings",
	"/admin/security",
	"/admin/plugins",
	"/admin/applications",
	"/admin/sessions",
	"/admin/webhooks",
	"/admin/domains",
	"/admin/setup-guide",
]);

/** Return an exact console UI route, unambiguous scope and an optional scoped workspace tab. */
export function safeConsoleReturnTo(value?: string | null): string | null {
	if (
		!value ||
		value.length > 4096 ||
		!value.startsWith("/") ||
		value.startsWith("//") ||
		value.includes("\\") ||
		value.trim() !== value
	)
		return null;
	let target: URL;
	try {
		target = new URL(value, "https://allauth.invalid");
	} catch {
		return null;
	}
	if (
		target.origin !== "https://allauth.invalid" ||
		value.split(/[?#]/, 1)[0] !== target.pathname ||
		!consolePaths.has(target.pathname)
	)
		return null;
	const scope = new URLSearchParams();
	for (const key of ["workspace", "project"] as const) {
		const values = target.searchParams.getAll(key);
		if (!values.length) continue;
		if (values.length !== 1 || !/^[A-Za-z0-9_-]{1,128}$/.test(values[0]!))
			return null;
		scope.set(key, values[0]!);
	}
	if (target.pathname === "/admin/workspaces" && target.searchParams.has("tab")) {
		const tabs = target.searchParams.getAll("tab");
		if (
			!scope.has("workspace") ||
			tabs.length !== 1 ||
			!tabs.every((tab) => tab === "team" || tab === "settings" || tab === "billing")
		)
			return null;
		scope.set("tab", tabs[0]!);
	}
	return `${target.pathname}${scope.size ? `?${scope}` : ""}`;
}

/** Duplicate account return parameters are invalid, even when one is otherwise safe. */
export function consoleReturnFromSearch(
	params: Pick<URLSearchParams, "getAll">,
): string | null {
	const values = params.getAll("consoleReturnTo");
	return values.length === 1 ? safeConsoleReturnTo(values[0]) : null;
}

/** Account settings and organization pages can carry explicit console return context. */
export function isAccountNavigationPath(pathname: string): boolean {
	return /^\/(account|organizations|organization)(\/|$)/.test(pathname);
}

/** Add validated console return context only to personal account navigation. */
export function accountNavigationHref(path: string, consoleReturnTo?: string | null) {
	const target = new URL(path, "https://allauth.invalid");
	if (!isAccountNavigationPath(target.pathname)) return path;
	target.searchParams.delete("consoleReturnTo");
	const safeReturnTo = safeConsoleReturnTo(consoleReturnTo);
	if (safeReturnTo) target.searchParams.set("consoleReturnTo", safeReturnTo);
	return `${target.pathname}${target.search}${target.hash}`;
}
