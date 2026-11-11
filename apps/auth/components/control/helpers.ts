import type { ControlOutcome } from "./types";

/** Selected projects have separate query caches from the platform and one another. */
export function controlQueryScope(project?: string) {
	return ["control", project ?? null] as const;
}

export function managementHref(
	path: string,
	project?: string,
	workspace?: string,
) {
	if (project === undefined && workspace === undefined) return path;
	const url = new URL(path, "https://allauth.invalid");
	if (project !== undefined) url.searchParams.set("project", project);
	if (workspace !== undefined) url.searchParams.set("workspace", workspace);
	return `${url.pathname}${url.search}${url.hash}`;
}

export type ControlPageProps = {
	searchParams: Promise<{
		project?: string | string[];
		workspace?: string | string[];
	}>;
};

/** Ambiguous duplicate selections remain invalid rather than selecting an arbitrary project. */
export function projectFromSearch(
	value?: string | string[],
): string | undefined {
	return Array.isArray(value) ? value.join(",") : value;
}

export type AuditFilters = {
	q: string;
	type: string;
	outcome: ControlOutcome | "";
	userId: string;
	organizationId: string;
	from: string;
	to: string;
};

export const emptyAuditFilters: AuditFilters = {
	q: "",
	type: "",
	outcome: "",
	userId: "",
	organizationId: "",
	from: "",
	to: "",
};

export function dateToISO(value: string): string | undefined {
	if (!value) return undefined;
	const date = new Date(value);
	if (!Number.isFinite(date.getTime()))
		throw new Error("Enter a valid date and time.");
	return date.toISOString();
}

export function auditQuery(filters: AuditFilters, offset: number): string {
	const from = dateToISO(filters.from);
	const to = dateToISO(filters.to);
	if (from && to && from > to)
		throw new Error("The start time must be before the end time.");
	const query = new URLSearchParams({
		scope: "admin",
		limit: "25",
		offset: String(offset),
	});
	for (const key of [
		"q",
		"type",
		"outcome",
		"userId",
		"organizationId",
	] as const) {
		const value = filters[key].trim();
		if (value) query.set(key, value);
	}
	if (from) query.set("from", from);
	if (to) query.set("to", to);
	return query.toString();
}

export function sessionQuery(
	q: string,
	userId: string,
	offset: number,
): string {
	const query = new URLSearchParams({ limit: "25", offset: String(offset) });
	if (q.trim()) query.set("q", q.trim());
	if (userId.trim()) query.set("userId", userId.trim());
	return query.toString();
}

export function pageRange(total: number, offset: number, count: number) {
	return count
		? `${offset + 1}–${Math.min(total, offset + count)} of ${total.toLocaleString()}`
		: `0 of ${total.toLocaleString()}`;
}

export function parseEmailDomains(value: string): string[] {
	const values = value
		.split(/[\n,]+/)
		.map((domain) => domain.trim())
		.filter(Boolean);
	const domains = values.map((value) => {
		let domain = "";
		try {
			if (value.length <= 253 && !/[\s/@:#?\\]/.test(value))
				domain = new URL(`https://${value}`).hostname.toLowerCase();
		} catch {
			/* Report the same domain-specific validation message below. */
		}
		if (
			!domain.includes(".") ||
			/^\d+\.\d+\.\d+\.\d+$/.test(domain) ||
			!domain
				.split(".")
				.every(
					(label) =>
						/^[a-z\d](?:[a-z\d-]*[a-z\d])?$/.test(label) && label.length <= 63,
				)
		) {
			throw new Error(
				`Enter a domain such as example.com, without an email address, URL or wildcard: ${value}`,
			);
		}
		return domain;
	});
	const unique = [...new Set(domains)];
	if (unique.length > 200)
		throw new Error("Use no more than 200 blocked email domains.");
	return unique;
}

export function formatDateTime(value: string) {
	const date = new Date(value);
	return Number.isFinite(date.getTime())
		? date.toLocaleString(undefined, {
				dateStyle: "medium",
				timeStyle: "short",
			})
		: "Unavailable";
}

export function formatDay(value: string) {
	const date = new Date(value);
	return Number.isFinite(date.getTime())
		? date.toLocaleDateString(undefined, {
				month: "short",
				day: "numeric",
				timeZone: "UTC",
			})
		: value;
}

export function eventLabel(value: string) {
	return value
		.replace(/([a-z])([A-Z])/g, "$1 $2")
		.replace(/[._-]+/g, " ")
		.replace(/^./, (letter) => letter.toUpperCase());
}
