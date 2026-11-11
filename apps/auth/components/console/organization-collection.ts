"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { projectManagementPath } from "@/lib/management-client";
import { managementRequest } from "./common";

/** Separate page state and cache keys for each organization resource. */
export function useConsoleOrganizationCollection<Data>({ project, organizationId, resource, enabled }: {
	project?: string;
	organizationId: string;
	resource: "teams" | "roles" | "invitations";
	enabled: boolean;
}) {
	const [search, setSearchValue] = useState("");
	const [offset, setOffset] = useState(0);
	const query = useQuery({
		queryKey: ["console-organization-collection", project ?? null, organizationId, resource, search, offset],
		queryFn: ({ signal }) => managementRequest<Data & { total: number; limit: number; offset: number }>(projectManagementPath(
			`/api/admin/organizations/${encodeURIComponent(organizationId)}/${resource}?${new URLSearchParams({ search, offset: String(offset), limit: "25" })}`, project,
		), { signal }),
		enabled,
	});
	useEffect(() => {
		if (query.data && offset > 0 && offset >= query.data.total) setOffset(Math.max(0, Math.ceil(query.data.total / 25) - 1) * 25);
	}, [query.data, offset]);
	return { ...query, search, offset, setOffset, setSearch: (value: string) => { setSearchValue(value); setOffset(0); } };
}
