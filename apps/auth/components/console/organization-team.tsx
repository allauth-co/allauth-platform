"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { Button } from "@/components/ui/button";
import { projectManagementPath } from "@/lib/management-client";
import { Identity, managementRequest, Pagination, SearchField, StateMessage } from "./common";

export interface ConsoleOrganizationMember {
	id: string;
	userId: string;
	role: string;
	createdAt: string;
	name: string;
	email: string;
	image?: string;
	emailVerified: boolean;
	banned: boolean;
	directoryManaged: boolean;
}

interface MemberPage {
	members: ConsoleOrganizationMember[];
	total: number;
	limit: number;
	offset: number;
}

/** Keep organization and team directories scoped, searchable and reachable beyond the first page. */
export function useConsoleOrganizationMembers({ project, organizationId, search, offset, teamId, excludeTeam = false, limit = 25, enabled = true }: {
	project?: string;
	organizationId: string;
	search: string;
	offset: number;
	teamId?: string;
	excludeTeam?: boolean;
	limit?: number;
	enabled?: boolean;
}) {
	return useQuery({
		queryKey: ["console-organization-members", project ?? null, organizationId, teamId ?? null, excludeTeam, search, offset, limit],
		queryFn: ({ signal }) => managementRequest<MemberPage>(projectManagementPath(
			`/api/admin/organizations/${encodeURIComponent(organizationId)}/members?${new URLSearchParams({ search, offset: String(offset), limit: String(limit), ...(teamId ? { teamId, excludeTeam: String(excludeTeam) } : {}) })}`,
			project,
		), { signal }),
		enabled,
	});
}

/** Show actual team membership before offering targeted add/remove operations. */
export function ConsoleOrganizationTeam({ project, organizationId, team, busy, run }: {
	project?: string;
	organizationId: string;
	team: { id: string; name: string; memberCount: number };
	busy: boolean;
	run: (path: string, body: unknown, method?: string) => Promise<boolean>;
}) {
	const [search, setSearch] = useState("");
	const [offset, setOffset] = useState(0);
	const [candidateSearch, setCandidateSearch] = useState("");
	const [userId, setUserId] = useState("");
	const [editing, setEditing] = useState(false);
	const [name, setName] = useState(team.name);
	const [expanded, setExpanded] = useState(false);
	const members = useConsoleOrganizationMembers({ project, organizationId, search, offset, teamId: team.id, enabled: expanded });
	const candidates = useConsoleOrganizationMembers({ project, organizationId, search: candidateSearch, offset: 0, teamId: team.id, excludeTeam: true, limit: 100, enabled: expanded });
	const path = `/api/admin/organizations/${encodeURIComponent(organizationId)}/teams`;
	useEffect(() => {
		if (members.data && offset > 0 && offset >= members.data.total) setOffset(Math.max(0, Math.ceil(members.data.total / 25) - 1) * 25);
	}, [members.data, offset]);
	return (
		<div className="console-card mb-4">
			<div className="console-card-heading flex-wrap">
				<div className="min-w-0"><h2 className="break-words">{team.name}</h2><p>{team.memberCount} members</p></div>
				<div className="flex flex-wrap gap-2">
					<Button type="button" variant="outline" size="sm" aria-expanded={expanded} aria-controls={`team-roster-${team.id}`} onClick={() => setExpanded(!expanded)}>{expanded ? "Hide members" : "Manage members"}</Button>
					<Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => { setName(team.name); setEditing(true); }}>Rename</Button>
					<Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => {
						if (window.confirm(`Delete the ${team.name} team?`)) void run(path, { action: "delete", teamId: team.id });
					}}>Delete</Button>
				</div>
			</div>
			<div className="console-card-body">
				{editing && <form className="console-form mb-6" onSubmit={(event) => {
					event.preventDefault();
					void run(path, { action: "update", teamId: team.id, name }).then((ok) => { if (ok) setEditing(false); });
				}}>
					<label htmlFor={`team-name-${team.id}`}>Team name</label>
					<input id={`team-name-${team.id}`} required maxLength={100} value={name} onChange={(event) => setName(event.target.value)} />
					<div className="flex gap-2"><Button disabled={busy || !name.trim()}>Save name</Button><Button type="button" variant="ghost" disabled={busy} onClick={() => setEditing(false)}>Cancel</Button></div>
				</form>}
				{expanded && <div id={`team-roster-${team.id}`}>
				<SearchField value={search} onChange={(value) => { setSearch(value); setOffset(0); }} placeholder={`Search ${team.name} members…`} />
				<StateMessage loading={members.isPending} error={members.error} empty={members.data?.members.length === 0}>No team members match this search.</StateMessage>
				{members.data?.members.map((member) => <div key={member.id} className="flex items-center justify-between gap-3 border-b py-3">
					<Identity name={member.name} email={member.email} image={member.image} />
					<Button type="button" variant="ghost" size="sm" disabled={busy} aria-label={`Remove ${member.email} from ${team.name}`} onClick={() => {
						if (window.confirm(`Remove ${member.name || member.email} from ${team.name}?`)) void run(path, { action: "remove-member", teamId: team.id, userId: member.userId });
					}}>Remove</Button>
				</div>)}
				{members.data && <Pagination total={members.data.total} count={members.data.members.length} offset={offset} busy={members.isFetching || busy} onOffset={setOffset} />}
				<form className="console-form mt-6" onSubmit={(event) => {
					event.preventDefault();
					void run(path, { action: "add-member", teamId: team.id, userId }).then((ok) => { if (ok) setUserId(""); });
				}}>
					<label htmlFor={`team-search-${team.id}`}>Find an organization member to add</label>
					<input id={`team-search-${team.id}`} value={candidateSearch} maxLength={128} placeholder="Search name or email" onChange={(event) => { setCandidateSearch(event.target.value); setUserId(""); }} />
					<label htmlFor={`team-member-${team.id}`}>Organization member</label>
					<AppSelect id={`team-member-${team.id}`} value={userId} onValueChange={setUserId} required disabled={candidates.isPending || busy}>
						<AppSelectOption value="">Choose a member</AppSelectOption>
						{candidates.data?.members.map((member) => <AppSelectOption key={member.id} value={member.userId}>{member.name} · {member.email}</AppSelectOption>)}
					</AppSelect>
					<StateMessage error={candidates.error} empty={candidates.data?.total === 0}>No available organization members match this search.</StateMessage>
					{candidates.data && candidates.data.total > candidates.data.limit && <p>Showing the first {candidates.data.limit} matches. Search by name or email to find another member.</p>}
					<Button className="console-primary" disabled={busy || !userId || !candidates.data?.members.some((member) => member.userId === userId)}>Add to team</Button>
				</form>
				</div>}
			</div>
		</div>
	);
}
