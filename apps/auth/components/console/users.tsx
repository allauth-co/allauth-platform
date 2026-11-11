"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, Columns3, Plus, ShieldCheck } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
	getManagementClient,
	projectManagementPath,
} from "@/lib/management-client";
import { UserOrganizationMembership } from "./user-organization-membership";
import { supportSessionHref } from "@/lib/console/support-session";
import type { AuthPolicy } from "@/lib/auth-policy/policy";
import { defaultPasswordPolicy, passwordPolicyDescription, passwordPolicyError } from "@/lib/auth-policy/password";
import type { ControlEvent } from "@/lib/control/types";
import {
	Badge,
	CopyValue,
	DateText,
	DetailPanel,
	Identity,
	managementRequest,
	PageHeading,
	Pagination,
	SearchField,
	StateMessage,
} from "./common";
export interface ConsoleUser {
	id: string;
	name: string;
	email: string;
	image?: string | null;
	emailVerified: boolean;
	role?: string | null;
	banned?: boolean;
	banReason?: string | null;
	createdAt: string;
	updatedAt: string;
	username?: string | null;
	displayUsername?: string | null;
	twoFactorEnabled: boolean;
	isAnonymous: boolean;
	lastSignInAt?: string | null;
	activeSessionCount: number;
	publicMetadata?: Record<string, unknown>;
}
interface UserList {
	users: ConsoleUser[];
	total: number;
	limit: number;
	offset: number;
	lastSignInHistory: string;
}
interface UserDetail {
	user: ConsoleUser;
	accounts: { id: string; providerId: string; createdAt: string }[];
	sessions: {
		id: string;
		createdAt: string;
		expiresAt: string;
		ipAddress?: string;
		userAgent?: string;
		impersonatedBy?: string;
	}[];
	memberships: {
		id: string;
		role: string;
		createdAt: string;
		organizationId: string;
		name: string;
		slug: string;
		logo?: string;
		directoryManaged?: boolean;
	}[];
	recentEvents: ControlEvent[];
	passkeyCount: number;
}
const hasAdmin = (role?: string | null) =>
	role?.split(",").some((value) => value.trim() === "admin") ?? false;
export function ConsoleUsers({ project }: { project?: string }) {
	const searchParams = useSearchParams();
	const [search, setSearch] = useState("");
	const [offset, setOffset] = useState(0);
	const [status, setStatus] = useState("all");
	const [role, setRole] = useState("all");
	const [sort, setSort] = useState("createdAt");
	const [direction, setDirection] = useState("desc");
	const [selected, setSelected] = useState<string | undefined>(
		searchParams.get("selected") || undefined,
	);
	const [creating, setCreating] = useState(false);
	const [busy, setBusy] = useState(false);
	const [columns, setColumns] = useState([
		"username",
		"status",
		"lastSignInAt",
		"createdAt",
	]);
	const [draft, setDraft] = useState({ name: "", email: "", password: "" });
	const cache = useQueryClient();
	const client = getManagementClient(project);
	const requestedUser = searchParams.get("selected");
	useEffect(() => setSelected(requestedUser || undefined), [requestedUser]);
	const params = new URLSearchParams({
		search,
		status,
		role,
		sort,
		direction,
		offset: String(offset),
		limit: "25",
	});
	const query = useQuery({
		queryKey: ["console-users", project ?? null, params.toString()],
		queryFn: ({ signal }) =>
			managementRequest<UserList>(
				projectManagementPath(`/api/admin/users?${params}`, project),
				{ signal },
			),
	});
	const configuration = useQuery({
		queryKey: ["console-configuration", project ?? null],
		queryFn: ({ signal }) => managementRequest<{ policy: AuthPolicy }>(projectManagementPath("/api/admin/configuration", project), { signal }),
		enabled: creating,
	});
	const passwordPolicy = configuration.data?.policy.passwordPolicy || defaultPasswordPolicy;
	const run = async (
		action: () => Promise<{ error?: { message?: string } | null }>,
		message: string,
	) => {
		setBusy(true);
		try {
			const result = await action();
			if (result.error) throw new Error(result.error.message);
			toast.success(message);
			await cache.invalidateQueries({
				queryKey: ["console-users", project ?? null],
			});
			await cache.invalidateQueries({
				queryKey: ["console-user", project ?? null],
			});
			return true;
		} catch (error) {
			toast.error(
				error instanceof Error ? error.message : "The action failed.",
			);
			return false;
		} finally {
			setBusy(false);
		}
	};
	const changeSort = (value: string) => {
		if (sort === value) setDirection(direction === "desc" ? "asc" : "desc");
		else {
			setSort(value);
			setDirection("desc");
		}
		setOffset(0);
	};
	return (
		<>
			<PageHeading
				title="Users"
				description="Explore identities, authentication methods and account access."
			>
				<Button
					type="button"
					className="console-primary"
					onClick={() => setCreating(true)}
				>
					<Plus size={15} className="mr-2" />
					Create user
				</Button>
			</PageHeading>
			<div className="console-toolbar">
				<div className="console-toolbar-group">
					<SearchField
						value={search}
						onChange={(value) => {
							setSearch(value);
							setOffset(0);
						}}
						placeholder="Search name, email or username…"
					/>
					<ColumnsMenu
						columns={columns}
						onChange={setColumns}
						options={[
							["username", "Username"],
							["status", "Status"],
							["role", "Role"],
							["lastSignInAt", "Last signed in"],
							["createdAt", "Joined"],
							["mfa", "MFA"],
							["sessions", "Sessions"],
						]}
					/>
					<AppSelect
						aria-label="Filter account status"
						className="console-select"
						value={status}
						onValueChange={(selection) => {
							setStatus(selection);
							setOffset(0);
						}}
					>
						<AppSelectOption value="all">All statuses</AppSelectOption>
						<AppSelectOption value="verified">Verified</AppSelectOption>
						<AppSelectOption value="unverified">Unverified</AppSelectOption>
						<AppSelectOption value="banned">Banned</AppSelectOption>
					</AppSelect>
					<AppSelect
						aria-label="Filter user role"
						className="console-select"
						value={role}
						onValueChange={(selection) => {
							setRole(selection);
							setOffset(0);
						}}
					>
						<AppSelectOption value="all">All roles</AppSelectOption>
						<AppSelectOption value="admin">
							{project ? "Project administrators" : "Platform administrators"}
						</AppSelectOption>
						<AppSelectOption value="user">Users</AppSelectOption>
					</AppSelect>
				</div>
			</div>
			<div className="console-table-wrap">
				<table className="console-table">
					<thead>
						<tr>
							<th>
								<button type="button" onClick={() => changeSort("name")}>
									User
									{sort === "name" && (
										<ArrowDown
											size={12}
											className={`inline ml-2 ${direction === "asc" ? "rotate-180" : ""}`}
										/>
									)}
								</button>
							</th>
							{columns.includes("username") && <th>Username</th>}
							{columns.includes("status") && <th>Status</th>}
							{columns.includes("role") && <th>Role</th>}
							{columns.includes("lastSignInAt") && (
								<th>
									<button
										type="button"
										onClick={() => changeSort("lastSignInAt")}
									>
										Last signed in
										{sort === "lastSignInAt" && (
											<ArrowDown size={12} className="inline ml-2" />
										)}
									</button>
								</th>
							)}
							{columns.includes("createdAt") && (
								<th>
									<button type="button" onClick={() => changeSort("createdAt")}>
										Joined
										{sort === "createdAt" && (
											<ArrowDown size={12} className="inline ml-2" />
										)}
									</button>
								</th>
							)}
							{columns.includes("mfa") && <th>MFA</th>}
							{columns.includes("sessions") && <th>Sessions</th>}
						</tr>
					</thead>
					<tbody>
						{query.data?.users.map((user) => (
							<tr key={user.id}>
								<td>
									<button
										type="button"
										className="text-left"
										onClick={() => setSelected(user.id)}
									>
										<Identity
											name={user.name}
											email={user.email}
											image={user.image}
										/>
									</button>
								</td>
								{columns.includes("username") && (
									<td className="text-muted-foreground">
										{user.displayUsername || user.username || "—"}
									</td>
								)}
								{columns.includes("status") && (
									<td>
										<Badge
											tone={
												user.banned
													? "danger"
													: user.emailVerified
														? "success"
														: "neutral"
											}
										>
											{user.banned
												? "Banned"
												: user.emailVerified
													? "Verified"
													: "Unverified"}
										</Badge>
										{user.isAnonymous && <Badge>Guest</Badge>}
									</td>
								)}
								{columns.includes("role") && (
									<td>
										{hasAdmin(user.role)
											? project
												? "Project administrator"
												: "Platform administrator"
											: "User"}
									</td>
								)}
								{columns.includes("lastSignInAt") && (
									<td>
										<DateText value={user.lastSignInAt} time />
									</td>
								)}
								{columns.includes("createdAt") && (
									<td>
										<DateText value={user.createdAt} />
									</td>
								)}
								{columns.includes("mfa") && (
									<td>
										{user.twoFactorEnabled ? (
											<ShieldCheck
												size={16}
												className="text-green-600"
												aria-label="MFA enabled"
											/>
										) : (
											"—"
										)}
									</td>
								)}
								{columns.includes("sessions") && (
									<td>{user.activeSessionCount}</td>
								)}
							</tr>
						))}
					</tbody>
				</table>
				<StateMessage
					loading={query.isPending}
					error={query.error}
					empty={query.data?.users.length === 0}
				>
					No users match these filters.
				</StateMessage>
			</div>
			{query.data && (
				<>
					<Pagination
						total={query.data.total}
						offset={offset}
						count={query.data.users.length}
						onOffset={setOffset}
						busy={query.isFetching}
					/>
					<p className="text-[10px] text-muted-foreground mt-4">
						Last sign-in uses recorded events within audit retention. A dash
						means no retained sign-in event.
					</p>
				</>
			)}
			{creating && (
				<DetailPanel title="Create user" onClose={() => setCreating(false)}>
					<form
						className="console-form"
						onSubmit={(event) => {
							event.preventDefault();
							if (!configuration.data || configuration.isPending || configuration.error) return;
							const error = passwordPolicyError(draft.password, passwordPolicy);
							if (error) { toast.error(error); return; }
							void run(
								() => client.admin.createUser({ ...draft, role: "user" }),
								"User created",
							).then((ok) => {
								if (ok) {
									setCreating(false);
									setDraft({ name: "", email: "", password: "" });
								}
							});
						}}
					>
						{[
							["name", "Name", "text"],
							["email", "Email address", "email"],
							["password", "Initial password", "password"],
						].map(([key, label, type]) => (
							<div key={key}>
								<label htmlFor={`create-user-${key}`}>{label}</label>
								<input
									id={`create-user-${key}`}
									type={type}
									required
									minLength={key === "password" ? passwordPolicy.minLength : 1}
									maxLength={
										key === "password" ? passwordPolicy.maxLength : key === "email" ? 320 : 100
									}
									autoComplete={key === "password" ? "new-password" : "off"}
									value={draft[key as keyof typeof draft]}
									onChange={(event) =>
										setDraft({ ...draft, [key]: event.target.value })
									}
								/>
							</div>
						))}
						<p>{passwordPolicyDescription(passwordPolicy)}</p>
						<StateMessage loading={configuration.isPending} error={configuration.error} />
						<p>
							New users receive the standard user role. Email verification and
							account policies still apply.
						</p>
						<Button className="console-primary" disabled={busy || configuration.isPending || !!configuration.error}>
							{busy ? "Creating…" : "Create user"}
						</Button>
					</form>
				</DetailPanel>
			)}
			{selected && (
				<UserDrawer
					key={selected}
					project={project}
					userId={selected}
					busy={busy}
					run={run}
					onClose={() => setSelected(undefined)}
				/>
			)}
		</>
	);
}
export function ColumnsMenu({
	columns,
	onChange,
	options,
}: {
	columns: string[];
	onChange: (columns: string[]) => void;
	options: readonly (readonly [string, string])[];
}) {
	return (
		<details className="console-columns">
			<summary>
				<Columns3 size={14} />
				Columns
			</summary>
			<div className="console-columns-menu">
				{options.map(([key, label]) => (
					<label key={key}>
						<input
							type="checkbox"
							checked={columns.includes(key)}
							onChange={(event) =>
								onChange(
									event.target.checked
										? [...columns, key]
										: columns.filter((value) => value !== key),
								)
							}
						/>
						{label}
					</label>
				))}
			</div>
		</details>
	);
}
function UserDrawer({
	project,
	userId,
	busy,
	run,
	onClose,
}: {
	project?: string;
	userId: string;
	busy: boolean;
	run: (
		action: () => Promise<{ error?: { message?: string } | null }>,
		message: string,
	) => Promise<boolean>;
	onClose: () => void;
}) {
	const searchParams = useSearchParams();
	const client = getManagementClient(project);
	const [tab, setTab] = useState("Profile");
	const query = useQuery({
		queryKey: ["console-user", project ?? null, userId],
		queryFn: ({ signal }) =>
			managementRequest<UserDetail>(
				projectManagementPath(
					`/api/admin/users/${encodeURIComponent(userId)}`,
					project,
				),
				{ signal },
			),
	});
	const data = query.data;
	const [publicMetadata, setPublicMetadata] = useState("");
	const [privateMetadata, setPrivateMetadata] = useState("");
	return (
		<DetailPanel wide title="User details" onClose={onClose}>
			<StateMessage loading={query.isPending} error={query.error} />
			{data && (
				<>
					<div className="flex justify-between gap-4 items-start">
						<Identity
							name={data.user.name}
							email={data.user.email}
							image={data.user.image}
						/>
						<Badge
							tone={
								data.user.banned
									? "danger"
									: data.user.emailVerified
										? "success"
										: "neutral"
							}
						>
							{data.user.banned
								? "Banned"
								: data.user.emailVerified
									? "Verified"
									: "Unverified"}
						</Badge>
					</div>
					<div className="console-id mt-4 max-w-none">
						{userId}
						<CopyValue value={userId} label="Copy user ID" />
					</div>
					<div className="console-subtabs mt-6">
						{["Profile", "Organizations", "Sessions", "Activity"].map(
							(value) => (
								<button
									type="button"
									data-active={tab === value}
									key={value}
									onClick={() => setTab(value)}
								>
									{value}
								</button>
							),
						)}
					</div>
					{tab === "Profile" && (
						<>
							<dl className="console-definition">
								<dt>Username</dt>
								<dd>
									{data.user.displayUsername || data.user.username || "—"}
								</dd>
								<dt>Joined</dt>
								<dd>
									<DateText value={data.user.createdAt} />
								</dd>
								<dt>Last signed in</dt>
								<dd>
									<DateText value={data.user.lastSignInAt} time />
								</dd>
								<dt>Authentication</dt>
								<dd>
									{data.accounts
										.map((account) => account.providerId)
										.join(", ") || "No linked methods"}
								</dd>
								<dt>MFA</dt>
								<dd>
									{data.user.twoFactorEnabled ? "Enabled" : "Not enrolled"}
								</dd>
								<dt>Passkeys</dt>
								<dd>{data.passkeyCount}</dd>
								<dt>Role</dt>
								<dd>
									<AppSelect
										className="console-select"
										aria-label="User role"
										value={hasAdmin(data.user.role) ? "admin" : "user"}
										disabled={busy}
										onValueChange={(selection) => {
											const role = selection as "admin" | "user";
											if (
												window.confirm(
													`Set ${data.user.email}'s role to ${role}?`,
												)
											)
												void run(
													() => client.admin.setRole({ userId, role }),
													"User role updated",
												);
										}}
									>
										<AppSelectOption value="user">User</AppSelectOption>
										<AppSelectOption value="admin">
											{project
												? "Project administrator"
												: "Platform administrator"}
										</AppSelectOption>
									</AppSelect>
								</dd>
							</dl>
							<section className="console-detail-section">
								<h3>Metadata</h3>
								<p className="text-xs text-muted-foreground mb-3">
									Public metadata is visible to the user. A populated field
									replaces its object; leave blank to preserve it.
								</p>
								<form
									className="console-form"
									onSubmit={(event) => {
										event.preventDefault();
										void run(async () => {
											const payload: Record<string, unknown> = {};
											for (const [key, value] of [
												["publicMetadata", publicMetadata],
												["privateMetadata", privateMetadata],
											]) {
												if (!value.trim()) continue;
												const parsed: unknown = JSON.parse(value);
												if (
													!parsed ||
													typeof parsed !== "object" ||
													Array.isArray(parsed)
												)
													throw new Error("Metadata must be a JSON object.");
												payload[key] = parsed;
											}
											if (!Object.keys(payload).length)
												throw new Error("Enter metadata to save.");
											await managementRequest(
												projectManagementPath(
													`/api/admin/users/${encodeURIComponent(userId)}/metadata`,
													project,
												),
												{ method: "PATCH", body: JSON.stringify(payload) },
											);
											return {};
										}, "Metadata updated");
									}}
								>
									<div>
										<label htmlFor="user-public-metadata">
											Public metadata
										</label>
										<textarea
											id="user-public-metadata"
											className="font-mono text-xs"
											rows={4}
											placeholder={JSON.stringify(
												data.user.publicMetadata || {},
												null,
												2,
											)}
											value={publicMetadata}
											onChange={(event) =>
												setPublicMetadata(event.target.value)
											}
										/>
									</div>
									<div>
										<label htmlFor="user-private-metadata">
											Private metadata
										</label>
										<textarea
											id="user-private-metadata"
											className="font-mono text-xs"
											rows={3}
											value={privateMetadata}
											onChange={(event) =>
												setPrivateMetadata(event.target.value)
											}
											placeholder="Existing private metadata is not displayed."
										/>
									</div>
									<Button type="submit" variant="outline" disabled={busy}>
										Save metadata
									</Button>
								</form>
							</section>
							<section className="console-detail-section">
								<h3>Access management</h3>
								{data.user.banReason && (
									<p className="text-xs text-muted-foreground mb-4">
										Ban reason: {data.user.banReason}
									</p>
								)}
								<div className="flex flex-wrap gap-2">
									<Button
										type="button"
										variant="outline"
										size="sm"
										disabled={busy}
										onClick={() => {
											if (
												window.confirm(
													`Revoke all sessions for ${data.user.email}?`,
												)
											)
												void run(
													() => client.admin.revokeUserSessions({ userId }),
													"Sessions revoked",
												);
										}}
									>
										Revoke all sessions
									</Button>
									<Button
										type="button"
										variant="outline"
										size="sm"
										disabled={busy || hasAdmin(data.user.role) || data.user.banned}
										onClick={() => {
											if (
												window.confirm(
													`Start a support session as ${data.user.email}?`,
												)
											)
												void run(
													() => client.admin.impersonateUser({ userId }),
													"Support session started",
												).then((ok) => {
													if (ok)
														window.location.assign(
															supportSessionHref(project, searchParams.get("workspace") || undefined, userId),
														);
												});
										}}
									>
										Impersonate user
									</Button>
									<Button
										type="button"
										variant="outline"
										size="sm"
										disabled={busy}
										onClick={() => {
											if (data.user.banned)
												void run(
													() => client.admin.unbanUser({ userId }),
													"User unbanned",
												);
											else {
												const reason = window.prompt(
													`Reason for banning ${data.user.email}:`,
												);
												if (reason !== null)
													void run(
														() =>
															client.admin.banUser({
																userId,
																banReason: reason,
															}),
														"User banned",
													);
											}
										}}
									>
										{data.user.banned ? "Unban user" : "Ban user"}
									</Button>
									<Button
										type="button"
										variant="outline"
										size="sm"
										className="text-destructive"
										disabled={busy}
										onClick={() => {
											if (
												window.confirm(
													`Permanently delete ${data.user.email}? This cannot be undone.`,
												)
											)
												void run(
													() => client.admin.removeUser({ userId }),
													"User deleted",
												).then((ok) => {
													if (ok) onClose();
												});
										}}
									>
										Delete user
									</Button>
								</div>
							</section>
						</>
					)}
					{tab === "Organizations" && (
						<>
							<StateMessage empty={!data.memberships.length}>
								This user has no organization memberships.
							</StateMessage>
							{data.memberships.map((member) => (
								<UserOrganizationMembership key={member.id} project={project} member={member} busy={busy} run={run} />
							))}
						</>
					)}
					{tab === "Sessions" && (
						<>
							<p className="text-xs text-muted-foreground mb-4">
								{data.sessions.length} active sessions. Session credentials are
								never displayed.
							</p>
							{data.sessions.map((session) => (
								<div key={session.id} className="border-b py-4 space-y-2">
									<div className="flex justify-between">
										<span className="console-id">{session.id}</span>
										<Badge>{session.impersonatedBy ? "Support" : "User"}</Badge>
									</div>
									<p className="text-xs break-words">
										{session.userAgent || "Unknown device"}
									</p>
									<p className="text-xs text-muted-foreground">
										{session.ipAddress || "No IP recorded"} · Expires{" "}
										<DateText value={session.expiresAt} time />
									</p>
								</div>
							))}
							<Button
								type="button"
								variant="outline"
								disabled={busy || !data.sessions.length}
								className="mt-5"
								onClick={() => {
									if (window.confirm("Revoke all of this user's sessions?"))
										void run(
											() => client.admin.revokeUserSessions({ userId }),
											"Sessions revoked",
										);
								}}
							>
								Revoke all sessions
							</Button>
						</>
					)}
					{tab === "Activity" && (
						<>
							<StateMessage empty={!data.recentEvents.length}>
								No recent events for this user.
							</StateMessage>
							{data.recentEvents.map((event) => (
								<div key={event.id} className="border-b py-4">
									<div className="flex justify-between gap-3">
										<span className="font-mono text-xs">{event.type}</span>
										<Badge
											tone={event.outcome === "success" ? "success" : "danger"}
										>
											{event.outcome}
										</Badge>
									</div>
									<p className="text-xs text-muted-foreground mt-2">
										<DateText value={event.createdAt} time /> ·{" "}
										{event.ipAddress || "IP not recorded"}
									</p>
								</div>
							))}
						</>
					)}
				</>
			)}
		</DetailPanel>
	);
}
