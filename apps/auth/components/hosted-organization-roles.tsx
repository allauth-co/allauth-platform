"use client";

import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import type { FormEvent } from "react";
import type { AllAuthClient, AllAuthOrganizationRole } from "@/sdk/client";
import {
	useHostedOrganizationAction,
	useHostedOrganizationPermission,
} from "./hosted-organization-management";
import {
	AlertDialog,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "./ui/alert-dialog";
import { HostedOrganizationPagination } from "./hosted-organization-pagination";
import { AppSelect, AppSelectOption } from "./ui/app-select";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import {
	Dialog,
	DialogClose,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "./ui/table";

type Scope = { client: AllAuthClient; organizationId: string; userId: string };
const statements = [
	["organization", ["update", "delete"]],
	["member", ["create", "update", "delete"]],
	["invitation", ["create", "cancel"]],
	["team", ["create", "update", "delete"]],
	["ac", ["create", "read", "update", "delete"]],
] as const;
type Resource = (typeof statements)[number][0];
type Action = (typeof statements)[number][1][number];
const emptySelection = new Set<string>();

/** Show dynamic roles only after the selected realm confirms read authority. */
export function HostedOrganizationRoles({
	client,
	organizationId,
	userId,
}: Scope) {
	const queryClient = useQueryClient();
	const roles = useQuery({
		queryKey: ["hosted-organization", "roles", userId, organizationId],
		queryFn: async () => {
			const result = await client.organization.listRoles({
				query: { organizationId },
			});
			if (result.error) throw new Error(result.error.message);
			return (result.data ?? []).filter(
				(role) => role.organizationId === organizationId,
			);
		},
	});
	const create = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"ac",
		"create",
	);
	const update = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"ac",
		"update",
	);
	const remove = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		"ac",
		"delete",
	);
	const [search, setSearch] = useState("");
	const [resource, setResource] = useState("");
	const [descending, setDescending] = useState(false);
	const [page, setPage] = useState(0);
	const [size, setSize] = useState(10);
	const [selection, setSelection] = useState(emptySelection);
	const [editor, setEditor] = useState<
		AllAuthOrganizationRole | null | undefined
	>();
	const [deletion, setDeletion] = useState<AllAuthOrganizationRole[]>([]);
	const { busy, error, run } = useHostedOrganizationAction();
	const source = roles.data ?? [];
	const resources = [
		...new Set(source.flatMap((role) => Object.keys(role.permission))),
	].sort();
	const term = search.trim().toLowerCase();
	const matching = source.filter((role) => {
		const matchesResource =
			!resource || Object.hasOwn(role.permission, resource);
		const searchable = [
			role.role,
			...Object.entries(role.permission).flatMap(([key, actions]) => [
				key,
				...actions,
			]),
		];
		return (
			matchesResource &&
			(!term || searchable.some((value) => value.toLowerCase().includes(term)))
		);
	});
	matching.sort(
		(left, right) =>
			(descending ? -1 : 1) * left.role.localeCompare(right.role),
	);
	const pageCount = Math.max(1, Math.ceil(matching.length / size));
	const currentPage = Math.min(page, pageCount - 1);
	const current = matching.slice(currentPage * size, (currentPage + 1) * size);
	const assignments = useQueries({
		queries: current.map((role) => ({
			queryKey: [
				"hosted-organization",
				"role-assignments",
				userId,
				organizationId,
				role.role,
			],
			enabled: remove.data === true,
			queryFn: async () => {
				const result = await client.organization.listMembers({
					query: {
						organizationId,
						filterField: "role",
						filterOperator: "contains",
						filterValue: role.role,
						limit: 1,
					},
				});
				if (result.error) throw new Error(result.error.message);
				return result.data?.total ?? 0;
			},
		})),
	});
	const removable = current.filter(
		(_role, index) => assignments[index]?.data === 0,
	);
	const selected = source.filter((role) => selection.has(role.id));
	const accessError =
		roles.error?.message ||
		create.error?.message ||
		update.error?.message ||
		remove.error?.message;
	function toggle(roleIds: string[], checked: boolean) {
		setSelection((previous) => {
			const next = new Set(previous);
			for (const roleId of roleIds) {
				if (checked) next.add(roleId);
				else next.delete(roleId);
			}
			return next;
		});
	}
	async function reload() {
		await Promise.all([
			roles.refetch(),
			queryClient.invalidateQueries({
				queryKey: ["hosted-organization", "permission", userId, organizationId],
			}),
			queryClient.invalidateQueries({
				queryKey: [
					"hosted-organization",
					"role-assignments",
					userId,
					organizationId,
				],
			}),
		]);
	}
	function deleteRoles() {
		if (!remove.data || !deletion.length) return;
		void run(
			async () => {
				const outcomes = await Promise.all(
					deletion.map(async (role) => {
						const result = await client.organization.deleteRole({
							organizationId,
							roleId: role.id,
						});
						return { role, result };
					}),
				);
				const failed = outcomes.filter(
					({ result }) => result.error || !result.data?.success,
				);
				await reload();
				setSelection(new Set(failed.map(({ role }) => role.id)));
				setDeletion(failed.map(({ role }) => role));
				if (failed.length)
					throw new Error(
						failed[0]?.result.error?.message ||
							"One or more role deletions could not be confirmed.",
					);
			},
			deletion.length === 1 ? "Role deleted" : "Roles deleted",
		);
	}
	return (
		<section className="space-y-4" aria-labelledby="hosted-roles-title">
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 id="hosted-roles-title" className="text-sm font-semibold">
					Roles
				</h2>
				{create.data && (
					<Button type="button" size="sm" onClick={() => setEditor(null)}>
						Create role
					</Button>
				)}
			</div>
			{accessError && (
				<p role="alert" className="text-sm text-destructive">
					{accessError}
				</p>
			)}
			<div className="flex flex-wrap items-center gap-2">
				<Input
					type="search"
					aria-label="Search roles"
					placeholder="Search roles"
					className="max-w-56"
					value={search}
					onChange={(event) => {
						setSearch(event.target.value);
						setPage(0);
					}}
				/>
				<AppSelect
					aria-label="Filter roles by permission"
					value={resource}
					onValueChange={(value) => {
						setResource(value);
						setPage(0);
					}}
					className="min-w-36 rounded-md border px-2 text-sm"
				>
					<AppSelectOption value="">All permissions</AppSelectOption>
					{resources.map((name) => (
						<AppSelectOption key={name} value={name}>
							{name === "ac" ? "Role management" : name}
						</AppSelectOption>
					))}
				</AppSelect>
				{remove.data && selected.length > 0 && (
					<Button
						type="button"
						variant="outline"
						size="sm"
						onClick={() => setDeletion(selected)}
					>
						Delete selected
					</Button>
				)}
			</div>
			<Card>
				<CardContent>
					<Table aria-label="Organization roles">
						<TableHeader>
							<TableRow>
								{remove.data && (
									<TableHead className="w-8">
										<input
											type="checkbox"
											aria-label="Select all visible removable roles"
											disabled={removable.length === 0}
											checked={
												removable.length > 0 &&
												removable.every((role) => selection.has(role.id))
											}
											onChange={(event) =>
												toggle(
													removable.map((role) => role.id),
													event.target.checked,
												)
											}
										/>
									</TableHead>
								)}
								<TableHead aria-sort={descending ? "descending" : "ascending"}>
									<Button
										type="button"
										variant="ghost"
										size="sm"
										onClick={() => {
											setDescending(!descending);
											setPage(0);
										}}
									>
										Role
									</Button>
								</TableHead>
								<TableHead>Permissions</TableHead>
								<TableHead className="text-right">Actions</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{current.map((role, index) => (
								<RoleRow
									key={role.id}
									role={role}
									assignmentCount={assignments[index]?.data}
									assignmentError={assignments[index]?.error?.message}
									canUpdate={update.data === true}
									canDelete={remove.data === true}
									selected={selection.has(role.id)}
									toggle={(checked) => toggle([role.id], checked)}
									edit={() => setEditor(role)}
									remove={() => setDeletion([role])}
								/>
							))}
						</TableBody>
					</Table>
					{roles.isLoading ? (
						<p role="status" className="py-3 text-sm text-muted-foreground">
							Loading roles…
						</p>
					) : (
						!current.length && (
							<p className="py-3 text-sm text-muted-foreground">
								No roles found.
							</p>
						)
					)}
				</CardContent>
			</Card>
			<HostedOrganizationPagination
				label="Roles"
				page={currentPage}
				pageCount={pageCount}
				size={size}
				setPage={setPage}
				setSize={(size) => {
					setSize(size);
					setPage(0);
				}}
			/>
			{editor !== undefined && (
				<RoleEditor
					key={editor?.id ?? "new"}
					client={client}
					organizationId={organizationId}
					userId={userId}
					role={editor}
					allowed={editor ? update.data === true : create.data === true}
					dismiss={() => setEditor(undefined)}
					reload={reload}
				/>
			)}
			<AlertDialog
				open={deletion.length > 0}
				onOpenChange={(open) => {
					if (!open && !busy) setDeletion([]);
				}}
			>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>
							{deletion.length === 1 ? "Delete role" : "Delete roles"}
						</AlertDialogTitle>
						<AlertDialogDescription>
							{deletion.map((role) => role.role).join(", ")}
						</AlertDialogDescription>
					</AlertDialogHeader>
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<AlertDialogFooter>
						<AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
						<Button
							type="button"
							variant="destructive"
							disabled={busy || !remove.data}
							onClick={deleteRoles}
						>
							Delete
						</Button>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</section>
	);
}

function RoleRow({
	role,
	assignmentCount,
	assignmentError,
	canUpdate,
	canDelete,
	selected,
	toggle,
	edit,
	remove,
}: {
	role: AllAuthOrganizationRole;
	assignmentCount?: number;
	assignmentError?: string;
	canUpdate: boolean;
	canDelete: boolean;
	selected: boolean;
	toggle(checked: boolean): void;
	edit(): void;
	remove(): void;
}) {
	const allowDelete = canDelete && assignmentCount === 0;
	return (
		<TableRow>
			{canDelete && (
				<TableCell>
					<input
						type="checkbox"
						checked={selected}
						disabled={!allowDelete}
						aria-label={`Select ${role.role}`}
						onChange={(event) => toggle(event.target.checked)}
					/>
				</TableCell>
			)}
			<TableCell className="font-medium">{role.role}</TableCell>
			<TableCell>
				{Object.values(role.permission).reduce(
					(sum, actions) => sum + actions.length,
					0,
				)}
			</TableCell>
			<TableCell className="text-right space-x-2">
				{canUpdate && (
					<Button
						type="button"
						variant="ghost"
						size="sm"
						aria-label={`Edit ${role.role}`}
						onClick={edit}
					>
						Edit
					</Button>
				)}
				{canDelete && (
					<Button
						type="button"
						variant="ghost"
						size="sm"
						aria-label={`Delete ${role.role}`}
						disabled={!allowDelete}
						title={
							assignmentError ||
							(assignmentCount
								? `Assigned to ${assignmentCount} members`
								: undefined)
						}
						onClick={remove}
					>
						Delete
					</Button>
				)}
			</TableCell>
		</TableRow>
	);
}

function RoleEditor({
	client,
	organizationId,
	userId,
	role,
	allowed,
	dismiss,
	reload,
}: Scope & {
	role: AllAuthOrganizationRole | null;
	allowed: boolean;
	dismiss(): void;
	reload(): Promise<void>;
}) {
	const id = useId();
	const [name, setName] = useState(role?.role ?? "");
	const [permissions, setPermissions] = useState(role?.permission ?? {});
	const { busy, error, run } = useHostedOrganizationAction();
	function save(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		const roleName = name.trim();
		if (!allowed || !roleName) return;
		void run(
			async () => {
				const permission = Object.fromEntries(
					Object.entries(permissions).filter(([, actions]) => actions.length),
				);
				if (Object.keys(permission).length) {
					const access = await client.organization.hasPermission({
						organizationId,
						permissions: permission,
					});
					if (access.error || !access.data?.success)
						throw new Error("You can only grant permissions you already have.");
				}
				const result = role
					? await client.organization.updateRole({
							organizationId,
							roleId: role.id,
							data: { roleName, permission },
						})
					: await client.organization.createRole({
							organizationId,
							role: roleName,
							permission,
						});
				if (result.error) throw new Error(result.error.message);
				if (
					!result.data?.success ||
					result.data.roleData.organizationId !== organizationId ||
					(role && result.data.roleData.id !== role.id)
				)
					throw new Error("The role change could not be confirmed.");
				await reload();
				dismiss();
			},
			role ? "Role updated" : "Role created",
		);
	}
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !busy) dismiss();
			}}
		>
			<DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>{role ? "Edit role" : "Create role"}</DialogTitle>
					<DialogDescription>
						Choose permissions for the organization role.
					</DialogDescription>
				</DialogHeader>
				<form className="space-y-4" onSubmit={save}>
					<Label htmlFor={`${id}-name`}>Role name</Label>
					<Input
						id={`${id}-name`}
						value={name}
						disabled={!allowed || busy}
						onChange={(event) => setName(event.target.value)}
						required
					/>
					<div className="grid gap-3 sm:grid-cols-2">
						{statements.map(([resource, actions]) => (
							<fieldset
								key={resource}
								className="space-y-2 rounded-md border p-3"
							>
								<legend className="px-1 text-sm capitalize">
									{resource === "ac" ? "Role management" : resource}
								</legend>
								{actions.map((action) => (
									<RolePermission
										key={action}
										client={client}
										organizationId={organizationId}
										userId={userId}
										resource={resource}
										action={action}
										checked={permissions[resource]?.includes(action) === true}
										disabled={!allowed || busy}
										onChange={(checked) =>
											setPermissions((current) => ({
												...current,
												[resource]: checked
													? [...(current[resource] ?? []), action]
													: (current[resource] ?? []).filter(
															(value) => value !== action,
														),
											}))
										}
									/>
								))}
							</fieldset>
						))}
					</div>
					{error && (
						<p role="alert" className="text-sm text-destructive">
							{error}
						</p>
					)}
					<DialogFooter>
						<DialogClose asChild>
							<Button type="button" variant="outline" disabled={busy}>
								Cancel
							</Button>
						</DialogClose>
						<Button type="submit" disabled={busy || !allowed}>
							{role ? "Save changes" : "Create role"}
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}

function RolePermission({
	client,
	organizationId,
	userId,
	resource,
	action,
	checked,
	disabled,
	onChange,
}: Scope & {
	resource: Resource;
	action: Action;
	checked: boolean;
	disabled: boolean;
	onChange(checked: boolean): void;
}) {
	const access = useHostedOrganizationPermission(
		client,
		userId,
		organizationId,
		resource,
		action,
	);
	return (
		<label className="flex items-center gap-2 text-sm capitalize">
			<input
				type="checkbox"
				checked={checked}
				disabled={disabled || access.isLoading || (!checked && !access.data)}
				onChange={(event) => onChange(event.target.checked)}
			/>
			{action}
		</label>
	);
}
