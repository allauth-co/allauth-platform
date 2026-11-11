"use client";

import { useQuery } from "@tanstack/react-query";
import type { WorkspaceRole, workspaceLimits } from "@/lib/workspaces/types";
import { managementRequest } from "./common";
export {
	canManageWorkspace,
	workspaceProjectQueryKey,
	workspaceProjectsPath,
} from "@/lib/console/workspace-navigation";

export type WorkspaceLimits = ReturnType<typeof workspaceLimits>;
export interface ConsoleWorkspace {
	id: string;
	name: string;
	slug: string;
	protected: boolean;
	createdBy: string | null;
	createdAt: string;
	updatedAt: string;
	role: WorkspaceRole | "platform-admin";
	applicationCount: number;
	environmentCount: number;
	memberCount: number;
}
export interface WorkspaceList {
	workspaces: ConsoleWorkspace[];
	limits: WorkspaceLimits;
	platformAdmin: boolean;
}
export interface ConsoleWorkspaceMember {
	id: string;
	userId: string;
	name: string;
	email: string;
	role: WorkspaceRole;
	createdAt: string;
}
export interface ConsoleWorkspaceInvitation {
	id: string;
	workspaceId: string;
	email: string;
	role: WorkspaceRole;
	status: "pending" | "accepted" | "cancelled";
	expiresAt: string;
	createdAt: string;
	emailDelivery?: "accepted" | "failed" | null;
}
export interface WorkspaceDetail {
	workspace: ConsoleWorkspace;
	members: ConsoleWorkspaceMember[];
	invitations: ConsoleWorkspaceInvitation[];
	permissions: { manage: boolean; manageOwners: boolean };
	limits: WorkspaceLimits;
}

export function isConsoleWorkspaceId(id: string | undefined): id is string {
	return typeof id === "string" && /^[a-zA-Z0-9_-]+$/.test(id);
}

export function workspacePath(id: string) {
	return `/api/workspaces/${encodeURIComponent(id)}`;
}

export function workspaceDetailQueryKey(id?: string) {
	return ["console-workspace", id] as const;
}

export function useConsoleWorkspaceDetail(id?: string, enabled = true) {
	return useQuery({
		queryKey: workspaceDetailQueryKey(id),
		queryFn: ({ signal }) => managementRequest<WorkspaceDetail>(workspacePath(id!), { signal }),
		enabled: enabled && isConsoleWorkspaceId(id),
	});
}

/** Directory links can select an authorized workspace outside the capped picker. */
export function useSelectedConsoleWorkspace(id: string | undefined, picker?: WorkspaceList) {
	const listed = picker?.workspaces.find((workspace) => workspace.id === id);
	const needsDetail = !!picker && !listed && isConsoleWorkspaceId(id);
	const detail = useConsoleWorkspaceDetail(id, needsDetail);
	const fetched = needsDetail && !detail.error ? detail.data?.workspace : undefined;
	return {
		workspace: listed ?? (fetched?.id === id ? fetched : undefined),
		isPending: needsDetail && detail.isPending,
		error: needsDetail ? detail.error : null,
	};
}

export function useConsoleWorkspaces() {
	return useQuery({
		queryKey: ["console-workspaces"],
		queryFn: () => managementRequest<WorkspaceList>("/api/workspaces"),
	});
}
