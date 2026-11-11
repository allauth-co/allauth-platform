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

export function useConsoleWorkspaces() {
	return useQuery({
		queryKey: ["console-workspaces"],
		queryFn: () => managementRequest<WorkspaceList>("/api/workspaces"),
	});
}
