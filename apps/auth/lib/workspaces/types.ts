import * as z from "zod";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import { reservedWorkspaceSlugs, workspaceSlugPattern } from "./slug";

export const platformWorkspaceId = "00000000-0000-4000-8000-000000000001";
export const workspaceRole = z.enum(["owner", "admin", "member"]);
export type WorkspaceRole = z.infer<typeof workspaceRole>;
export const workspaceSlugInput = z.string().regex(workspaceSlugPattern).refine((value) => !reservedWorkspaceSlugs.includes(value));
export const workspaceInput = z.object({ name: z.string().trim().min(2).max(100), slug: workspaceSlugInput.optional() }).strict();
export const workspaceUpdate = z.object({ name: z.string().trim().min(2).max(100) }).strict();
export const invitationInput = z.object({ email: z.email().max(320).transform((email) => email.toLowerCase()), role: workspaceRole.default("member") }).strict();
export const memberUpdate = z.object({ role: workspaceRole }).strict();
export interface Workspace { id: string; name: string; slug: string; protected: boolean; createdBy: string | null; createdAt: Date; updatedAt: Date }
export interface WorkspaceSummary extends Workspace { role: WorkspaceRole | "platform-admin"; applicationCount: number; environmentCount: number; memberCount: number }
export interface WorkspaceMember { id: string; userId: string; name: string; email: string; role: WorkspaceRole; createdAt: Date }
export interface WorkspaceInvitation { id: string; workspaceId: string; email: string; role: WorkspaceRole; status: "pending" | "accepted" | "cancelled"; invitedBy: string | null; acceptedBy: string | null; expiresAt: Date; createdAt: Date; updatedAt: Date }
/** Published self-service limits are server-owned and bounded even when environment settings are invalid. */
export function workspaceLimits(env: AuthEnvironment) {
	const value = (name: string, fallback: number, maximum: number) => { const raw = setting(env, name); return /^\d+$/.test(raw) && Number(raw) >= 1 && Number(raw) <= maximum ? Number(raw) : fallback; };
	return { ownedWorkspaces: value("WORKSPACE_MAX_OWNED", 3, 100), applicationsPerWorkspace: value("WORKSPACE_MAX_APPLICATIONS", 5, 100), environmentsPerApplication: 2, membersPerWorkspace: value("WORKSPACE_MAX_MEMBERS", 50, 1000), pendingInvitationsPerWorkspace: value("WORKSPACE_MAX_INVITATIONS", 20, 100), invitationExpiryDays: 7 };
}
