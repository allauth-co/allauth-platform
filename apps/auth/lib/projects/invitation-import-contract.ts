import { createHash } from "node:crypto";
import * as z from "zod";

const sourceId = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const id = z.string().min(1).max(160);
export const invitationImportInput = z
	.object({
		sourceInstance: sourceId,
		dryRun: z.boolean().default(true),
		invitations: z
			.array(
				z
					.object({
						sourceInvitationId: sourceId,
						organizationId: id,
						email: z
							.email()
							.max(320)
							.transform((value) => value.toLowerCase()),
						role: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/),
						inviterId: id,
						expiresAt: z.iso.datetime({ offset: true }),
						createdAt: z.iso.datetime({ offset: true }).optional(),
						sourceUpdatedAt: z.iso.datetime({ offset: true }).optional(),
					})
					.strict(),
			)
			.min(1)
			.max(100),
	})
	.strict()
	.superRefine((value, ctx) => {
		if (
			new Set(value.invitations.map((row) => row.sourceInvitationId)).size !==
			value.invitations.length
		)
			ctx.addIssue({ code: "custom", message: "Duplicate source invitation." });
		if (
			new TextEncoder().encode(JSON.stringify(value)).byteLength >
			1024 * 1024
		)
			ctx.addIssue({
				code: "custom",
				message: "Import batches must not exceed 1 MiB.",
			});
	});
export type InvitationImportRow = z.output<
	typeof invitationImportInput
>["invitations"][number];
export type InvitationImportConflict =
	| "source_changed"
	| "source_conflict"
	| "organization_missing"
	| "invalid_inviter"
	| "role_missing"
	| "membership_conflict"
	| "invitation_conflict"
	| "expired"
	| "write_conflict";
export type InvitationImportStatus =
	| "created"
	| "existing"
	| "would_create"
	| "conflict";
export interface InvitationImportResult {
	sourceInvitationId: string;
	sourceUpdatedAt: string | null;
	invitationId?: string;
	status: InvitationImportStatus;
	nativeStatus?: string;
	reason?: InvitationImportConflict;
}

export const invitationImportPath = "/project-admin/import-invitations";
const digest = (value: string) =>
	createHash("sha256").update(value).digest("hex");

export function invitationImportIdentity(
	projectId: string,
	sourceInstance: string,
	input: InvitationImportRow,
) {
	const identity = digest(
		JSON.stringify([projectId, sourceInstance, input.sourceInvitationId]),
	);
	return {
		identity,
		invitationId: `imported_${identity}`,
		fingerprint: digest(JSON.stringify(input)),
	};
}

export function invitationImportResult(
	input: InvitationImportRow,
	invitationId: string,
	status: InvitationImportStatus,
	reason?: InvitationImportConflict,
	nativeStatus?: string,
): InvitationImportResult {
	return {
		sourceInvitationId: input.sourceInvitationId,
		sourceUpdatedAt: input.sourceUpdatedAt
			? new Date(input.sourceUpdatedAt).toISOString()
			: null,
		...(status === "conflict" ? {} : { invitationId }),
		status,
		...(reason ? { reason } : {}),
		...(nativeStatus ? { nativeStatus } : {}),
	};
}

export function storedInvitationCreatePermission(value: string): boolean {
	try {
		const permission: unknown = JSON.parse(value);
		return Boolean(
			permission &&
				typeof permission === "object" &&
				"invitation" in permission &&
				Array.isArray(permission.invitation) &&
				permission.invitation.includes("create"),
		);
	} catch {
		return false;
	}
}
