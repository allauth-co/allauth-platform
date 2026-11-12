import type { GenericEndpointContext } from "@better-auth/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@better-auth/core/context";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import { createAuthEndpoint } from "better-auth/api";
import { defaultRoles } from "better-auth/plugins/organization/access";
import type { ControlEventInput, ControlPrincipal } from "../control/types";

import type {
	InvitationImportConflict as Conflict,
	InvitationImportRow as Input,
	InvitationImportResult,
	InvitationImportStatus,
} from "./invitation-import-contract";
import {
	invitationImportIdentity,
	invitationImportInput,
	invitationImportPath,
	invitationImportResult,
	storedInvitationCreatePermission,
} from "./invitation-import-contract";

export { invitationImportInput } from "./invitation-import-contract";

interface Provenance {
	id: string;
	fingerprint: string;
	invitationId: string;
}
interface NativeInvitation {
	id: string;
	status: string;
}

async function mayInvite(
	adapter: DBTransactionAdapter,
	organizationId: string,
	inviterId: string,
) {
	const user = await adapter.findOne<{
		emailVerified: boolean;
		banned?: boolean;
		directoryDisabled?: boolean;
	}>({
		model: "user",
		where: [{ field: "id", value: inviterId }],
		select: ["id", "emailVerified", "banned", "directoryDisabled"],
	});
	if (!user?.emailVerified || user.banned || user.directoryDisabled)
		return false;
	const member = await adapter.findOne<{ role: string }>({
		model: "member",
		where: [
			{ field: "organizationId", value: organizationId },
			{ field: "userId", value: inviterId },
		],
	});
	if (!member) return false;
	for (const role of member.role.split(",").map((value) => value.trim())) {
		if (
			Object.hasOwn(defaultRoles, role) &&
			(
				defaultRoles[role as keyof typeof defaultRoles].statements
					.invitation as readonly string[]
			).includes("create")
		)
			return true;
		const custom = await adapter.findOne<{ permission: string }>({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: organizationId },
				{ field: "role", value: role },
			],
		});
		if (custom && storedInvitationCreatePermission(custom.permission))
			return true;
	}
	return false;
}
async function validate(
	adapter: DBTransactionAdapter,
	input: Input,
): Promise<Conflict | undefined> {
	if (
		new Date(input.expiresAt) <= new Date() ||
		(input.createdAt && new Date(input.createdAt) >= new Date(input.expiresAt))
	)
		return "expired";
	if (
		!(await adapter.findOne({
			model: "organization",
			where: [{ field: "id", value: input.organizationId }],
			select: ["id"],
		}))
	)
		return "organization_missing";
	if (
		!Object.hasOwn(defaultRoles, input.role) &&
		!(await adapter.findOne({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: input.organizationId },
				{ field: "role", value: input.role },
			],
			select: ["id"],
		}))
	)
		return "role_missing";
	if (!(await mayInvite(adapter, input.organizationId, input.inviterId)))
		return "invalid_inviter";
	const user = await adapter.findOne<{ id: string }>({
		model: "user",
		where: [{ field: "email", value: input.email }],
		select: ["id"],
	});
	if (
		user &&
		(await adapter.findOne({
			model: "member",
			where: [
				{ field: "organizationId", value: input.organizationId },
				{ field: "userId", value: user.id },
			],
			select: ["id"],
		}))
	)
		return "membership_conflict";
	if (
		await adapter.findOne({
			model: "invitation",
			where: [
				{ field: "organizationId", value: input.organizationId },
				{ field: "email", value: input.email },
				{ field: "status", value: "pending" },
				{ field: "expiresAt", operator: "gt", value: new Date() },
			],
			select: ["id"],
		})
	)
		return "invitation_conflict";
}

/** Privileged migration only: exact source provenance, native records, no mail or onboarding events. */
export function invitationImportEndpoint(options: {
	projectId: string;
	projectSlug?: string;
	authorize: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>;
	recordEvent: (
		ctx: GenericEndpointContext,
		event: ControlEventInput,
	) => Promise<void>;
}) {
	return createAuthEndpoint(
		invitationImportPath,
		{ method: "POST", requireHeaders: true, body: invitationImportInput },
		async (ctx) => {
			const actor = await options.authorize(ctx);
			const results: InvitationImportResult[] = [];
			const seen = new Set<string>();
			for (const input of ctx.body.invitations) {
				const { identity, invitationId, fingerprint } =
					invitationImportIdentity(
						options.projectId,
						ctx.body.sourceInstance,
						input,
					);
				const result = (
					status: InvitationImportStatus,
					reason?: Conflict,
					nativeStatus?: string,
				) =>
					invitationImportResult(
						input,
						invitationId,
						status,
						reason,
						nativeStatus,
					);
				const process = async () => {
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const provenance = await adapter.findOne<Provenance>({
						model: "allauthInvitationImport",
						where: [{ field: "id", value: identity }],
					});
					if (provenance) {
						if (provenance.fingerprint !== fingerprint)
							return result("conflict", "source_changed");
						const existing = await adapter.findOne<NativeInvitation>({
							model: "invitation",
							where: [{ field: "id", value: provenance.invitationId }],
						});
						return existing
							? result("existing", undefined, existing.status)
							: result("conflict", "source_conflict");
					}
					if (
						await adapter.findOne({
							model: "invitation",
							where: [{ field: "id", value: invitationId }],
							select: ["id"],
						})
					)
						return result("conflict", "source_conflict");
					const conflict = await validate(adapter, input);
					if (conflict) return result("conflict", conflict);
					const destination = JSON.stringify([
						input.organizationId,
						input.email,
					]);
					if (seen.has(destination))
						return result("conflict", "invitation_conflict");
					if (ctx.body.dryRun) return result("would_create");
					await adapter.create({
						model: "invitation",
						forceAllowId: true,
						data: {
							id: invitationId,
							organizationId: input.organizationId,
							email: input.email,
							role: input.role,
							inviterId: input.inviterId,
							status: "pending",
							expiresAt: new Date(input.expiresAt),
							createdAt: input.createdAt
								? new Date(input.createdAt)
								: new Date(),
						},
					});
					await adapter.create({
						model: "allauthInvitationImport",
						forceAllowId: true,
						data: {
							id: identity,
							sourceInstance: ctx.body.sourceInstance,
							sourceInvitationId: input.sourceInvitationId,
							invitationId,
							fingerprint,
							sourceUpdatedAt: input.sourceUpdatedAt
								? new Date(input.sourceUpdatedAt)
								: null,
							createdAt: new Date(),
						},
					});
					await options.recordEvent(ctx, {
						type: "admin.invitation-import",
						outcome: "success",
						actorId: actor.user.id,
						organizationId: input.organizationId,
						targetId: invitationId,
						metadata: { signal: "invitation-import", version: 1 },
					});
					return result("created", undefined, "pending");
				};
				let entry: ReturnType<typeof result>;
				try {
					entry = ctx.body.dryRun
						? await process()
						: await runWithTransaction(ctx.context.adapter, process);
				} catch {
					entry = result("conflict", "write_conflict");
				}
				results.push(entry);
				if (entry.status !== "conflict")
					seen.add(JSON.stringify([input.organizationId, input.email]));
			}
			return ctx.json({
				project: options.projectSlug ?? null,
				projectId: options.projectId,
				sourceInstance: ctx.body.sourceInstance,
				dryRun: ctx.body.dryRun,
				created: results.filter((row) => row.status === "created").length,
				existing: results.filter((row) => row.status === "existing").length,
				conflicts: results.filter((row) => row.status === "conflict").length,
				invitations: results,
			});
		},
	);
}

export const invitationImportSchema = {
	allauthInvitationImport: {
		fields: {
			sourceInstance: { type: "string", required: true },
			sourceInvitationId: { type: "string", required: true },
			invitationId: { type: "string", required: true },
			fingerprint: { type: "string", required: true },
			sourceUpdatedAt: { type: "date", required: false },
			createdAt: { type: "date", required: true },
		},
	},
} as const;
