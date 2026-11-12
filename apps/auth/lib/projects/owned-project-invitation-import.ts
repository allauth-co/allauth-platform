import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { ControlPrincipal } from "../control/types";
import type {
	InvitationImportConflict,
	InvitationImportResult,
	InvitationImportRow,
	InvitationImportStatus,
} from "./invitation-import-contract";
import {
	invitationImportIdentity,
	invitationImportInput,
	invitationImportPath,
	invitationImportResult,
	storedInvitationCreatePermission,
} from "./invitation-import-contract";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import {
	hasOrganizationPermission,
	isBuiltInOrganizationRole,
	organizationRolePermissions,
} from "./owned-project-organization-access";
import { projectOrganizations } from "./owned-project-organization-store";
import type { Project } from "./registry";

type Store = ReturnType<typeof createProjectEngineStore>;
const builtInRoles = organizationRolePermissions([]);

async function validate(
	client: PoolClient,
	input: InvitationImportRow,
	dryRun: boolean,
): Promise<InvitationImportConflict | undefined> {
	const expiresAt = new Date(input.expiresAt);
	if (
		expiresAt.getTime() <= Date.now() ||
		(input.createdAt && new Date(input.createdAt) >= expiresAt)
	)
		return "expired";
	const realm = projectOrganizations(client);
	// Ordinary organization mutations lock the actor before the organization.
	const inviter = (
		await client.query<{
			emailVerified: boolean;
			banned: boolean | null;
			directoryDisabled: boolean | null;
		}>(
			`SELECT "emailVerified", banned, "directoryDisabled" FROM "user" WHERE id=$1${dryRun ? "" : " FOR SHARE"}`,
			[input.inviterId],
		)
	).rows[0];
	if (
		!(await realm.organization(
			input.organizationId,
			"id",
			dryRun ? false : "write",
		))
	)
		return "organization_missing";
	if (expiresAt.getTime() <= Date.now()) return "expired";
	const roles = await realm.roles(input.organizationId, !dryRun);
	if (
		!isBuiltInOrganizationRole(input.role) &&
		!roles.some(({ role }) => role === input.role)
	)
		return "role_missing";
	if (!inviter?.emailVerified || inviter.banned || inviter.directoryDisabled)
		return "invalid_inviter";
	const member = await realm.member(
		input.inviterId,
		input.organizationId,
		!dryRun,
	);
	const mayInvite = member?.role
		.split(",")
		.map((role) => role.trim())
		.some((role) => {
			if (
				builtInRoles &&
				hasOrganizationPermission(builtInRoles, role, {
					invitation: ["create"],
				})
			)
				return true;
			const custom = roles.find((entry) => entry.role === role);
			return Boolean(
				custom && storedInvitationCreatePermission(custom.permission),
			);
		});
	if (!mayInvite) return "invalid_inviter";
	if (await realm.memberByEmail(input.organizationId, input.email))
		return "membership_conflict";
	if (await realm.pendingInvitation(input.organizationId, input.email))
		return "invitation_conflict";
}

async function writeInvitation(
	client: PoolClient,
	input: InvitationImportRow,
	keys: ReturnType<typeof invitationImportIdentity>,
	sourceInstance: string,
	actorId: string,
	userAgent: string | null,
) {
	const { identity, invitationId, fingerprint } = keys;
	await client.query(
		`INSERT INTO "invitation" (id,"organizationId",email,role,"inviterId",status,"expiresAt","createdAt")
		 VALUES ($1,$2,$3,$4,$5,'pending',$6,coalesce($7::timestamptz,statement_timestamp()))`,
		[
			invitationId,
			input.organizationId,
			input.email,
			input.role,
			input.inviterId,
			input.expiresAt,
			input.createdAt ?? null,
		],
	);
	await client.query(
		`INSERT INTO "allauthInvitationImport" (id,"sourceInstance","sourceInvitationId","invitationId",fingerprint,"sourceUpdatedAt")
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		[
			identity,
			sourceInstance,
			input.sourceInvitationId,
			invitationId,
			fingerprint,
			input.sourceUpdatedAt ?? null,
		],
	);
	await client.query(
		`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","organizationId","targetId","userAgent","createdAt",metadata)
		 VALUES ($1,'admin.invitation-import','success',$2,$3,$4,$5,statement_timestamp(),
		  jsonb_build_object('signal','invitation-import','version',1))`,
		[randomUUID(), actorId, input.organizationId, invitationId, userAgent],
	);
}

const forbidden = () =>
	accountLinkError(
		403,
		"FORBIDDEN",
		"A verified workspace administrator is required.",
	);

/** Preserve native source provenance and create pending invitations without delivery side effects. */
export function createOwnedProjectInvitationImport(options: {
	store: Store;
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">;
	origin: string;
	basePath: string;
	platformOrigin: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	readBody(request: Request): Promise<unknown>;
}) {
	const { project, store } = options;
	const direct = `/api/projects/${project.slug}/auth`;
	return async (request: Request, path: string) => {
		if (path !== invitationImportPath || request.method !== "POST") return null;
		const url = new URL(request.url);
		if (
			options.basePath !== direct ||
			options.origin !== options.platformOrigin ||
			url.origin !== options.platformOrigin ||
			url.pathname !== direct + path ||
			request.headers.has("authorization") ||
			request.headers.get("origin") !== options.platformOrigin ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			return forbidden();
		const actor = await options.readWorkspacePrincipal(request.headers);
		if (
			!actor ||
			actor.session.userId !== actor.user.id ||
			actor.session.impersonatedBy ||
			!actor.user.emailVerified ||
			actor.user.banned
		)
			return forbidden();
		const parsed = invitationImportInput.safeParse(
			await options.readBody(request),
		);
		if (!parsed.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"The request contains invalid fields.",
			);
		const { dryRun, sourceInstance, invitations } = parsed.data;
		const userAgent =
			request.headers
				.get("user-agent")
				?.slice(0, 512)
				.replace(/[\u0000-\u001f]/g, "") || null;
		const seen = new Set<string>();
		const results: InvitationImportResult[] = [];
		for (const input of invitations) {
			const keys = invitationImportIdentity(project.id, sourceInstance, input);
			const { identity, invitationId, fingerprint } = keys;
			const destination = JSON.stringify([input.organizationId, input.email]);
			const result = (
				status: InvitationImportStatus,
				reason?: InvitationImportConflict,
				nativeStatus?: string,
			) =>
				invitationImportResult(
					input,
					invitationId,
					status,
					reason,
					nativeStatus,
				);
			let entry: InvitationImportResult | null;
			try {
				entry = await store.transaction(async (client) => {
					if (
						!(await lockOwnedProjectWorkspaceAdministrator(
							client,
							project,
							actor,
						))
					)
						return null;
					if (!dryRun)
						await client.query(
							"SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':invitation-import:' || $1, 0))",
							[identity],
						);
					const prior = (
						await client.query<{ fingerprint: string; status: string | null }>(
							`SELECT p.fingerprint, i.status FROM "allauthInvitationImport" p
						 LEFT JOIN "invitation" i ON i.id=p."invitationId" WHERE p.id=$1`,
							[identity],
						)
					).rows[0];
					if (prior) {
						if (prior.fingerprint !== fingerprint)
							return result("conflict", "source_changed");
						return prior.status === null
							? result("conflict", "source_conflict")
							: result("existing", undefined, prior.status);
					}
					if (
						(
							await client.query('SELECT 1 FROM "invitation" WHERE id=$1', [
								invitationId,
							])
						).rowCount
					)
						return result("conflict", "source_conflict");
					const invalid = await validate(client, input, dryRun);
					if (invalid) return result("conflict", invalid);
					if (seen.has(destination))
						return result("conflict", "invitation_conflict");
					if (dryRun) return result("would_create");
					await writeInvitation(
						client,
						input,
						keys,
						sourceInstance,
						actor.user.id,
						userAgent,
					);
					return result("created", undefined, "pending");
				});
			} catch {
				entry = result("conflict", "write_conflict");
			}
			if (!entry) return forbidden();
			results.push(entry);
			if (entry.status !== "conflict") seen.add(destination);
		}
		return accountLinkJson({
			project: project.slug,
			projectId: project.id,
			sourceInstance,
			dryRun,
			created: results.filter(({ status }) => status === "created").length,
			existing: results.filter(({ status }) => status === "existing").length,
			conflicts: results.filter(({ status }) => status === "conflict").length,
			invitations: results,
		});
	};
}
