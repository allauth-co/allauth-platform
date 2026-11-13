import type { PoolClient } from "pg";
import type { ControlPrincipal } from "../control/types";
import type {
	Conflict,
	ImportResult,
	ImportUser,
} from "./clerk-import-contract";
import {
	canonical,
	clerkImportBody,
	digest,
	importedId,
} from "./clerk-import-contract";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";

export const ownedClerkImportPath = "/project-admin/import-clerk-users";

type Store = ReturnType<typeof createProjectEngineStore>;

async function inspect(
	client: PoolClient,
	user: ImportUser,
	userId: string,
	sourceInstance: string,
	fingerprint: string,
): Promise<Conflict | "existing" | undefined> {
	const existing = (
		await client.query<{ privateMetadata: Record<string, unknown> | null }>(
			'SELECT "privateMetadata" FROM "user" WHERE id=$1 FOR SHARE',
			[userId],
		)
	).rows[0];
	if (existing) {
		const provenance = existing.privateMetadata?.allauthClerkMigration;
		if (
			!provenance ||
			typeof provenance !== "object" ||
			!("sourceInstance" in provenance) ||
			!("sourceUserId" in provenance) ||
			provenance.sourceInstance !== sourceInstance ||
			provenance.sourceUserId !== user.sourceUserId
		)
			return "source_conflict";
		return "fingerprint" in provenance && provenance.fingerprint === fingerprint
			? "existing"
			: "source_changed";
	}
	if (user.twoFactorEnabled) return "mfa_unsupported";
	if (
		(await client.query('SELECT 1 FROM "user" WHERE email=$1', [user.email]))
			.rowCount
	)
		return "email_conflict";
	for (const account of user.socialAccounts) {
		if (
			(
				await client.query(
					'SELECT 1 FROM "account" WHERE "providerId"=$1 AND "accountId"=$2 LIMIT 1',
					[account.provider, account.subject],
				)
			).rowCount
		)
			return "provider_conflict";
	}
	return undefined;
}

async function writeUser(
	client: PoolClient,
	user: ImportUser,
	userId: string,
	sourceInstance: string,
	fingerprint: string,
) {
	const now = new Date();
	const createdAt = user.createdAt ? new Date(user.createdAt) : now;
	const updatedAt = user.updatedAt ? new Date(user.updatedAt) : now;
	const restricted = user.banned || user.locked;
	const provenance = {
		version: 1,
		sourceInstance,
		sourceUserId: user.sourceUserId,
		fingerprint,
		sourceUpdatedAt: user.updatedAt || null,
		banned: user.banned,
		locked: user.locked,
	};
	await client.query(
		`INSERT INTO "user" (
		  id,name,email,"emailVerified",image,"createdAt","updatedAt",role,banned,"banReason",
		  "twoFactorEnabled","isAnonymous","publicMetadata","privateMetadata")
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'user',$8,$9,false,false,$10::jsonb,$11::jsonb)`,
		[
			userId,
			user.name,
			user.email,
			user.emailVerified,
			user.image ?? null,
			createdAt,
			updatedAt,
			restricted,
			restricted ? "Restricted in source identity provider" : null,
			user.publicMetadata ? JSON.stringify(user.publicMetadata) : null,
			JSON.stringify({
				...user.privateMetadata,
				allauthClerkMigration: provenance,
			}),
		],
	);
	if (user.passwordHash)
		await client.query(
			`INSERT INTO "account" (id,"accountId","providerId","userId",password,"createdAt","updatedAt")
			 VALUES ($1,$2,'credential',$2,$3,$4,$5)`,
			[
				`clerk_credential_${digest(userId)}`,
				userId,
				user.passwordHash,
				createdAt,
				updatedAt,
			],
		);
	for (const account of user.socialAccounts) {
		const id = `clerk_social_${digest(JSON.stringify([account.provider, account.subject]))}`;
		await client.query(
			`INSERT INTO "account" (id,"accountId","providerId","userId","createdAt","updatedAt")
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			[id, account.subject, account.provider, userId, createdAt, updatedAt],
		);
	}
}

const forbidden = () =>
	accountLinkError(
		403,
		"FORBIDDEN",
		"A verified workspace administrator is required.",
	);

/** Import each Clerk account and its audit entry in the selected project transaction. */
export function createOwnedProjectClerkImport(options: {
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
		if (path !== ownedClerkImportPath || request.method !== "POST") return null;
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
		const parsed = clerkImportBody.safeParse(await options.readBody(request));
		if (!parsed.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"The request contains invalid fields.",
			);

		const { dryRun, sourceInstance, users } = parsed.data;
		const userAgent = request.headers.get("user-agent") ?? undefined;
		const results: ImportResult[] = [];
		const seenEmails = new Set<string>();
		const seenProviders = new Set<string>();
		for (const user of users) {
			const userId = importedId(project.id, sourceInstance, user.sourceUserId);
			const fingerprint = digest(canonical(user));
			const providers = user.socialAccounts.map((account) => ({
				...account,
				key: JSON.stringify([account.provider, account.subject]),
			}));
			const result = (
				status: ImportResult["status"],
				reason?: Conflict,
			): ImportResult => ({
				sourceUserId: user.sourceUserId,
				sourceUpdatedAt: user.updatedAt
					? new Date(user.updatedAt).toISOString()
					: null,
				...(status === "conflict" ? {} : { userId }),
				status,
				...(reason ? { reason } : {}),
			});
			if (
				seenEmails.has(user.email) ||
				providers.some(({ key }) => seenProviders.has(key))
			) {
				results.push(
					result(
						"conflict",
						seenEmails.has(user.email) ? "email_conflict" : "provider_conflict",
					),
				);
				continue;
			}
			let entry: ImportResult | null;
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
					if (!dryRun) {
						// Serialize each subject with live OAuth account binding. A batch uses
						// consistent lock ordering so two imports cannot deadlock each other.
						for (const { provider, subject } of providers.sort((a, b) =>
							a.key < b.key ? -1 : a.key > b.key ? 1 : 0,
						))
							await store.lockProviderIdentity(client, provider, subject);
					}
					const status = await inspect(
						client,
						user,
						userId,
						sourceInstance,
						fingerprint,
					);
					if (status)
						return status === "existing"
							? result("existing")
							: result("conflict", status);
					if (dryRun) return result("would_create");
					await writeUser(client, user, userId, sourceInstance, fingerprint);
					await store.recordEvent(client, {
						type: "admin.clerk-import",
						outcome: "success",
						actorId: actor.user.id,
						userId,
						targetId: userId,
						userAgent,
						metadata: {
							path: ownedClerkImportPath,
							signal: "clerk-import",
							version: 1,
						},
					});
					return result("created");
				});
			} catch {
				// PostgreSQL errors can include plaintext bind values.
				entry = result("conflict", "write_conflict");
			}
			if (!entry) return forbidden();
			results.push(entry);
			if (entry.status !== "conflict") {
				seenEmails.add(user.email);
				for (const { key } of providers) seenProviders.add(key);
			}
		}
		return accountLinkJson({
			project: project.slug,
			projectId: project.id,
			sourceInstance,
			dryRun,
			created: results.filter(({ status }) => status === "created").length,
			existing: results.filter(({ status }) => status === "existing").length,
			conflicts: results.filter(({ status }) => status === "conflict").length,
			users: results,
		});
	};
}
