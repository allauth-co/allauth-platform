import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { ownedSCIMScopedKey } from "./owned-project-scim-authority";
import { reconcileOwnedSCIMDirectory } from "./owned-project-scim-directory-writes";
import type { OwnedSCIMManagedConnection } from "./owned-project-scim-management-store";
import {
	ownedSCIMManagementFailure,
	ownedSCIMManagementStore,
} from "./owned-project-scim-management-store";

const leaseDurationMs = 5 * 60_000;
const batchSize = 50;

interface Binding {
	id: string;
	connectionId: string;
	provisioningDomainId: string;
	decommissionedAt: Date | null;
	decommissionStatus: "active" | "reconciling" | "complete";
	decommissionCursorUserId: string | null;
	decommissionReconciledUserCount: number;
	decommissionBatchCount: number;
	decommissionRevision: number;
	decommissionCompletedAt: Date | null;
	decommissionLeaseId: string | null;
	decommissionLeaseExpiresAt: Date | null;
}

const lifecycleChanged = () =>
	ownedSCIMManagementFailure(
		409,
		"SCIM connection lifecycle changed; retry the request.",
	);

function renewedAt(at: Date) {
	return new Date(at.getTime() + leaseDurationMs);
}

export function ownedSCIMDecommissionResult(binding: Binding) {
	return {
		connectionId: binding.connectionId,
		provisioningDomainId: binding.provisioningDomainId,
		status: binding.decommissionStatus,
		decommissionedAt: binding.decommissionedAt,
		completedAt: binding.decommissionCompletedAt,
		retryAfter: binding.decommissionLeaseExpiresAt,
		reconciledUsers: binding.decommissionReconciledUserCount,
		batches: binding.decommissionBatchCount,
	};
}

export function ownedSCIMDecommissionStore(
	client: PoolClient,
	organizationId: string,
	actorId: string,
	connectionId: string,
	credentialHashSecret: string,
) {
	const store = ownedSCIMManagementStore(
		client,
		organizationId,
		actorId,
		credentialHashSecret,
	);
	const domain = `organization:${organizationId}`;
	const connectionKey = ownedSCIMScopedKey(["scim-connection", connectionId]);
	const path =
		"/api/organizations/:organizationId/scim/:connectionId/decommission";

	async function lockOrganization() {
		const organization = await client.query(
			`SELECT id FROM "organization" WHERE id = $1 FOR KEY SHARE`,
			[organizationId],
		);
		if (!organization.rowCount)
			throw ownedSCIMManagementFailure(404, "The request is not permitted.");
	}

	async function getBinding(lock: boolean) {
		const result = await client.query<Binding>(
			`SELECT * FROM "scimConnectionBinding" WHERE "connectionKey" = $1${lock ? " FOR UPDATE" : ""}`,
			[connectionKey],
		);
		const binding = result.rows[0];
		if (
			binding &&
			(binding.connectionId !== connectionId ||
				binding.provisioningDomainId !== domain)
		)
			throw lifecycleChanged();
		return binding;
	}

	async function completedReplay(connection: OwnedSCIMManagedConnection) {
		// The console reports each authorized terminal response to existing
		// subscribers. The transition audit and managed revision are written once.
		await store.recordDirectoryEvent("directory.decommissioned", connectionId);
		return {
			...(await store.state(connection)),
			decommission: { status: "complete" as const, retryAfter: null },
		};
	}

	async function begin() {
		await lockOrganization();
		let connection = await store.lockBoundConnection(connectionId);
		if (connection.status === "decommissioned")
			return { response: await completedReplay(connection) };
		if (connection.status === "active") {
			const at = new Date();
			const update = await client.query<OwnedSCIMManagedConnection>(
				`UPDATE "scimManagedConnection" SET status = 'decommissioning', revision = revision + 1,
				 "decommissionStartedAt" = $2, "decommissionStartedBy" = $3 WHERE id = $1 RETURNING *`,
				[connection.id, at, actorId],
			);
			connection = update.rows[0]!;
			// Resource writes already holding credential locks must finish before the core binding is fenced.
			await client.query(
				`UPDATE "scimManagedCredential" SET status = 'decommissioned',
				 "activeSlotKey" = "credentialId" || ':inactive', "decommissionedAt" = $2
				 WHERE "connectionRecordId" = $1 AND status = 'active'`,
				[connection.id, at],
			);
			await store.event(
				connection.id,
				connection.revision,
				"connection.decommissioning",
				at,
			);
		}
		if (connection.status !== "decommissioning") throw lifecycleChanged();

		let binding = await getBinding(true);
		if (!binding) {
			const at = new Date();
			// An unused connector has no core binding. Preserve the native terminal shape for it.
			await client.query(
				`INSERT INTO "scimConnectionBinding"
				 (id,"connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionedAt","decommissionCompletedAt","decommissionReconciledUserCount","decommissionBatchCount","decommissionRevision")
				 SELECT $1,$2,$3,$4,$5::timestamptz,CASE WHEN used THEN 'active' ELSE 'complete' END,
				 CASE WHEN used THEN NULL ELSE $5 END,CASE WHEN used THEN NULL ELSE $5 END,0,0,0
				 FROM (SELECT EXISTS(SELECT 1 FROM "scimUser" WHERE "connectionId" = $2 AND "provisioningDomainId" = $4) AS used) source
				 ON CONFLICT ("connectionKey") DO NOTHING`,
				[randomUUID(), connectionId, connectionKey, domain, at],
			);
			binding = await getBinding(true);
			if (!binding) throw lifecycleChanged();
		}
		if (binding.decommissionStatus === "complete") return { binding };
		const now = new Date();
		if (
			binding.decommissionStatus === "reconciling" &&
			binding.decommissionLeaseId &&
			binding.decommissionLeaseExpiresAt &&
			binding.decommissionLeaseExpiresAt > now
		)
			return {
				response: {
					...(await store.state(connection)),
					decommission: ownedSCIMDecommissionResult(binding),
				},
			};
		if (
			binding.decommissionStatus !== "reconciling" &&
			binding.decommissionStatus !== "active"
		)
			throw lifecycleChanged();
		const leaseId = randomUUID();
		const acquired = await client.query<Binding>(
			`UPDATE "scimConnectionBinding" SET "decommissionStatus" = 'reconciling',
			 "decommissionedAt" = coalesce("decommissionedAt", $2), "decommissionCompletedAt" = NULL,
			 "decommissionLeaseId" = $3, "decommissionLeaseExpiresAt" = $4,
			 "decommissionRevision" = "decommissionRevision" + 1 WHERE id = $1 RETURNING *`,
			[binding.id, now, leaseId, renewedAt(now)],
		);
		return { binding: acquired.rows[0]!, leaseId };
	}

	async function advance(leaseId: string) {
		await lockOrganization();
		const stored = await getBinding(false);
		if (!stored) throw lifecycleChanged();
		if (stored.decommissionStatus === "complete") return stored;
		if (
			stored.decommissionStatus !== "reconciling" ||
			stored.decommissionLeaseId !== leaseId
		)
			throw lifecycleChanged();
		const { rows: candidates } = await client.query<{ userId: string }>(
			`SELECT "userId" FROM "scimUser" WHERE "provisioningDomainId" = $1
			 AND ($2::text IS NULL OR "userId" > $2) ORDER BY "userId" ASC LIMIT $3`,
			[domain, stored.decommissionCursorUserId, batchSize + 1],
		);
		const page = candidates.slice(0, batchSize);
		const users = [...new Set(page.map(({ userId }) => userId))].sort();
		// Use the same subject-before-connection lock order as SCIM resource and SSO writes.
		for (const userId of users) {
			const subject = await client.query(
				`UPDATE "scimSubject" SET revision = revision + 1, "updatedAt" = statement_timestamp() WHERE "userId" = $1`,
				[userId],
			);
			if (!subject.rowCount)
				throw new Error("SCIM projection subject is missing.");
		}
		const locked = await getBinding(true);
		if (
			!locked ||
			locked.id !== stored.id ||
			locked.decommissionStatus !== "reconciling" ||
			locked.decommissionLeaseId !== leaseId ||
			locked.decommissionRevision !== stored.decommissionRevision
		)
			throw lifecycleChanged();
		await client.query(
			`UPDATE "scimConnectionBinding" SET "decommissionLeaseExpiresAt" = $2 WHERE id = $1`,
			[locked.id, renewedAt(new Date())],
		);
		for (const userId of users)
			await reconcileOwnedSCIMDirectory(
				client,
				userId,
				organizationId,
				domain,
				path,
			);

		const hasMore = candidates.length > batchSize;
		const now = new Date();
		const advanced = await client.query<Binding>(
			`UPDATE "scimConnectionBinding" SET "decommissionRevision" = "decommissionRevision" + 1,
			 "decommissionCursorUserId" = $2,
			 "decommissionReconciledUserCount" = "decommissionReconciledUserCount" + $3,
			 "decommissionBatchCount" = "decommissionBatchCount" + $4,
			 "decommissionStatus" = $5, "decommissionCompletedAt" = $6,
			 "decommissionLeaseId" = $7, "decommissionLeaseExpiresAt" = $8 WHERE id = $1 RETURNING *`,
			[
				locked.id,
				page.at(-1)?.userId ?? stored.decommissionCursorUserId,
				users.length,
				page.length ? 1 : 0,
				hasMore ? "reconciling" : "complete",
				hasMore ? null : now,
				hasMore ? leaseId : null,
				hasMore ? renewedAt(now) : null,
			],
		);
		return advanced.rows[0]!;
	}

	async function release(leaseId: string) {
		await client.query(
			`UPDATE "scimConnectionBinding" SET "decommissionRevision" = "decommissionRevision" + 1,
			 "decommissionLeaseId" = NULL, "decommissionLeaseExpiresAt" = NULL
			 WHERE "connectionKey" = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3
			 AND "decommissionStatus" = 'reconciling' AND "decommissionLeaseId" = $4`,
			[connectionKey, connectionId, domain, leaseId],
		);
	}

	async function complete() {
		await lockOrganization();
		let connection = await store.lockBoundConnection(connectionId);
		if (connection.status === "decommissioned")
			return completedReplay(connection);
		const binding = await getBinding(false);
		if (
			connection.status !== "decommissioning" ||
			binding?.decommissionStatus !== "complete"
		)
			throw lifecycleChanged();
		const at = new Date();
		const updated = await client.query<OwnedSCIMManagedConnection>(
			`UPDATE "scimManagedConnection" SET status = 'decommissioned', revision = revision + 1,
			 "decommissionedAt" = $2, "decommissionedBy" = $3 WHERE id = $1 RETURNING *`,
			[connection.id, at, actorId],
		);
		connection = updated.rows[0]!;
		await store.event(
			connection.id,
			connection.revision,
			"connection.decommissioned",
			at,
		);
		await store.audit("directory.decommissioned", connectionId);
		return {
			...(await store.state(connection)),
			decommission: ownedSCIMDecommissionResult(binding),
		};
	}

	return { begin, advance, release, complete };
}
