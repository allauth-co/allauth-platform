import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import {
	newOwnedSCIMConnectionId,
	newOwnedSCIMCredential,
	ownedSCIMCredentialHashVersion,
	ownedSCIMScopes,
	parseOwnedSCIMScopes,
} from "./owned-project-scim-managed-credentials";

type Client = Pick<PoolClient, "query">;
type ConnectionStatus = "active" | "decommissioning" | "decommissioned";
type CredentialStatus = "active" | "expired" | "revoked" | "decommissioned";
type ManagedEvent =
	| "connection.created"
	| "credential.issued"
	| "credential.rotated"
	| "credential.revoked"
	| "connection.decommissioning"
	| "connection.decommissioned";

export interface OwnedSCIMManagedConnection {
	id: string;
	revision: number;
	creationRequestId: string;
	connectionId: string;
	provisioningDomainId: string;
	status: ConnectionStatus;
	createdAt: Date;
	createdBy: string;
	decommissionStartedAt: Date | null;
	decommissionStartedBy: string | null;
	decommissionedAt: Date | null;
	decommissionedBy: string | null;
}

interface Credential {
	connectionRecordId: string;
	credentialId: string;
	status: CredentialStatus;
	serializedScopes: string;
	expiresAt: Date;
	createdAt: Date;
	createdBy: string;
	lastUsedAt: Date | null;
	revokedAt: Date | null;
	revokedBy: string | null;
}

const credentialColumns = `"connectionRecordId", "credentialId", status, "serializedScopes", "expiresAt", "createdAt", "createdBy", "lastUsedAt", "revokedAt", "revokedBy"`;
const maximumLiveCredentials = 5;
const credentialTtlMs = 90 * 24 * 60 * 60 * 1000;

export function ownedSCIMManagementJSON(body: object, status = 200) {
	return Response.json(body, {
		status,
		headers: {
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			"X-Content-Type-Options": "nosniff",
		},
	});
}

export function ownedSCIMManagementFailure(status: number, error: string) {
	return ownedSCIMManagementJSON({ error }, status);
}

function publicConnection(row: OwnedSCIMManagedConnection) {
	return {
		creationRequestId: row.creationRequestId,
		connectionId: row.connectionId,
		provisioningDomainId: row.provisioningDomainId,
		status: row.status,
		createdAt: row.createdAt,
		createdBy: row.createdBy,
		decommissionStartedAt: row.decommissionStartedAt,
		decommissionStartedBy: row.decommissionStartedBy,
		decommissionedAt: row.decommissionedAt,
		decommissionedBy: row.decommissionedBy,
	};
}

function publicCredential(row: Credential, now: Date) {
	const scopes = parseOwnedSCIMScopes(row.serializedScopes);
	if (!scopes)
		throw ownedSCIMManagementFailure(
			500,
			"Managed SCIM credential scope policy is invalid",
		);
	return {
		credentialId: row.credentialId,
		status:
			row.status === "active" && row.expiresAt <= now ? "expired" : row.status,
		scopes,
		expiresAt: row.expiresAt,
		createdAt: row.createdAt,
		createdBy: row.createdBy,
		lastUsedAt: row.lastUsedAt,
		revokedAt: row.revokedAt,
		revokedBy: row.revokedBy,
	};
}

function activeSlot(rowId: string, index: number) {
	return `${rowId}:active:${index}`;
}

/** Catalog transactions receive a checked project search path and a verified organization actor. */
export function ownedSCIMManagementStore(
	client: Client,
	organizationId: string,
	actorId: string,
	secret: string,
) {
	const domain = `organization:${organizationId}`;
	async function credentials(rowIds: string[]) {
		const result = await client.query<Credential>(
			`SELECT ${credentialColumns} FROM "scimManagedCredential"
			WHERE "connectionRecordId" = ANY($1::text[]) ORDER BY "createdAt" DESC`,
			[rowIds],
		);
		return result.rows;
	}
	async function list() {
		const { rows } = await client.query<
			OwnedSCIMManagedConnection & { providerId: string | null }
		>(
			`SELECT c.*, d."providerId"
			FROM "scimManagedConnection" c LEFT JOIN "allauthDirectory" d ON d."connectionId" = c."connectionId" AND d."organizationId" = $1
			WHERE c."provisioningDomainId" = $2 ORDER BY c."createdAt" DESC`,
			[organizationId, domain],
		);
		const grouped = new Map<string, ReturnType<typeof publicCredential>[]>();
		const now = new Date();
		if (rows.length) {
			for (const row of await credentials(
				rows.map((connection) => connection.id),
			)) {
				const list = grouped.get(row.connectionRecordId) ?? [];
				list.push(publicCredential(row, now));
				grouped.set(row.connectionRecordId, list);
			}
		}
		return rows.map((row) => ({
			connection: publicConnection(row),
			credentials: grouped.get(row.id) ?? [],
			...(row.providerId ? { providerId: row.providerId } : {}),
		}));
	}
	async function state(connection: OwnedSCIMManagedConnection) {
		const now = new Date();
		return {
			connection: publicConnection(connection),
			credentials: (await credentials([connection.id])).map((row) =>
				publicCredential(row, now),
			),
		};
	}
	async function event(
		connectionId: string,
		sequence: number,
		type: ManagedEvent,
		createdAt: Date,
		credentialId?: string,
	) {
		await client.query(
			`INSERT INTO "scimManagedConnectionEvent" (id, "connectionRecordId", "eventKey", sequence, type, "actorId", "credentialId", "createdAt")
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			[
				randomUUID(),
				connectionId,
				`${connectionId}:${sequence}`,
				sequence,
				type,
				actorId,
				credentialId ?? null,
				createdAt,
			],
		);
	}
	async function audit(
		action:
			| "directory.created"
			| "directory.credential.rotated"
			| "directory.credential.revoked"
			| "directory.decommissioned",
		target: string,
	) {
		await client.query(
			`INSERT INTO "allauthAudit" (id, "actorId", action, "targetId", "organizationId", "createdAt")
			VALUES ($1,$2,$3,$4,$5,statement_timestamp())`,
			[randomUUID(), actorId, action, target, organizationId],
		);
		await client.query(
			`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","targetId","organizationId","createdAt",metadata)
			VALUES ($1,$2,'success',$3,$4,$5,statement_timestamp(),'{}')`,
			[randomUUID(), action, actorId, target, organizationId],
		);
	}
	async function issueCredential(
		connection: OwnedSCIMManagedConnection,
		index: number,
		at: Date,
	) {
		const { credentialId, token, tokenDigest } = newOwnedSCIMCredential(secret);
		const { rows } = await client.query<Credential>(
			`INSERT INTO "scimManagedCredential"
			(id,"connectionRecordId","credentialId","tokenDigest","hashVersion","activeSlotKey",status,"serializedScopes","expiresAt","createdAt","createdBy")
			VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10) RETURNING ${credentialColumns}`,
			[
				randomUUID(),
				connection.id,
				credentialId,
				tokenDigest,
				ownedSCIMCredentialHashVersion,
				activeSlot(connection.id, index),
				JSON.stringify(ownedSCIMScopes),
				new Date(at.getTime() + credentialTtlMs),
				at,
				actorId,
			],
		);
		return { credential: publicCredential(rows[0]!, at), token };
	}
	async function lockBoundConnection(connectionId: string) {
		const result = await client.query<OwnedSCIMManagedConnection>(
			`SELECT c.* FROM "scimManagedConnection" c JOIN "allauthDirectory" d
			ON d."connectionId" = c."connectionId" AND d."organizationId" = $1
			WHERE c."provisioningDomainId" = $2 AND c."connectionId" = $3 FOR UPDATE OF c`,
			[organizationId, domain, connectionId],
		);
		if (!result.rows[0])
			throw ownedSCIMManagementFailure(404, "The request is not permitted.");
		return result.rows[0];
	}
	async function bump(row: OwnedSCIMManagedConnection) {
		const result = await client.query<OwnedSCIMManagedConnection>(
			`UPDATE "scimManagedConnection" SET revision = revision + 1 WHERE id = $1 AND revision = $2 AND status = 'active' RETURNING *`,
			[row.id, row.revision],
		);
		if (!result.rows[0])
			throw ownedSCIMManagementFailure(
				409,
				"Managed SCIM connection changed concurrently",
			);
		return result.rows[0];
	}
	async function create(providerId: string) {
		const provider = await client.query(
			`SELECT "providerId" FROM "ssoProvider" WHERE "providerId" = $1 AND "organizationId" = $2 AND "domainVerified" IS TRUE FOR UPDATE`,
			[providerId, organizationId],
		);
		if (!provider.rowCount)
			throw ownedSCIMManagementFailure(
				400,
				"Select a verified SSO provider belonging to this organization.",
			);
		if (
			(
				await client.query(
					`SELECT 1 FROM "allauthDirectory" WHERE "providerId" = $1`,
					[providerId],
				)
			).rowCount
		)
			throw ownedSCIMManagementFailure(
				409,
				"This SSO provider already has a directory binding.",
			);
		const now = new Date();
		const connectionId = newOwnedSCIMConnectionId();
		const { rows } = await client.query<OwnedSCIMManagedConnection>(
			`INSERT INTO "scimManagedConnection" (id,"creationRequestId","connectionId","provisioningDomainId",status,revision,"createdAt","createdBy")
			VALUES ($1,$2,$3,$4,'active',2,$5,$6) RETURNING *`,
			[randomUUID(), randomUUID(), connectionId, domain, now, actorId],
		);
		const connection = rows[0]!;
		const issued = await issueCredential(connection, 0, now);
		await event(connection.id, 1, "connection.created", now);
		await event(
			connection.id,
			2,
			"credential.issued",
			now,
			issued.credential.credentialId,
		);
		await client.query(
			`INSERT INTO "allauthDirectory" (id,"providerId","organizationId","connectionId","createdAt") VALUES ($1,$2,$3,$4,$5)`,
			[randomUUID(), providerId, organizationId, connectionId, now],
		);
		await audit("directory.created", connectionId);
		return { connection: publicConnection(connection), ...issued };
	}
	async function rotate(connectionId: string) {
		const row = await lockBoundConnection(connectionId);
		if (row.status !== "active")
			throw ownedSCIMManagementFailure(
				409,
				"Managed SCIM connection is not active",
			);
		const now = new Date();
		await client.query(
			`UPDATE "scimManagedCredential" SET status = 'expired', "activeSlotKey" = "credentialId" || ':inactive'
			WHERE "connectionRecordId" = $1 AND status = 'active' AND "expiresAt" <= $2`,
			[row.id, now],
		);
		const active = await client.query<{ activeSlotKey: string }>(
			`SELECT "activeSlotKey" FROM "scimManagedCredential" WHERE "connectionRecordId" = $1 AND status = 'active' LIMIT $2`,
			[row.id, maximumLiveCredentials],
		);
		const activeSlots = new Set(
			active.rows.map((credential) => credential.activeSlotKey),
		);
		const free = Array.from(
			{ length: maximumLiveCredentials },
			(_, slot) => slot,
		).find((slot) => !activeSlots.has(activeSlot(row.id, slot)));
		if (activeSlots.size >= maximumLiveCredentials || free === undefined)
			throw ownedSCIMManagementFailure(
				409,
				"Managed SCIM connection has the maximum number of active credentials",
			);
		const connection = await bump(row);
		const issued = await issueCredential(connection, free, now);
		await event(
			connection.id,
			connection.revision,
			"credential.rotated",
			now,
			issued.credential.credentialId,
		);
		await audit("directory.credential.rotated", connectionId);
		return { connection: publicConnection(connection), ...issued };
	}
	async function revoke(connectionId: string, credentialId: string) {
		const row = await lockBoundConnection(connectionId);
		const result = await client.query<{ status: CredentialStatus }>(
			`SELECT status FROM "scimManagedCredential" WHERE "connectionRecordId" = $1 AND "credentialId" = $2`,
			[row.id, credentialId],
		);
		const credential = result.rows[0];
		if (!credential)
			throw ownedSCIMManagementFailure(
				404,
				"Managed SCIM connection or credential not found",
			);
		let connection = row;
		if (credential.status !== "revoked") {
			if (row.status !== "active" || credential.status !== "active")
				throw ownedSCIMManagementFailure(
					409,
					"Managed SCIM credential is not active",
				);
			const now = new Date();
			connection = await bump(row);
			await client.query(
				`UPDATE "scimManagedCredential" SET status = 'revoked', "activeSlotKey" = "credentialId" || ':inactive', "revokedAt" = $3, "revokedBy" = $4
				WHERE "connectionRecordId" = $1 AND "credentialId" = $2 AND status = 'active'`,
				[row.id, credentialId, now, actorId],
			);
			await event(
				row.id,
				connection.revision,
				"credential.revoked",
				now,
				credentialId,
			);
		}
		await audit("directory.credential.revoked", credentialId);
		return state(connection);
	}
	return {
		list,
		create,
		rotate,
		revoke,
		state,
		event,
		audit,
		lockBoundConnection,
	};
}
