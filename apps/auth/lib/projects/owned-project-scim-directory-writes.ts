import { randomBytes, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { PoolClient } from "pg";
import type { OwnedProjectSCIMConnection } from "./owned-project-scim-authority";
import { ownedSCIMScopedKey } from "./owned-project-scim-authority";
import {
	ownedSCIMError,
	scimEnterpriseUserSchema,
} from "./owned-project-scim-discovery";
import type { OwnedSCIMUserRow } from "./owned-project-scim-resources";
import { readOwnedSCIMUserAttributes } from "./owned-project-scim-resources-user";
import type { OwnedSCIMUserInput } from "./owned-project-scim-user-input";

type Client = Pick<PoolClient, "query">;
type Source = OwnedSCIMUserRow & {
	userId: string;
	externalIdKey: string | null;
	primaryEmail: string;
};
type Subject = { profileSourceId: string | null };
type Tombstone = {
	id: string;
	userId: string;
	profile: string;
	provisioningDomainId: string;
	externalId: string;
};

export type SCIMProfileAdmission = (input: {
	client: Client;
	request: Request;
	action: "create";
	email: string;
	userId: string;
}) => Promise<Response | null>;

const profileColumns = [
	"userName",
	"userNameKey",
	"primaryEmail",
	"workEmailValueIndex",
	"emailValueIndex",
	"displayName",
	"formattedName",
	"givenName",
	"familyName",
	"serializedEmails",
	"serializedAttributes",
	"externalId",
	"externalIdKey",
	"active",
];
const domainChanged = () =>
	ownedSCIMError(
		409,
		"The connection provisioningDomainId changed after resources were created",
	);
const missingUser = () => ownedSCIMError(404, "SCIM User not found");

function externalKey(connectionId: string, externalId: string | null) {
	return externalId
		? ownedSCIMScopedKey(["scim-user-external-id", connectionId, externalId])
		: null;
}

function profileValues(connectionId: string, profile: OwnedSCIMUserInput) {
	const { name, emails } = profile.attributes;
	const emailIndex = (type?: string) =>
		`|${[...new Set(emails.filter((email) => !type || email.type === type).map((email) => ownedSCIMScopedKey(["scim-email-value", email.value])))].sort().join("|")}|`;
	return [
		profile.userName,
		ownedSCIMScopedKey([
			"scim-user-name",
			connectionId,
			profile.userName.toLowerCase(),
		]),
		profile.primaryEmail,
		emailIndex("work"),
		emailIndex(),
		profile.displayName,
		name.formatted,
		name.givenName ?? null,
		name.familyName ?? null,
		JSON.stringify(emails),
		profile.serializedAttributes,
		profile.externalId,
		externalKey(connectionId, profile.externalId),
		profile.active,
	];
}

async function audit(
	client: Client,
	type: "user.created" | "user.updated" | "session.deleted",
	userId: string,
	targetId: string,
	path: string,
) {
	await client.query(
		`INSERT INTO "allauthEvent" (id, type, outcome, "actorId", "userId", "targetId", "createdAt", metadata)
		VALUES ($1, $2, 'success', $3, $4, $5, statement_timestamp(), jsonb_build_object('path', $6::text))`,
		[
			randomUUID(),
			type,
			type === "session.deleted" ? null : userId,
			userId,
			targetId,
			path,
		],
	);
}

async function assertEmailAvailable(
	client: Client,
	email: string,
	userId: string,
) {
	const result = await client.query(
		`SELECT 1 FROM "user" WHERE email = $1 AND id <> $2`,
		[email, userId],
	);
	if (result.rowCount)
		throw ownedSCIMError(
			409,
			"A Better Auth User already uses this email",
			"uniqueness",
		);
}

async function updateProfile(
	client: Client,
	userId: string,
	profile: OwnedSCIMUserInput,
	path: string,
) {
	await assertEmailAvailable(client, profile.primaryEmail, userId);
	const result = await client.query(
		`UPDATE "user" SET email = $2, name = $3,
		"emailVerified" = CASE WHEN email = $2 THEN "emailVerified" ELSE false END, "updatedAt" = statement_timestamp() WHERE id = $1`,
		[userId, profile.primaryEmail, profile.displayName],
	);
	if (!result.rowCount)
		throw ownedSCIMError(409, "The linked Better Auth User no longer exists");
	await audit(client, "user.updated", userId, userId, path);
}

async function acquireSubject(client: Client, userId: string) {
	const result = await client.query<Subject>(
		`UPDATE "scimSubject" SET revision = revision + 1, "updatedAt" = statement_timestamp()
		WHERE "userId" = $1 RETURNING "profileSourceId"`,
		[userId],
	);
	if (!result.rows[0])
		throw ownedSCIMError(500, "The SCIM User subject is missing");
	return result.rows[0];
}

async function findSource(
	client: Client,
	connection: OwnedProjectSCIMConnection,
	id: string,
	lock = false,
) {
	const row = (
		await client.query<Source>(
			`SELECT * FROM "scimUser" WHERE id = $1 AND "connectionId" = $2${lock ? " FOR UPDATE" : ""}`,
			[id, connection.connectionId],
		)
	).rows[0];
	if (!row) throw missingUser();
	if (row.provisioningDomainId !== connection.provisioningDomainId)
		throw domainChanged();
	return row;
}

async function assertAvailableKeys(
	client: Client,
	connectionId: string,
	profile: OwnedSCIMUserInput,
	exclude = "",
) {
	const args = [
		connectionId,
		ownedSCIMScopedKey([
			"scim-user-name",
			connectionId,
			profile.userName.toLowerCase(),
		]),
		externalKey(connectionId, profile.externalId),
		exclude,
	];
	const result = await client.query<{
		nameConflict: boolean;
		externalConflict: boolean;
	}>(
		`SELECT EXISTS (SELECT 1 FROM "scimUser" WHERE "connectionId" = $1 AND "userNameKey" = $2 AND id <> $4) AS "nameConflict",
		        EXISTS (SELECT 1 FROM "scimUser" WHERE "connectionId" = $1 AND "externalIdKey" = $3 AND id <> $4) AS "externalConflict"`,
		args,
	);
	if (result.rows[0]?.nameConflict)
		throw ownedSCIMError(
			409,
			"SCIM userName already exists for this connection",
			"uniqueness",
		);
	if (result.rows[0]?.externalConflict)
		throw ownedSCIMError(
			409,
			"SCIM externalId already exists for this connection",
			"uniqueness",
		);
}

async function reconcileMembership(
	client: Client,
	userId: string,
	organizationId: string,
	active: boolean,
) {
	const parameters = [organizationId, userId];
	if (active) {
		const memberId = randomUUID();
		const added = await client.query(
			`INSERT INTO "member" (id, "organizationId", "userId", role, "createdAt")
			SELECT $3, $1, $2, 'member', statement_timestamp()
			WHERE NOT EXISTS (SELECT 1 FROM "member" WHERE "organizationId" = $1 AND "userId" = $2)`,
			[...parameters, memberId],
		);
		if (added.rowCount)
			await client.query(
				`INSERT INTO "allauthDirectoryMembership" (id, "organizationId", "userId", "memberId", "createdAt")
			VALUES ($4, $1, $2, $3, statement_timestamp())`,
				[...parameters, memberId, randomUUID()],
			);
		return;
	}
	const owned = await client.query<{ memberId: string }>(
		`SELECT "memberId" FROM "allauthDirectoryMembership" WHERE "organizationId" = $1 AND "userId" = $2 FOR UPDATE`,
		parameters,
	);
	for (const binding of owned.rows) {
		const removed = await client.query(
			`DELETE FROM "member" WHERE "organizationId" = $1 AND "userId" = $2 AND id = $3 AND role = 'member'`,
			[...parameters, binding.memberId],
		);
		if (removed.rowCount)
			await client.query(
				`WITH removed AS (
			DELETE FROM "teamMember" m USING "team" t WHERE m."teamId" = t.id AND t."organizationId" = $1 AND m."userId" = $2 RETURNING m."teamId"
		) UPDATE "team" t SET "memberCount" = t."memberCount" - r.total FROM (SELECT "teamId", count(*)::integer AS total FROM removed GROUP BY "teamId") r
		WHERE t.id = r."teamId" AND t."memberCount" >= r.total`,
				parameters,
			);
	}
	await client.query(
		`DELETE FROM "allauthDirectoryMembership" WHERE "organizationId" = $1 AND "userId" = $2`,
		parameters,
	);
	await client.query(
		`UPDATE "session" SET "activeOrganizationId" = NULL, "activeTeamId" = NULL WHERE "activeOrganizationId" = $1 AND "userId" = $2`,
		parameters,
	);
	await client.query(
		`DELETE FROM "oauthAccessToken" WHERE "referenceId" = $1 AND "userId" = $2`,
		parameters,
	);
	await client.query(
		`DELETE FROM "oauthRefreshToken" WHERE "referenceId" = $1 AND "userId" = $2`,
		parameters,
	);
}

async function reconcileDirectory(
	client: Client,
	userId: string,
	organizationId: string,
	provisioningDomainId: string,
	path: string,
) {
	const { rows } = await client.query<{
		id: string;
		active: boolean;
		provisioningDomainId: string;
	}>(
		`SELECT u.id, u.active, u."provisioningDomainId" FROM "scimUser" u WHERE u."userId" = $1
		 AND NOT EXISTS (SELECT 1 FROM "scimConnectionBinding" b WHERE b."connectionId" = u."connectionId" AND b."decommissionStatus" <> 'active')`,
		[userId],
	);
	const active = rows.some((row) => row.active);
	const activeInDomain = rows.some(
		(row) => row.active && row.provisioningDomainId === provisioningDomainId,
	);
	await client.query(
		`UPDATE "scimSubject" SET "profileSourceId" = NULL, revision = revision + 1, "updatedAt" = statement_timestamp()
		WHERE "userId" = $1 AND "profileSourceId" IS NOT NULL AND NOT ("profileSourceId" = ANY($2::text[]))`,
		[userId, rows.map((row) => row.id)],
	);
	await client.query(
		`DELETE FROM "scimProjectionGrant" WHERE "userId" = $1 AND "provisioningDomainId" = $2`,
		[userId, provisioningDomainId],
	);
	await reconcileMembership(client, userId, organizationId, activeInDomain);
	await client.query(
		`UPDATE "user" SET "directoryManaged" = true, "directoryDisabled" = $2 WHERE id = $1`,
		[userId, !active],
	);
	if (active) return;
	await client.query(`DELETE FROM "oauthAccessToken" WHERE "userId" = $1`, [
		userId,
	]);
	await client.query(`DELETE FROM "oauthRefreshToken" WHERE "userId" = $1`, [
		userId,
	]);
	await client.query(
		`DELETE FROM "verification" WHERE value = $1 AND (starts_with(identifier, 'trust-device-') OR starts_with(identifier, '2fa-'))`,
		[userId],
	);
	const deleted = await client.query<{ id: string }>(
		`DELETE FROM "session" WHERE "userId" = $1 RETURNING id`,
		[userId],
	);
	for (const session of deleted.rows)
		await audit(client, "session.deleted", userId, session.id, path);
}

function changed(row: Source, profile: OwnedSCIMUserInput) {
	const { [scimEnterpriseUserSchema]: enterprise, ...current } =
		readOwnedSCIMUserAttributes(row);
	return (
		row.userName !== profile.userName ||
		row.displayName !== profile.displayName ||
		row.externalId !== profile.externalId ||
		row.active !== profile.active ||
		row.primaryEmail !== profile.primaryEmail ||
		!isDeepStrictEqual(
			{ ...current, ...(enterprise ? { enterprise } : {}) },
			JSON.parse(profile.serializedAttributes),
		)
	);
}

/** Applies organization projection and User writes with the existing transaction lock ordering. */
export async function ownedSCIMDirectoryWriter(
	client: Client,
	connection: OwnedProjectSCIMConnection,
	request: Request,
	admitProfile: SCIMProfileAdmission,
) {
	const domain = connection.provisioningDomainId;
	const connectionId = connection.connectionId;
	const organizationId = domain.startsWith("organization:")
		? domain.slice("organization:".length)
		: "";
	const organization = await client.query(
		`SELECT id FROM "organization" WHERE id = $1 FOR KEY SHARE`,
		[organizationId],
	);
	if (!organizationId || !organization.rowCount)
		throw ownedSCIMError(
			409,
			"SCIM connection requires an existing organization provisioning domain",
		);
	const collectionPath = "/scim/v2/Users";
	const detailPath = `${collectionPath}/:userId`;

	async function create(profile: OwnedSCIMUserInput) {
		const mismatched = await client.query(
			`SELECT 1 FROM "scimUser" WHERE "connectionId" = $1 AND "provisioningDomainId" <> $2 LIMIT 1`,
			[connectionId, domain],
		);
		if (mismatched.rowCount) throw domainChanged();
		await assertAvailableKeys(client, connectionId, profile);
		const key = externalKey(connectionId, profile.externalId);
		const tombstone = key
			? (
					await client.query<Tombstone>(
						`SELECT id, "userId", profile, "provisioningDomainId", "externalId" FROM "scimIdentityTombstone" WHERE "connectionId" = $1 AND "externalIdKey" = $2`,
						[connectionId, key],
					)
				).rows[0]
			: undefined;
		if (
			tombstone &&
			(tombstone.provisioningDomainId !== domain ||
				tombstone.externalId !== profile.externalId)
		)
			throw ownedSCIMError(
				409,
				"The connection provisioningDomainId changed after this User was deleted",
			);
		const userId = tombstone?.userId ?? randomUUID();
		const manage = !tombstone || tombstone.profile === "manage";
		if (
			tombstone &&
			tombstone.profile !== "manage" &&
			tombstone.profile !== "preserve"
		)
			throw ownedSCIMError(
				500,
				"Stored SCIM User profile authority is invalid",
			);
		if (!tombstone) {
			await assertEmailAvailable(client, profile.primaryEmail, userId);
			const denial = await admitProfile({
				client,
				request,
				action: "create",
				email: profile.primaryEmail,
				userId,
			});
			if (denial) throw denial;
			await client.query(
				`INSERT INTO "user" (id, email, name, "emailVerified", role) VALUES ($1, $2, $3, false, 'user')`,
				[userId, profile.primaryEmail, profile.displayName],
			);
			await audit(client, "user.created", userId, userId, collectionPath);
		}
		const subject = (
			await client.query<Subject>(
				`INSERT INTO "scimSubject" (id, "userId", revision, "createdAt", "updatedAt")
			VALUES ($1, $2, 1, statement_timestamp(), statement_timestamp()) ON CONFLICT ("userId") DO UPDATE
			SET revision = "scimSubject".revision + 1, "updatedAt" = statement_timestamp() RETURNING "profileSourceId"`,
				[randomUUID(), userId],
			)
		).rows[0];
		if (manage && subject?.profileSourceId)
			throw ownedSCIMError(
				409,
				"Another SCIM source already manages this User profile",
				"uniqueness",
			);
		if (tombstone) {
			const removed = await client.query(
				`DELETE FROM "scimIdentityTombstone" WHERE id = $1 AND "userId" = $2 AND profile = $3 AND "provisioningDomainId" = $4`,
				[tombstone.id, userId, tombstone.profile, domain],
			);
			if (!removed.rowCount)
				throw ownedSCIMError(
					409,
					"The SCIM User identity changed concurrently",
				);
			if (manage) await updateProfile(client, userId, profile, collectionPath);
		}
		const id = randomUUID();
		const params = [
			id,
			connectionId,
			domain,
			userId,
			ownedSCIMScopedKey(["scim-user", connectionId, userId]),
			`${Date.now().toString().padStart(15, "0")}:${randomBytes(8).toString("hex")}`,
			...profileValues(connectionId, profile),
		];
		const inserted = await client.query<Source>(
			`INSERT INTO "scimUser" (id, "connectionId", "provisioningDomainId", "userId", "connectionUserKey", "orderKey", ${profileColumns.map((column) => `"${column}"`).join(", ")}, "createdAt", "updatedAt")
			VALUES (${params.map((_, index) => `$${index + 1}`).join(", ")}, statement_timestamp(), statement_timestamp()) RETURNING *`,
			params,
		);
		if (manage)
			await client.query(
				`UPDATE "scimSubject" SET "profileSourceId" = $2, revision = revision + 1, "updatedAt" = statement_timestamp() WHERE "userId" = $1`,
				[userId, id],
			);
		await reconcileDirectory(
			client,
			userId,
			organizationId,
			domain,
			collectionPath,
		);
		return inserted.rows[0]!;
	}

	async function update(
		id: string,
		profileFor: (row: OwnedSCIMUserRow) => OwnedSCIMUserInput,
		patch: boolean,
	) {
		const observed = await findSource(client, connection, id);
		const subject = await acquireSubject(client, observed.userId);
		const current = await findSource(client, connection, id, true);
		if (current.userId !== observed.userId)
			throw ownedSCIMError(409, "The SCIM User identity changed concurrently");
		const profile = profileFor(current);
		if (patch && !changed(current, profile)) return current;
		await assertAvailableKeys(client, connectionId, profile, id);
		if (subject.profileSourceId === id)
			await updateProfile(client, current.userId, profile, detailPath);
		const result = await client.query<Source>(
			`UPDATE "scimUser" SET ${profileColumns.map((column, index) => `"${column}" = $${index + 4}`).join(", ")}, "updatedAt" = statement_timestamp()
			WHERE id = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3 RETURNING *`,
			[id, connectionId, domain, ...profileValues(connectionId, profile)],
		);
		await reconcileDirectory(
			client,
			current.userId,
			organizationId,
			domain,
			detailPath,
		);
		return result.rows[0]!;
	}

	async function remove(id: string) {
		const observed = await findSource(client, connection, id);
		const groups = await client.query<{ id: string }>(
			`SELECT g.id FROM "scimGroup" g WHERE g."connectionId" = $1 AND g."provisioningDomainId" = $2
			AND EXISTS (SELECT 1 FROM "scimGroupMember" m WHERE m."connectionId" = $1 AND m."scimUserId" = $3 AND m."groupId" = g.id) ORDER BY g.id FOR UPDATE`,
			[connectionId, domain, id],
		);
		const subject = await acquireSubject(client, observed.userId);
		const current = await findSource(client, connection, id, true);
		if (current.userId !== observed.userId)
			throw ownedSCIMError(409, "The SCIM User identity changed concurrently");
		const groupIds = groups.rows.map((group) => group.id);
		const unlocked = await client.query(
			`SELECT 1 FROM "scimGroupMember" WHERE "scimUserId" = $1 AND ("connectionId" <> $2 OR NOT ("groupId" = ANY($3::text[]))) LIMIT 1`,
			[id, connectionId, groupIds],
		);
		if (unlocked.rowCount)
			throw ownedSCIMError(
				409,
				"The SCIM Group changed concurrently; retry the request",
			);
		if (current.externalId && current.externalIdKey)
			await client.query(
				`INSERT INTO "scimIdentityTombstone" (id, "connectionId", "provisioningDomainId", "externalId", "externalIdKey", "userId", profile, "deletedAt")
			VALUES ($1, $2, $3, $4, $5, $6, $7, statement_timestamp()) ON CONFLICT ("externalIdKey") DO UPDATE SET
			"userId" = EXCLUDED."userId", profile = EXCLUDED.profile, "deletedAt" = EXCLUDED."deletedAt"`,
				[
					randomUUID(),
					connectionId,
					domain,
					current.externalId,
					current.externalIdKey,
					current.userId,
					subject.profileSourceId === id ? "manage" : "preserve",
				],
			);
		await client.query(
			`DELETE FROM "scimGroupMember" WHERE "connectionId" = $1 AND "scimUserId" = $2`,
			[connectionId, id],
		);
		await client.query(
			`UPDATE "scimGroup" SET revision = revision + 1, "updatedAt" = statement_timestamp() WHERE "connectionId" = $1 AND id = ANY($2::text[])`,
			[connectionId, groupIds],
		);
		await client.query(
			`DELETE FROM "scimUser" WHERE id = $1 AND "connectionId" = $2 AND "provisioningDomainId" = $3`,
			[id, connectionId, domain],
		);
		await reconcileDirectory(
			client,
			current.userId,
			organizationId,
			domain,
			detailPath,
		);
	}

	return { create, update, remove };
}
