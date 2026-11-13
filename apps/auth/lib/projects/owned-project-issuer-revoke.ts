import type { PoolClient } from "pg";

interface RevocableRefresh {
	id: string;
	userId: string;
	revoked: Date | null;
	live: boolean;
}

/** Revoke only a stored access token issued to the authenticated caller. */
export async function revokeIssuerOpaqueAccess(
	database: PoolClient,
	digest: string,
	clientId: string,
) {
	const removed = await database.query(
		'DELETE FROM "oauthAccessToken" WHERE token=$1 AND "clientId"=$2',
		[digest, clientId],
	);
	return removed.rowCount === 1;
}

/** Share the user → grant lock order with refresh rotation and directory changes. */
export async function revokeIssuerRefresh(
	database: PoolClient,
	digest: string,
	clientId: string,
) {
	async function find(lock: boolean) {
		const { rows } = await database.query<RevocableRefresh>(
			`SELECT id,"userId",revoked,"expiresAt" > clock_timestamp() AS live
			 FROM "oauthRefreshToken" WHERE token=$1 AND "clientId"=$2${lock ? " FOR UPDATE" : ""}`,
			[digest, clientId],
		);
		return rows[0];
	}
	const observed = await find(false);
	if (!observed) return false;
	if (!observed.live) return true;
	await database.query('SELECT id FROM "user" WHERE id=$1 FOR UPDATE', [
		observed.userId,
	]);
	const grant = await find(true);
	if (
		!grant ||
		grant.id !== observed.id ||
		grant.userId !== observed.userId ||
		!grant.live
	)
		return true;
	if (grant.revoked) {
		// Legacy refresh replay invalidates the client/user family. The refresh
		// foreign key removes its opaque access tokens in the same transaction.
		await database.query(
			'DELETE FROM "oauthRefreshToken" WHERE "clientId"=$1 AND "userId"=$2',
			[clientId, grant.userId],
		);
		return true;
	}
	await database.query(
		`UPDATE "oauthRefreshToken" SET revoked=date_trunc('second', clock_timestamp()),
		 "rotationReplayResponse"=NULL,"rotationReplayExpiresAt"=NULL WHERE id=$1`,
		[grant.id],
	);
	await database.query('DELETE FROM "oauthAccessToken" WHERE "refreshId"=$1', [
		grant.id,
	]);
	return true;
}
