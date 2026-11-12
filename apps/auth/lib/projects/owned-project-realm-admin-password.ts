import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import type { OwnedProjectPasswordChangeOptions } from "./owned-project-password-change";

export const realmAdminPasswordPath = "/admin/set-user-password";
export type RealmAdminPasswordSafety =
	OwnedProjectPasswordChangeOptions["checkPasswordSafety"];

export const realmAdminPasswordUnavailable = {
	status: 503,
	code: "PASSWORD_CHANGE_UNAVAILABLE",
	message: "Password changes are temporarily unavailable.",
};

/** Perform the network check and scrypt work before taking database locks. */
export async function prepareRealmAdminPassword(
	password: string,
	checkSafety?: RealmAdminPasswordSafety,
) {
	const safety = await checkSafety?.(password).catch(
		() => "unavailable" as const,
	);
	if (safety === "breached")
		return {
			failure: {
				status: 400,
				code: "PASSWORD_COMPROMISED",
				message:
					"The password you entered has been compromised. Please choose a different password.",
			},
		};
	if (safety !== "allowed") return { failure: realmAdminPasswordUnavailable };
	return { hash: await clerkCompatiblePasswords.hash(password) };
}

/** Store a rollback-compatible credential for an account locked by the caller. */
export async function writeRealmAdminPassword(
	client: PoolClient,
	store: Pick<ReturnType<typeof createProjectEngineStore>, "recordEvent">,
	{ userId, actorId, hash }: { userId: string; actorId: string; hash: string },
) {
	const { rows } = await client.query<{ id: string; accountId: string }>(
		`SELECT id,"accountId" FROM "account" WHERE "userId"=$1 AND "providerId"='credential'
		 ORDER BY id LIMIT 2 FOR UPDATE`,
		[userId],
	);
	if (rows.length > 1 || (rows[0] && rows[0].accountId !== userId))
		return false;
	if (rows[0]) {
		await client.query(
			'UPDATE "account" SET password=$1,"updatedAt"=statement_timestamp() WHERE id=$2',
			[hash, rows[0].id],
		);
	} else {
		const id = randomUUID();
		await client.query(
			`INSERT INTO "account" (id,"accountId","providerId","userId",password,"updatedAt")
			 VALUES ($1,$2,'credential',$2,$3,statement_timestamp())`,
			[id, userId, hash],
		);
		await store.recordEvent(client, {
			type: "account.linked",
			outcome: "success",
			actorId,
			userId,
			targetId: id,
			metadata: { path: realmAdminPasswordPath, provider: "credential" },
		});
	}
	return true;
}
