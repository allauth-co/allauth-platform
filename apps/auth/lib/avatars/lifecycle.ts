import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { APIError } from "better-auth";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { brandingAssetOrigin } from "../branding/validation";
import type { ValidatedBrandingAsset } from "../branding/types";
import { checkedProjectSchema } from "../projects/validation";
import {
	avatarCapabilityPath,
	avatarProtocol,
	signAvatarRequest,
	validAvatarPath,
} from "./protocol";
export interface AvatarScope {
	projectId: string;
	workspaceId: string;
	applicationId: string;
	schemaName: string;
}
interface AssetRow {
	id: string;
	userId: string | null;
	projectId: string;
	workspaceId: string;
	applicationId: string;
	url: string;
	objectPath: string;
	state: string;
	attempts: number;
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const unavailable = () =>
	new APIError("SERVICE_UNAVAILABLE", {
		message: "Owned profile photo storage is unavailable. Try again.",
	});
const pending = () =>
	new APIError("SERVICE_UNAVAILABLE", {
		message:
			"Profile photo erasure is pending. Retry account deletion shortly.",
	});
function tables(scope: AvatarScope) {
	if (
		![scope.projectId, scope.workspaceId, scope.applicationId].every((value) =>
			uuid.test(value),
		)
	)
		throw unavailable();
	const prefix = `"${checkedProjectSchema(scope.schemaName)}".`;
	return {
		asset: `${prefix}"allauthAvatarAsset"`,
		state: `${prefix}"allauthAvatarUserState"`,
		lifecycle: `${prefix}"allauthAvatarLifecycle"`,
		user: `${prefix}"user"`,
	};
}
export function ownedAvatarSelected(env: AuthEnvironment, projectId: string) {
	const values = setting(env, "ALLAUTH_OWNED_AVATAR_PROJECT_IDS")
		.split(",")
		.map((value) => value.trim())
		.filter(Boolean);
	return (
		values.length <= 100 &&
		values.every((value) => uuid.test(value)) &&
		new Set(values).size === values.length &&
		values.includes(projectId)
	);
}
function storage(env: AuthEnvironment) {
	const origin = brandingAssetOrigin(env),
		secret = setting(env, "ALLAUTH_AVATAR_SECRET");
	if (secret.length < 32) throw unavailable();
	return { origin, secret };
}
async function registryPresent(pool: Pool, scope: AvatarScope) {
	return Boolean(
		(
			await pool.query<{ table: string | null }>(
				"SELECT to_regclass($1)::text AS table",
				[`${checkedProjectSchema(scope.schemaName)}.\"allauthAvatarAsset\"`],
			)
		).rows[0]?.table,
	);
}
/** Missing rollout, schema, hooks, signed Worker verification or fresh cleanup heartbeat stays disabled. */
export async function ownedAvatarReady(
	pool: Pool,
	scope: AvatarScope,
	env: AuthEnvironment,
) {
	if (
		!ownedAvatarSelected(env, scope.projectId) ||
		setting(env, "ALLAUTH_AVATAR_CLEANUP_ENABLED") !== "true"
	)
		return false;
	try {
		const table = tables(scope),
			{ origin } = storage(env);
		const row = (
			await pool.query<{
				protocolVersion: number;
				assetOrigin: string;
				healthy: boolean;
				hooks: number;
			}>(
				`SELECT "protocolVersion","assetOrigin",("healthyAt">NOW()-INTERVAL '5 minutes' AND "healthyAt"<=NOW()) AS healthy,(SELECT COUNT(*)::int FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='user' AND t.tgenabled='O' AND t.tgname IN ('allauth_avatar_image_guard','allauth_avatar_delete_guard','allauth_avatar_insert_guard')) AS hooks FROM ${table.lifecycle} WHERE id=TRUE`,
				[scope.schemaName],
			)
		).rows[0];
		return (
			row?.protocolVersion === avatarProtocol &&
			row.assetOrigin === origin &&
			row.healthy === true &&
			row.hooks === 3
		);
	} catch {
		return false;
	}
}
async function transport(
	url: string,
	method: "GET" | "PUT" | "DELETE",
	env: AuthEnvironment,
	asset?: ValidatedBrandingAsset,
	signal?: AbortSignal,
) {
	const { origin, secret } = storage(env),
		parsed = new URL(url);
	if (
		parsed.origin !== origin ||
		parsed.href !== origin + parsed.pathname ||
		(parsed.pathname !== avatarCapabilityPath &&
			!validAvatarPath(parsed.pathname))
	)
		throw unavailable();
	const request = new Request(url, {
		method,
		...(asset
			? { headers: { "content-type": asset.contentType }, body: asset.bytes }
			: {}),
	});
	return fetch(url, {
		method,
		headers: await signAvatarRequest(request, secret),
		...(asset ? { body: asset.bytes } : {}),
		redirect: "error",
		cache: "no-store",
		credentials: "omit",
		signal: signal
			? AbortSignal.any([
					signal,
					AbortSignal.timeout(method === "PUT" ? 15000 : 5000),
				])
			: AbortSignal.timeout(method === "PUT" ? 15000 : 5000),
	});
}
async function workerReady(env: AuthEnvironment, signal?: AbortSignal) {
	const { origin } = storage(env),
		response = await transport(
			origin + avatarCapabilityPath,
			"GET",
			env,
			undefined,
			signal,
		);
	if (
		response.status !== 200 ||
		!response.headers.get("cache-control")?.includes("no-store")
	)
		throw unavailable();
	const value: unknown = await response.json();
	if (
		!value ||
		typeof value !== "object" ||
		!("profileImageOwnershipAndDeletionProtocol" in value) ||
		value.profileImageOwnershipAndDeletionProtocol !== avatarProtocol
	)
		throw unavailable();
	return origin;
}
async function lockUser(
	client: PoolClient,
	scope: AvatarScope,
	userId: string,
) {
	const table = tables(scope),
		user = (
			await client.query<{ id: string }>(
				`SELECT id FROM ${table.user} WHERE id=$1 FOR UPDATE`,
				[userId],
			)
		).rows[0];
	if (
		!user ||
		(
			await client.query<{ deleting: boolean }>(
				`SELECT deleting FROM ${table.state} WHERE "userId"=$1`,
				[userId],
			)
		).rows[0]?.deleting
	)
		throw unavailable();
}
/** A committed ownership intent exists before any image bytes can reach the private Worker bucket. */
async function storeOwnedAvatarInternal(
	asset: ValidatedBrandingAsset,
	userId: string,
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
) {
	if (
		!(await ownedAvatarReady(pool, scope, env)) ||
		asset.bytes.length > 131072 ||
		asset.extension === "ico"
	)
		throw unavailable();
	const table = tables(scope),
		id = randomUUID(),
		{ origin } = storage(env),
		path = `/avatars/${scope.workspaceId}/${scope.applicationId}/${scope.projectId}/${id}.${asset.extension}`,
		url = origin + path;
	const client = await pool.connect();
	let prepared = false;
	try {
		await client.query("BEGIN");
		await lockUser(client, scope, userId);
		const count = Number(
			(
				await client.query<{ count: string }>(
					`SELECT COUNT(*)::text AS count FROM ${table.asset} WHERE "userId"=$1 AND state IN ('prepared','draft')`,
					[userId],
				)
			).rows[0]?.count,
		);
		if (count >= 10)
			throw new APIError("TOO_MANY_REQUESTS", {
				message: "Too many unfinished profile photos. Try again after cleanup.",
			});
		await client.query(
			`INSERT INTO ${table.asset} (id,"userId","projectId","workspaceId","applicationId",url,"objectPath",state) VALUES ($1,$2,$3,$4,$5,$6,$7,'prepared')`,
			[
				id,
				userId,
				scope.projectId,
				scope.workspaceId,
				scope.applicationId,
				url,
				path,
			],
		);
		await client.query("COMMIT");
		prepared = true;
		await client.query("BEGIN");
		await lockUser(client, scope, userId);
		const row = (
			await client.query<AssetRow>(
				`SELECT * FROM ${table.asset} WHERE id=$1 FOR UPDATE`,
				[id],
			)
		).rows[0];
		if (row?.state !== "prepared" || row.userId !== userId) throw unavailable();
		const response = await transport(url, "PUT", env, asset),
			value: unknown = await response.json();
		if (
			response.status !== 201 ||
			!value ||
			typeof value !== "object" ||
			!("url" in value) ||
			value.url !== url ||
			!response.headers.get("cache-control")?.includes("no-store")
		)
			throw unavailable();
		await client.query(`UPDATE ${table.asset} SET state='draft' WHERE id=$1`, [
			id,
		]);
		await client.query("COMMIT");
		return url;
	} catch (error) {
		await client.query("ROLLBACK");
		if (prepared)
			await client.query(
				`UPDATE ${table.asset} SET state='delete_pending',"availableAt"=NOW() WHERE id=$1 AND state<>'deleted'`,
				[id],
			);
		if (error instanceof APIError && error.statusCode === 429) throw error;
		throw unavailable();
	} finally {
		client.release();
	}
}
/** Bounded idempotent cleanup. Rows retain durable retry intent until exact Worker deletion acknowledges. */
async function cleanupOwnedAvatarsInternal(
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
	limit = 10,
	userId?: string,
	signal?: AbortSignal,
) {
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 25)
		throw unavailable();
	signal?.throwIfAborted();
	const table = tables(scope),
		origin = await workerReady(env, signal),
		client = await pool.connect();
	let erased = 0,
		failed = 0;
	try {
		const configured = (
			await client.query<{ assetOrigin: string | null }>(
				`SELECT "assetOrigin" FROM ${table.lifecycle} WHERE id=TRUE`,
			)
		).rows[0];
		if (
			!configured ||
			(configured.assetOrigin && configured.assetOrigin !== origin)
		)
			throw unavailable();
		for (let index = 0; index < limit; index++) {
			signal?.throwIfAborted();
			await client.query("BEGIN");
			const row = (
				await client.query<AssetRow>(
					`SELECT * FROM ${table.asset} WHERE "projectId"=$1 AND "workspaceId"=$2 AND "applicationId"=$3 AND ($4::text IS NULL OR "userId"=$4) AND (state='delete_pending' OR (state IN ('prepared','draft') AND "expiresAt"<=NOW())) AND "availableAt"<=NOW() ORDER BY "availableAt",id LIMIT 1 FOR UPDATE SKIP LOCKED`,
					[
						scope.projectId,
						scope.workspaceId,
						scope.applicationId,
						userId ?? null,
					],
				)
			).rows[0];
			if (!row) {
				await client.query("COMMIT");
				break;
			}
			const expectedPrefix = `/avatars/${scope.workspaceId}/${scope.applicationId}/${scope.projectId}/${row.id}.`;
			try {
				if (
					!validAvatarPath(row.objectPath) ||
					!row.objectPath.startsWith(expectedPrefix) ||
					row.url !== origin + row.objectPath
				)
					throw unavailable();
				const response = await transport(
					row.url,
					"DELETE",
					env,
					undefined,
					signal,
				);
				if (
					response.status !== 204 ||
					!response.headers.get("cache-control")?.includes("no-store")
				)
					throw unavailable();
				signal?.throwIfAborted();
				await client.query(
					`UPDATE ${table.asset} SET state='deleted',"userId"=NULL,attempts=attempts+1,"erasedAt"=NOW() WHERE id=$1`,
					[row.id],
				);
				erased++;
			} catch {
				if (signal?.aborted) throw unavailable();
				await client.query(
					`UPDATE ${table.asset} SET state='delete_pending',attempts=attempts+1,"availableAt"=NOW()+LEAST(3600,10*POWER(2,LEAST(attempts,8))) * INTERVAL '1 second' WHERE id=$1`,
					[row.id],
				);
				failed++;
			}
			await client.query("COMMIT");
		}
		signal?.throwIfAborted();
		await client.query(
			`UPDATE ${table.lifecycle} SET "assetOrigin"=$1,"healthyAt"=CASE WHEN $2=0 AND NOT EXISTS (SELECT 1 FROM ${table.asset} WHERE state='delete_pending' AND attempts>0) THEN NOW() ELSE NULL END WHERE id=TRUE`,
			[origin, failed],
		);
		return { erased, failed };
	} catch {
		try {
			await client.query("ROLLBACK");
		} catch {
			/* Cancellation discards this connection. */
		}
		throw unavailable();
	} finally {
		client.release(signal?.aborted === true);
	}
}
/** Normal user deletion cannot succeed while new owned images or abandoned drafts await erasure. */
async function eraseOwnedAvatarsInternal(
	userId: string,
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
) {
	if (!(await registryPresent(pool, scope))) {
		if (ownedAvatarSelected(env, scope.projectId)) throw pending();
		return; // Compatible realm never opted into owned storage.
	}
	const table = tables(scope),
		client = await pool.connect();
	try {
		await client.query("BEGIN");
		const existing = await client.query<{ id: string }>(
			`SELECT id FROM ${table.user} WHERE id=$1 FOR UPDATE`,
			[userId],
		);
		if (!existing.rows.length) {
			await client.query("COMMIT");
			return;
		}
		await client.query(
			`INSERT INTO ${table.state} ("userId",deleting) VALUES ($1,TRUE) ON CONFLICT ("userId") DO UPDATE SET deleting=TRUE`,
			[userId],
		);
		await client.query(
			`UPDATE ${table.asset} SET state='delete_pending',"availableAt"=NOW() WHERE "userId"=$1 AND state<>'deleted'`,
			[userId],
		);
		await client.query("COMMIT");
	} catch {
		await client.query("ROLLBACK");
		throw pending();
	} finally {
		client.release();
	}
	const remaining = async () =>
		Number(
			(
				await pool.query<{ count: string }>(
					`SELECT COUNT(*)::text AS count FROM ${table.asset} WHERE "userId"=$1 AND state<>'deleted'`,
					[userId],
				)
			).rows[0]?.count,
		);
	if ((await remaining()) === 0) return;
	try {
		await cleanupOwnedAvatars(scope, pool, env, 3, userId);
	} catch {
		throw pending();
	}
	if ((await remaining()) > 0) throw pending();
}

/** Public lifecycle boundaries never export underlying database/transport errors. */
export async function storeOwnedAvatar(
	asset: ValidatedBrandingAsset,
	userId: string,
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
) {
	try {
		return await storeOwnedAvatarInternal(asset, userId, scope, pool, env);
	} catch (error) {
		if (error instanceof APIError && error.statusCode === 429) throw error;
		throw unavailable();
	}
}
export async function cleanupOwnedAvatars(
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
	limit = 10,
	userId?: string,
	signal?: AbortSignal,
) {
	try {
		return await cleanupOwnedAvatarsInternal(
			scope,
			pool,
			env,
			limit,
			userId,
			signal,
		);
	} catch {
		throw unavailable();
	}
}
export async function eraseOwnedAvatarsBeforeDelete(
	userId: string,
	scope: AvatarScope,
	pool: Pool,
	env: AuthEnvironment,
) {
	try {
		await eraseOwnedAvatarsInternal(userId, scope, pool, env);
	} catch {
		throw pending();
	}
}
