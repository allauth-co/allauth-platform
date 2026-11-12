import { sql } from "kysely";
import type { AnalyticsEntity } from "./analytics-types";
import { mutationEventType } from "./event-contract";
import type { ControlDatabase } from "./types";

export type ActivitySource = 1 | 2 | 4;
type SessionIdentity = {
	id: string;
	userId: string;
	activeOrganizationId?: string | null;
	impersonatedBy?: string | null;
};

const today = () => new Date().toISOString().slice(0, 10);
const utcDate = (value: Date) => value.toISOString().slice(0, 10);
const scopedTable = (schema: string | undefined, table: string) =>
	schema === undefined ? sql.id(table) : sql.id(schema, table);

/** The native analytics hook and the owned writer recognize the same authenticated mutations. */
export function isControlActivityMutation(path: string, method?: string) {
	return (
		method !== "GET" &&
		!/^\/(admin|project-admin|control)\//.test(path) &&
		Boolean(mutationEventType(path) || path === "/organization/set-active")
	);
}

/** Prefer the organization returned by the authorized action, then the requested organization. */
export function activityOrganizationTarget(
	path: string,
	body: unknown,
	result: unknown,
) {
	const input = body && typeof body === "object" ? body : {};
	const output = result && typeof result === "object" ? result : {};
	if (
		path === "/organization/create" &&
		"id" in output &&
		typeof output.id === "string"
	)
		return output.id;
	if ("organizationId" in output && typeof output.organizationId === "string")
		return output.organizationId;
	if ("organizationId" in input && typeof input.organizationId === "string")
		return input.organizationId;
}

/** Deduplicate activity per project, UTC date, entity, and source. */
export function createActivityRecorder(
	database: ControlDatabase,
	maximumKeys = 10_000,
	schema?: string,
) {
	if (!Number.isInteger(maximumKeys) || maximumKeys < 1 || maximumKeys > 10_000)
		throw new Error("Analytics cache must hold between 1 and 10000 keys.");
	const remembered = new Map<string, Promise<boolean>>();
	let rememberedDay = "";
	const activity = scopedTable(schema, "allauthAnalyticsActivity");
	const identities = scopedTable(schema, "allauthAnalyticsEntity");
	const record = (
		entity: AnalyticsEntity,
		id: string,
		source: ActivitySource,
		recordedAt = new Date(),
	): Promise<boolean> => {
		const day = utcDate(recordedAt);
		if (day !== rememberedDay) {
			remembered.clear();
			rememberedDay = day;
		}
		const key = `${entity}:${id}:${day}:${source}`;
		const existing = remembered.get(key);
		if (existing) return existing.then(() => false);
		const operation = (async () => {
			const result =
				await sql`INSERT INTO ${activity} AS activity ("entityType","entityId",day,sources)
				SELECT ${entity},${id},${day}::date,${source} FROM ${identities}
				WHERE "entityType"=${entity} AND "entityId"=${id} AND "deletedAt" IS NULL AND NOT anonymous
				ON CONFLICT ("entityType","entityId",day) DO UPDATE SET sources=activity.sources | EXCLUDED.sources
				WHERE (activity.sources & EXCLUDED.sources) <> EXCLUDED.sources RETURNING day`.execute(
					database,
				);
			return result.rows.length > 0;
		})();
		if (remembered.size >= maximumKeys)
			remembered.delete(remembered.keys().next().value as string);
		remembered.set(key, operation);
		operation.catch(() => {
			if (remembered.get(key) === operation) remembered.delete(key);
		});
		return operation;
	};
	return {
		record,
		cachedKeys: () => remembered.size,
		has(entity: AnalyticsEntity, id: string, source: ActivitySource) {
			const day = today();
			return (
				rememberedDay === day &&
				remembered.has(`${entity}:${id}:${day}:${source}`)
			);
		},
	};
}

/** Attribute facts only to a surviving realm session and an existing membership. */
export function createAuthenticatedActivityCollector(
	database: ControlDatabase,
	schema?: string,
) {
	const recorder = createActivityRecorder(database, undefined, schema);
	const sessions = scopedTable(schema, "session");
	const users = scopedTable(schema, "user");
	const members = scopedTable(schema, "member");
	const organizations = scopedTable(schema, "organization");

	async function collect(
		predicate: ReturnType<typeof sql>,
		source: ActivitySource,
		organizationId?: string,
	) {
		const {
			rows: [live],
		} = await sql<{ userId: string; organizationId: string | null }>`
			SELECT s."userId", (
				SELECT m."organizationId" FROM ${members} m JOIN ${organizations} o ON o.id=m."organizationId"
				WHERE m."userId"=s."userId" AND m."organizationId"=COALESCE(${organizationId ?? null},s."activeOrganizationId") LIMIT 1
			) AS "organizationId"
			FROM ${sessions} s JOIN ${users} u ON u.id=s."userId"
			WHERE ${predicate} AND s."expiresAt">CURRENT_TIMESTAMP
				AND u.banned IS DISTINCT FROM TRUE AND u."directoryDisabled" IS DISTINCT FROM TRUE
				AND u."isAnonymous" IS DISTINCT FROM TRUE AND s."impersonatedBy" IS NULL
		`.execute(database);
		if (!live) return;
		await recorder.record("users", live.userId, source);
		if (live.organizationId)
			await recorder.record("organizations", live.organizationId, source);
	}

	return {
		recorder,
		session(
			session: SessionIdentity,
			source: ActivitySource,
			organizationId?: string,
			organizationAction = false,
		) {
			if (session.impersonatedBy) return;
			const selected = organizationId ?? session.activeOrganizationId;
			if (
				!organizationAction &&
				recorder.has("users", session.userId, source) &&
				(!selected || recorder.has("organizations", selected, source))
			)
				return;
			return collect(
				sql`s.id=${session.id} AND s."userId"=${session.userId}`,
				source,
				organizationId,
			);
		},
		byToken(token: string) {
			return collect(sql`s.token=${token}`, 4);
		},
	};
}
