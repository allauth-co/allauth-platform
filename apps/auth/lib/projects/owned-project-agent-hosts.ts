import type { PoolClient } from "pg";
import * as z from "zod";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";

const listInput = z.object({
	status: z
		.enum(["active", "pending", "pending_enrollment", "revoked", "rejected"])
		.optional(),
});
const detailInput = z.object({ host_id: z.string() });
const revokeInput = z.object({ host_id: z.string().optional() });
const ownerRequired = "Only the owner of this agent host can change it.";

type Host = {
	id: string;
	name: string | null;
	defaultCapabilities: string | null;
	status: string;
	activatedAt: Date | null;
	expiresAt: Date | null;
	lastUsedAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
};

type BrowserHosts = {
	store: ReturnType<typeof createProjectEngineStore>;
	trustedRequest(headers: Headers, mutation: boolean): boolean;
	trustedIP(request: Request): string | null;
	readBody(request: Request): Promise<unknown>;
	/** Writes lock and recheck the current realm user and signed session. */
	authorizeBrowser(
		client: PoolClient,
		request: Request,
		fresh: boolean,
	): Promise<string | null>;
};

const columns = `id,name,"defaultCapabilities",status,"activatedAt","expiresAt","lastUsedAt","createdAt","updatedAt"`;

function json(value: object, status = 200) {
	return Response.json(value, {
		status,
		headers: { "Cache-Control": "no-store" },
	});
}

function capabilities(value: string | null): string[] {
	if (!value) return [];
	try {
		let decoded: unknown = JSON.parse(value);
		if (typeof decoded === "string") decoded = JSON.parse(decoded);
		return Array.isArray(decoded)
			? decoded.filter((item): item is string => typeof item === "string")
			: [];
	} catch {
		return [];
	}
}

function publicHost(host: Host) {
	return {
		id: host.id,
		name: host.name || `Device ${host.id.slice(0, 8)}`,
		default_capabilities: capabilities(host.defaultCapabilities),
		status: host.status,
		activated_at: host.activatedAt,
		expires_at: host.expiresAt,
		last_used_at: host.lastUsedAt,
		created_at: host.createdAt,
		updated_at: host.updatedAt,
	};
}

function queryValue(query: URLSearchParams, key: string) {
	const values = query.getAll(key);
	return values.length > 1 ? values : values[0];
}

function forbidden(message: string) {
	return json({ message }, 403);
}

async function revoke(client: PoolClient, userId: string, hostId: string) {
	const host = (
		await client.query<{ status: string }>(
			`SELECT status FROM "agentHost" WHERE id=$1 AND "userId"=$2 FOR UPDATE`,
			[hostId, userId],
		)
	).rows[0];
	if (!host) return forbidden(ownerRequired);
	if (host.status === "revoked")
		return json({ host_id: hostId, status: "revoked", agents_revoked: 0 });
	const { rows: agents } = await client.query<{ id: string }>(
		`UPDATE "agent" SET status='revoked',"publicKey"='',kid=NULL,"updatedAt"=transaction_timestamp()
		 WHERE "hostId"=$1 AND status NOT IN ('revoked','rejected') RETURNING id`,
		[hostId],
	);
	await client.query(
		`UPDATE "agentCapabilityGrant" SET status='revoked',"updatedAt"=transaction_timestamp()
		 WHERE "agentId"=ANY($1::text[])`,
		[agents.map(({ id }) => id)],
	);
	await client.query(
		`UPDATE "agentHost" SET status='revoked',"publicKey"='',kid=NULL,"updatedAt"=transaction_timestamp() WHERE id=$1`,
		[hostId],
	);
	return json({
		host_id: hostId,
		status: "revoked",
		agents_revoked: agents.length,
	});
}

/** Browser-only host management for the isolated candidate fixture. */
export function createOwnedProjectAgentHosts(options: BrowserHosts) {
	return async (
		path: string,
		request: Request,
	): Promise<Response | undefined> => {
		const write = path === "/host/revoke" && request.method === "POST";
		const read =
			request.method === "GET" &&
			(path === "/host/get" || path === "/host/list");
		if (!write && !read) return;
		const limited = await options.store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		if (request.headers.has("authorization")) {
			if (write && request.headers.get("authorization"))
				return forbidden(
					"Use your browser session or a valid signed host request.",
				);
			return forbidden("Use your signed-in browser session for this action.");
		}
		if (!options.trustedRequest(request.headers, write))
			return forbidden("This authentication request is not permitted.");
		const params = new URL(request.url).searchParams;
		const query = !read
			? undefined
			: path === "/host/get"
				? detailInput.safeParse({ host_id: queryValue(params, "host_id") })
				: listInput.safeParse({ status: queryValue(params, "status") });
		if (query && !query.success)
			return json(
				{
					code: "VALIDATION_ERROR",
					message: "Validation error",
					originalMessage: query.error.issues
						.map(({ path, message }) => `[query.${path.join(".")}] ${message}`)
						.join("; "),
				},
				400,
			);
		const input = query?.data ?? {};
		const body = write
			? revokeInput.safeParse(await options.readBody(request))
			: undefined;
		const hostId = body?.success ? body.data.host_id : undefined;
		return options.store.transaction(async (client) => {
			const userId = await options.authorizeBrowser(client, request, write);
			if (!userId)
				return write
					? forbidden(
							"Sign in again with a verified account before approving access.",
						)
					: json({ code: "UNAUTHORIZED", message: "Unauthorized" }, 401);
			// AllAuth's owner guard rejects missing IDs along with unknown and foreign hosts.
			if (write)
				return hostId
					? revoke(client, userId, hostId)
					: forbidden(ownerRequired);
			if ("host_id" in input) {
				const host = (
					await client.query<Host>(
						`SELECT ${columns} FROM "agentHost" WHERE id=$1 AND "userId"=$2`,
						[input.host_id, userId],
					)
				).rows[0];
				return host
					? json(publicHost(host))
					: json({ error: "host_not_found", message: "Host not found" }, 404);
			}
			const { rows } = await client.query<Host>(
				`SELECT ${columns} FROM "agentHost" WHERE "userId"=$1 AND ($2::text IS NULL OR status=$2)
				 ORDER BY "createdAt" DESC`,
				[userId, "status" in input ? (input.status ?? null) : null],
			);
			return json({ hosts: rows.map(publicHost) });
		});
	};
}
