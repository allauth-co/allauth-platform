import { decodeProtectedHeader } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	decideOwnedAgentApproval,
	listOwnedAgentApprovals,
} from "./owned-project-agent-approvals";
import {
	ownedAgentRevokeInput,
	ownedBrowserAgentQuery,
	readOwnedBrowserAgent,
	revokeOwnedBrowserAgent,
	revokeOwnedHostAgent,
} from "./owned-project-agent-browser";
import {
	agentHostCapabilities,
	agentHostJSON as json,
	createOwnedAgentHost,
	enrollOwnedAgentHost,
	invalidAgentBody,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem,
	decodeAgentMachineJWT,
	invalidAgentJWT,
	readAgentMachineHost,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";
import { registerOwnedProjectAgent } from "./owned-project-agent-registration";
import { readOwnedAgentStatus } from "./owned-project-agent-status";
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
const revokePath = "/host/revoke";
const agentRevokePath = "/agent/revoke";

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
		mode: "read" | "write" | "fresh",
	): Promise<string | null>;
};

const columns = `id,name,"defaultCapabilities",status,"activatedAt","expiresAt","lastUsedAt","createdAt","updatedAt"`;

function publicHost(host: Host) {
	return {
		id: host.id,
		name: host.name || `Device ${host.id.slice(0, 8)}`,
		default_capabilities: agentHostCapabilities(host.defaultCapabilities),
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

async function revokeLockedHost(
	client: PoolClient,
	hostId: string,
	status: string,
) {
	if (status === "revoked")
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

async function revokeBrowserHost(
	client: PoolClient,
	userId: string,
	hostId: string,
) {
	const {
		rows: [host],
	} = await client.query<{ status: string }>(
		`SELECT status FROM "agentHost" WHERE id=$1 AND "userId"=$2 FOR UPDATE`,
		[hostId, userId],
	);
	return host
		? revokeLockedHost(client, hostId, host.status)
		: forbidden(ownerRequired);
}

function hasSignedHostType(request: Request) {
	const token = /^Bearer\s+(\S+)$/i.exec(
		request.headers.get("authorization") ?? "",
	)?.[1];
	try {
		return Boolean(
			token &&
				token.length <= 8192 &&
				decodeProtectedHeader(token).typ === "host+jwt",
		);
	} catch {
		return false;
	}
}

async function verifyRevokingHost(
	client: PoolClient,
	request: Request,
	path: typeof revokePath | typeof agentRevokePath,
) {
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (
		!decoded ||
		decoded.typ !== "host+jwt" ||
		!validAgentIdentifier(decoded.claims.iss)
	)
		return invalidAgentJWT(url.origin);
	const audience = agentMachineAudience(url, path);
	if (
		![decoded.claims.aud]
			.flat()
			.some((value) => value && audience.includes(value))
	)
		return invalidAgentJWT(url.origin);
	const issuer = decoded.claims.iss;
	const hostUnavailable = () =>
		agentMachineProblem(401, "agent_not_found", "Agent not found", url.origin);
	const host = await readAgentMachineHost(client, issuer);
	if (!host?.userId || !host.publicKey || host.status !== "active")
		return hostUnavailable();
	const proof = await verifyAgentMachineJWT(
		decoded.token,
		host,
		audience,
		url.origin,
	);
	if (proof instanceof Response) return proof;
	const locked = await readAgentMachineHost(
		client,
		issuer,
		path === revokePath ? "update" : "share",
	);
	if (!locked || locked.id !== host.id || locked.status !== "active")
		return hostUnavailable();
	if (
		locked.userId !== host.userId ||
		locked.publicKey !== host.publicKey ||
		locked.jwksUrl !== host.jwksUrl
	)
		return invalidAgentJWT(url.origin);
	return locked;
}

async function signedHostRevoke(
	client: PoolClient,
	request: Request,
	path: typeof revokePath | typeof agentRevokePath,
	body: unknown,
) {
	const host = await verifyRevokingHost(client, request, path);
	if (host instanceof Response) return host;
	if (path === agentRevokePath) {
		const input = ownedAgentRevokeInput(body);
		return input instanceof Response
			? input
			: revokeOwnedHostAgent(client, host.id, input);
	}
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = revokeInput.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	if (parsed.data.host_id !== undefined && parsed.data.host_id !== host.id)
		return agentMachineProblem(
			403,
			"unauthorized",
			"Caller is not authorized for this operation",
		);
	return revokeLockedHost(client, host.id, host.status);
}

/** Browser host management and token enrollment for the isolated candidate fixture. */
export function createOwnedProjectAgentHosts(options: BrowserHosts) {
	return async (
		path: string,
		request: Request,
	): Promise<Response | undefined> => {
		const decision =
			request.method === "POST" && path === "/agent/approve-capability";
		const pending = request.method === "GET" && path === "/agent/ciba/pending";
		const status = request.method === "GET" && path === "/agent/status";
		const register = request.method === "POST" && path === "/agent/register";
		const agentRead =
			request.method === "GET" &&
			(path === "/agent/get" || path === "/agent/list");
		const agentRevoke = request.method === "POST" && path === agentRevokePath;
		const hostRevoke = request.method === "POST" && path === revokePath;
		const write =
			decision ||
			agentRevoke ||
			hostRevoke ||
			(request.method === "POST" && path === "/host/create");
		const enroll = request.method === "POST" && path === "/host/enroll";
		const read =
			request.method === "GET" &&
			(path === "/host/get" || path === "/host/list");
		if (
			!write &&
			!read &&
			!enroll &&
			!pending &&
			!status &&
			!register &&
			!agentRead
		)
			return;
		const limited = await options.store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: register
					? 10
					: decision
						? 5
						: pending || status
							? 300
							: agentRead || agentRevoke
								? 60
								: 100,
				windowMs: 60_000,
			}),
		);
		if (limited) return limited;
		if (status)
			return options.store.transaction((client) =>
				readOwnedAgentStatus(client, request),
			);
		if (register) {
			const body = await options.readBody(request);
			return options.store.transaction((client) =>
				registerOwnedProjectAgent(client, request, body),
			);
		}
		if (request.headers.has("authorization")) {
			if ((hostRevoke || agentRevoke) && hasSignedHostType(request)) {
				const body = await options.readBody(request);
				return options.store.transaction((client) =>
					signedHostRevoke(client, request, path, body),
				);
			}
			if (hostRevoke && request.headers.get("authorization"))
				return forbidden(
					"Use your browser session or a valid signed host request.",
				);
			return forbidden("Use your signed-in browser session for this action.");
		}
		if (!options.trustedRequest(request.headers, write))
			return forbidden("This authentication request is not permitted.");
		const body = write || enroll ? await options.readBody(request) : undefined;
		if (enroll)
			return options.store.transaction((client) =>
				enrollOwnedAgentHost(client, body),
			);
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
		const browserQuery = agentRead
			? ownedBrowserAgentQuery(path, request)
			: null;
		const browserRevoke = agentRevoke ? ownedAgentRevokeInput(body) : null;
		if (browserQuery instanceof Response) return browserQuery;
		if (browserRevoke instanceof Response) return browserRevoke;
		return options.store.transaction(async (client) => {
			const userId = await options.authorizeBrowser(
				client,
				request,
				agentRevoke ? "write" : write ? "fresh" : "read",
			);
			if (!userId) {
				if (agentRevoke)
					return json(
						{ error: "unauthorized", message: "Authentication required" },
						401,
					);
				return write
					? forbidden(
							"Sign in again with a verified account before approving access.",
						)
					: json({ code: "UNAUTHORIZED", message: "Unauthorized" }, 401);
			}
			if (browserQuery)
				return readOwnedBrowserAgent(client, userId, browserQuery);
			if (browserRevoke)
				return revokeOwnedBrowserAgent(client, userId, browserRevoke);
			if (decision) return decideOwnedAgentApproval(client, userId, body);
			if (pending) return listOwnedAgentApprovals(client, userId);
			if (write) {
				if (path === "/host/create")
					return createOwnedAgentHost(client, userId, body);
				// AllAuth's owner guard rejects missing IDs along with unknown and foreign hosts.
				const target = revokeInput.safeParse(body);
				return target.success && target.data.host_id
					? revokeBrowserHost(client, userId, target.data.host_id)
					: forbidden(ownerRequired);
			}
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
