import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import {
	ownedSCIMConnectionPrefix,
	ownedSCIMCredentialPrefix,
} from "./owned-project-scim-managed-credentials";
import {
	ownedSCIMManagementFailure,
	ownedSCIMManagementJSON,
	ownedSCIMManagementStore,
} from "./owned-project-scim-management-store";
import { ownedSCIMDatabaseCode } from "./owned-project-scim-mutation";
import { checkedProjectSchema } from "./validation";

type Operation = "list" | "create" | "rotate" | "revoke" | "decommission";
export type OwnedSCIMManagementAuthorization = (input: {
	request: Request;
	client: Pick<PoolClient, "query">;
	organizationId: string;
	operation: Operation;
}) => Promise<{ actorId: string } | Response>;

const createInput = z
	.object({ providerId: z.string().trim().min(1).max(255) })
	.strict();
const rotateInput = z.object({}).strict();
const revokeInput = z
	.object({
		credentialId: z.string().startsWith(ownedSCIMCredentialPrefix).max(255),
	})
	.strict();

function privateResponse(response: Response) {
	const headers = new Headers(response.headers);
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	headers.set("X-Content-Type-Options", "nosniff");
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

export async function readOwnedSCIMManagementBody(
	request: Request,
): Promise<unknown> {
	const reader = request.body?.getReader();
	if (!reader) return undefined;
	const decoder = new TextDecoder();
	let size = 0;
	let body = "";
	try {
		while (true) {
			const result = await reader.read();
			if (result.done) break;
			size += result.value.byteLength;
			if (size > 4096) {
				await reader.cancel().catch(() => undefined);
				throw ownedSCIMManagementFailure(
					413,
					"The request exceeds the supported size.",
				);
			}
			body += decoder.decode(result.value, { stream: true });
		}
		body += decoder.decode();
	} finally {
		reader.releaseLock();
	}
	try {
		return JSON.parse(body);
	} catch {
		return undefined;
	}
}

export function ownedSCIMManagementPathId(value: string, max: number) {
	try {
		const id = decodeURIComponent(value);
		return id.length <= max &&
			/^[^/\u0000-\u001f\u007f]+$/.test(id) &&
			id === id.trim()
			? id
			: undefined;
	} catch {
		return;
	}
}

export async function requireOwnedSCIMManagementActor(
	authorize: OwnedSCIMManagementAuthorization,
	input: Parameters<OwnedSCIMManagementAuthorization>[0],
) {
	const principal = await authorize(input);
	if (principal instanceof Response) throw privateResponse(principal);
	if (
		typeof principal?.actorId !== "string" ||
		!principal.actorId.trim() ||
		principal.actorId.length > 255
	)
		throw ownedSCIMManagementFailure(403, "The request is not permitted.");
	return principal.actorId;
}

/** Pins management writes and read snapshots to the server-selected project schema. */
export async function withOwnedSCIMManagementTransaction<T>(
	database: Pool,
	schemaName: string,
	readOnly: boolean,
	work: (client: PoolClient) => Promise<T>,
) {
	const schema = checkedProjectSchema(schemaName);
	const client = await database.connect();
	let discard = false;
	try {
		await client.query(
			readOnly ? "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY" : "BEGIN",
		);
		await client.query(`SET LOCAL search_path TO "${schema}"`);
		const result = await work(client);
		await client.query("COMMIT");
		return result;
	} catch (error) {
		try {
			await client.query("ROLLBACK");
		} catch {
			discard = true;
		}
		throw error;
	} finally {
		client.release(discard);
	}
}

/** Candidate directory management for a project realm selected by trusted server code. */
export function createOwnedProjectSCIMManagement(options: {
	database: Pool;
	schemaName: string;
	credentialHashSecret: string;
	managementOrigin: string;
	/** Full server-selected connector URL ending in `/scim/v2`. */
	baseURL: string;
	authorize: OwnedSCIMManagementAuthorization;
}) {
	const schema = checkedProjectSchema(options.schemaName);
	const managementURL = new URL(options.managementOrigin);
	const connector = new URL(options.baseURL);
	if (
		managementURL.origin !== options.managementOrigin ||
		!/^https?:$/.test(managementURL.protocol)
	)
		throw new Error("Invalid SCIM management origin.");
	if (
		!/^https?:$/.test(connector.protocol) ||
		connector.username ||
		connector.password ||
		connector.search ||
		connector.hash ||
		!connector.pathname.endsWith("/scim/v2")
	)
		throw new Error("Invalid SCIM connector URL.");
	if (
		options.credentialHashSecret.length < 32 ||
		typeof options.authorize !== "function"
	)
		throw new Error(
			"SCIM management authority and credential hashing are required.",
		);
	const baseURL = connector.toString();
	return async function manage(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const path =
			/^\/api\/organizations\/([^/]+)\/scim(?:\/([^/]+)\/(rotate|revoke))?$/.exec(
				url.pathname,
			);
		if (!path) return null;
		const operation: Operation | undefined =
			request.method === "POST"
				? path[3] === "rotate" || path[3] === "revoke"
					? path[3]
					: "create"
				: request.method === "GET" && !path[3]
					? "list"
					: undefined;
		if (!operation) return null;
		if (
			url.origin !== managementURL.origin ||
			(operation !== "list" &&
				request.headers.get("origin") !== managementURL.origin)
		)
			return ownedSCIMManagementFailure(
				403,
				"A same-origin request is required.",
			);
		const organizationId = ownedSCIMManagementPathId(path[1]!, 242);
		const connectionId = path[2]
			? ownedSCIMManagementPathId(path[2], 255)
			: undefined;
		if (
			!organizationId ||
			(path[2] && !connectionId?.startsWith(ownedSCIMConnectionPrefix))
		)
			return ownedSCIMManagementFailure(
				400,
				"The request contains invalid fields.",
			);
		try {
			const body =
				operation === "list"
					? undefined
					: await readOwnedSCIMManagementBody(request);
			return await withOwnedSCIMManagementTransaction(
				options.database,
				schema,
				operation === "list",
				async (client) => {
					const actorId = await requireOwnedSCIMManagementActor(
						options.authorize,
						{
							request,
							client,
							organizationId,
							operation,
						},
					);
					const store = ownedSCIMManagementStore(
						client,
						organizationId,
						actorId,
						options.credentialHashSecret,
					);
					let response: Response;
					if (operation === "list")
						response = ownedSCIMManagementJSON({
							connections: await store.list(),
							baseURL,
						});
					else {
						if (operation === "create")
							response = ownedSCIMManagementJSON(
								{
									...(await store.create(createInput.parse(body).providerId)),
									baseURL,
								},
								201,
							);
						else if (operation === "rotate") {
							rotateInput.parse(body);
							response = ownedSCIMManagementJSON({
								...(await store.rotate(connectionId!)),
								baseURL,
							});
						} else
							response = ownedSCIMManagementJSON(
								await store.revoke(
									connectionId!,
									revokeInput.parse(body).credentialId,
								),
							);
					}
					return response;
				},
			);
		} catch (error) {
			if (error instanceof Response) return error;
			if (error instanceof z.ZodError)
				return ownedSCIMManagementFailure(
					400,
					"The request contains invalid fields.",
				);
			const code = ownedSCIMDatabaseCode(error);
			if (code === "23505")
				return ownedSCIMManagementFailure(
					409,
					"A record with this identifier already exists.",
				);
			if (code === "40001" || code === "40P01")
				return ownedSCIMManagementFailure(
					409,
					"Managed SCIM connection changed concurrently",
				);
			return ownedSCIMManagementFailure(
				500,
				"The request could not be completed.",
			);
		}
	};
}
