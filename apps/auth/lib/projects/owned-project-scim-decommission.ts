import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import { ownedSCIMDecommissionStore } from "./owned-project-scim-decommission-store";
import { ownedSCIMConnectionPrefix } from "./owned-project-scim-managed-credentials";
import type { OwnedSCIMManagementAuthorization } from "./owned-project-scim-management";
import {
	ownedSCIMManagementPathId,
	readOwnedSCIMManagementBody,
	requireOwnedSCIMManagementActor,
	withOwnedSCIMManagementTransaction,
} from "./owned-project-scim-management";
import {
	ownedSCIMManagementFailure,
	ownedSCIMManagementJSON,
} from "./owned-project-scim-management-store";
import { ownedSCIMDatabaseCode } from "./owned-project-scim-mutation";
import { checkedProjectSchema } from "./validation";

const decommissionInput = z.object({}).strict();

/** Candidate retirement for a managed directory in a server-selected project realm. */
export function createOwnedProjectSCIMDecommission(options: {
	database: Pool;
	schemaName: string;
	credentialHashSecret: string;
	managementOrigin: string;
	authorize: OwnedSCIMManagementAuthorization;
}) {
	const schema = checkedProjectSchema(options.schemaName);
	const managementURL = new URL(options.managementOrigin);
	if (
		managementURL.origin !== options.managementOrigin ||
		!/^https?:$/.test(managementURL.protocol)
	)
		throw new Error("Invalid SCIM management origin.");
	if (
		options.credentialHashSecret.length < 32 ||
		typeof options.authorize !== "function"
	)
		throw new Error(
			"SCIM management authority and credential hashing are required.",
		);
	const transaction = <T>(work: (client: PoolClient) => Promise<T>) =>
		withOwnedSCIMManagementTransaction(options.database, schema, false, work);

	return async function decommission(
		request: Request,
	): Promise<Response | null> {
		if (request.method !== "POST") return null;
		const url = new URL(request.url);
		const route =
			/^\/api\/organizations\/([^/]+)\/scim\/([^/]+)\/decommission$/.exec(
				url.pathname,
			);
		if (!route) return null;
		if (
			url.origin !== managementURL.origin ||
			request.headers.get("origin") !== managementURL.origin
		)
			return ownedSCIMManagementFailure(
				403,
				"A same-origin request is required.",
			);
		const organizationId = ownedSCIMManagementPathId(route[1]!, 242);
		const connectionId = ownedSCIMManagementPathId(route[2]!, 255);
		if (!organizationId || !connectionId?.startsWith(ownedSCIMConnectionPrefix))
			return ownedSCIMManagementFailure(
				400,
				"The request contains invalid fields.",
			);
		const store = (client: PoolClient, actorId: string) =>
			ownedSCIMDecommissionStore(
				client,
				organizationId,
				actorId,
				connectionId,
				options.credentialHashSecret,
			);
		try {
			decommissionInput.parse(await readOwnedSCIMManagementBody(request));
			const { actorId, start } = await transaction(async (client) => {
				const actorId = await requireOwnedSCIMManagementActor(
					options.authorize,
					{
						request,
						client,
						organizationId,
						operation: "decommission",
					},
				);
				return { actorId, start: await store(client, actorId).begin() };
			});
			if (start.response) return ownedSCIMManagementJSON(start.response);
			if (start.leaseId) {
				const leaseId = start.leaseId;
				try {
					let binding = start.binding;
					while (binding.decommissionStatus === "reconciling")
						binding = await transaction((client) =>
							store(client, actorId).advance(leaseId),
						);
				} catch (error) {
					// Retain committed checkpoints. A disconnected worker can also be recovered after lease expiry.
					await transaction((client) =>
						store(client, actorId).release(leaseId),
					).catch(() => undefined);
					throw error;
				}
			}
			return ownedSCIMManagementJSON(
				await transaction((client) => store(client, actorId).complete()),
			);
		} catch (error) {
			if (error instanceof Response) return error;
			if (error instanceof z.ZodError)
				return ownedSCIMManagementFailure(
					400,
					"The request contains invalid fields.",
				);
			const code = ownedSCIMDatabaseCode(error);
			if (code === "40001" || code === "40P01")
				return ownedSCIMManagementFailure(
					409,
					"Managed SCIM connection changed concurrently.",
				);
			return ownedSCIMManagementFailure(
				500,
				"Managed SCIM connection could not be retired.",
			);
		}
	};
}
