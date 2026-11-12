import { createAuthEndpoint } from "@better-auth/core/api";
import type { SecondaryStorage } from "@better-auth/core/db";
import type { Pool, PoolClient } from "pg";
import {
	agentKeyRotationPath,
	ownedAgentKeyRotationInput,
	rotateOwnedAgentKey,
} from "./owned-project-agent-key-rotation";
import { consumeAgentMachineReplay } from "./owned-project-agent-machine";

const nativePrefix = "agent-auth:jti:";

function unavailable(): never {
	throw new Error("Unexpected Agent Auth replay storage operation.");
}

/** Adapt the installed Agent plugin's private cache to the realm's fenced replay rows. */
export function nativeProjectAgentReplayStorage(
	database: Pick<PoolClient, "query">,
): SecondaryStorage {
	return {
		async get(key) {
			if (!key.startsWith(nativePrefix)) return unavailable();
			const identity = key.slice(nativePrefix.length);
			const host = identity.startsWith("host:");
			const [principal, ...proofParts] = (
				host ? identity.slice(5) : identity
			).split(":");
			const proof = proofParts.join(":");
			if (!principal || !proof || proof.length > 8192) return "1";
			// Native checks has() immediately before add(). Reserve in the lookup so
			// two replicas cannot pass that check using the same verified proof.
			return (await consumeAgentMachineReplay(
				database,
				host ? "host-registration" : "agent-status",
				principal,
				proof,
			))
				? null
				: "1";
		},
		set(key, value) {
			if (!key.startsWith(nativePrefix) || value !== "1") return unavailable();
		},
		getAndDelete: unavailable,
		increment: unavailable,
		delete: unavailable,
	};
}

/** The installed native Agent key-rotation route lacks a replay check. Share the fenced mutation during rollback. */
export function nativeProjectAgentKeyRotation(database: Pick<Pool, "connect">) {
	return createAuthEndpoint(
		agentKeyRotationPath,
		{
			method: "POST",
			body: ownedAgentKeyRotationInput,
			metadata: {
				openapi: {
					description: "Rotate an agent's public key via host JWT (§A76.8).",
				},
			},
		},
		async (ctx) => {
			const request =
				ctx.request ??
				new Request(`${ctx.context.baseURL}${agentKeyRotationPath}`, {
					method: "POST",
					headers: ctx.headers,
				});
			const client = await database.connect();
			try {
				await client.query("BEGIN");
				const response = await rotateOwnedAgentKey(client, request, ctx.body);
				await client.query("COMMIT");
				return response;
			} catch (error) {
				await client.query("ROLLBACK");
				throw error;
			} finally {
				client.release();
			}
		},
	);
}
