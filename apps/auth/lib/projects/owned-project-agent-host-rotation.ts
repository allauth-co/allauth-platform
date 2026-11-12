import { calculateJwkThumbprint, type JWK } from "jose";
import type { PoolClient } from "pg";
import * as z from "zod";
import { hasRemoteAgentKeys } from "../features/helpers";
import {
	agentHostJSON as json,
	invalidAgentBody,
	lockOwnedAgentHostKey,
	ownedAgentPublicJwkInput,
	readOwnedAgentPublicKey,
} from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	consumeAgentMachineReplay,
	decodeAgentMachineJWT,
	invalidAgentJWT,
	readAgentMachineHost,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";

export const agentHostRotationPath = "/host/rotate-key";
const input = z.object({ public_key: ownedAgentPublicJwkInput });

/** Replace a known inline host key using the installed thumbprint ID contract. */
export async function rotateOwnedAgentHost(
	client: PoolClient,
	request: Request,
	body: unknown,
) {
	if (hasRemoteAgentKeys(body))
		return json(
			{
				message:
					"Use an inline public key. Remote key discovery is not active.",
			},
			400,
		);
	const parsed = input.safeParse(body);
	if (!parsed.success) return invalidAgentBody(parsed.error);
	const url = new URL(request.url);
	const decoded = decodeAgentMachineJWT(request);
	if (decoded === null) return invalidAgentJWT();
	if (
		!decoded ||
		decoded.typ !== "host+jwt" ||
		!validAgentIdentifier(decoded.claims.iss)
	)
		return invalidAgentJWT(url.origin);
	const issuer = decoded.claims.iss;
	const audience = agentMachineAudience(url, agentHostRotationPath);
	if (
		![decoded.claims.aud]
			.flat()
			.some((value) => value && audience.includes(value))
	)
		return invalidAgentJWT(url.origin);
	const unavailable = () =>
		problem(401, "agent_not_found", "Agent not found", url.origin);
	const host = await readAgentMachineHost(client, issuer);
	if (!host?.userId || !host.publicKey || host.status !== "active")
		return unavailable();
	const proof = await verifyAgentMachineJWT(
		decoded.token,
		host,
		audience,
		url.origin,
	);
	if (proof instanceof Response) return proof;
	if (host.id !== issuer)
		return problem(404, "host_not_found", "Host not found");
	if (!validAgentIdentifier(proof.jti)) return invalidAgentJWT();
	const key = await readOwnedAgentPublicKey(parsed.data.public_key);
	if (key instanceof Response) return key;
	const newHostId = await calculateJwkThumbprint(parsed.data.public_key as JWK);
	await lockOwnedAgentHostKey(client, key, newHostId);
	const locked = await readAgentMachineHost(client, issuer, "update");
	if (!locked || locked.id !== host.id || locked.status !== "active")
		return unavailable();
	if (
		locked.userId !== host.userId ||
		locked.publicKey !== host.publicKey ||
		locked.jwksUrl !== host.jwksUrl
	)
		return invalidAgentJWT(url.origin);
	// The installed host rotation and registration routes consume the same host JTI.
	if (
		!(await consumeAgentMachineReplay(
			client,
			"host-registration",
			host.id,
			proof.jti,
		))
	)
		return problem(401, "jti_replay", "JWT has already been used");
	const collision = await client.query(
		`SELECT 1 FROM "agentHost" WHERE id<>$1 AND (id=$2 OR kid=$2 OR id=NULLIF($3,'') OR kid=NULLIF($3,'') OR "publicKey"=$4) LIMIT 1`,
		[host.id, newHostId, key.kid, key.serialized],
	);
	if (collision.rowCount)
		return problem(
			409,
			"host_already_linked",
			"Host is already linked to a different user",
		);
	if (newHostId !== host.id) {
		const {
			rows: [existing],
		} = await client.query<{ linked: boolean }>(
			`SELECT EXISTS (SELECT 1 FROM "agent" WHERE "hostId"=$1) OR EXISTS (SELECT 1 FROM "approvalRequest" WHERE "hostId"=$1) AS linked`,
			[host.id],
		);
		if (existing.linked)
			return problem(
				409,
				"host_rotation_blocked",
				"This host has existing agents or approval records.",
			);
	}
	await client.query(
		`UPDATE "agentHost" SET id=$2,"publicKey"=$3,kid=$4,"updatedAt"=transaction_timestamp() WHERE id=$1`,
		[host.id, newHostId, key.serialized, key.kid],
	);
	return json({ host_id: newHostId, status: "active" });
}
