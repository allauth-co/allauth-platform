import type { PoolClient } from "pg";
import * as z from "zod";
import { agentHostJSON as json } from "./owned-project-agent-enrollment";
import {
	agentMachineAudience,
	agentMachineProblem as problem,
	decodeAgentMachineJWT,
	readAgentMachineHost,
	validAgentIdentifier,
	verifyAgentMachineJWT,
} from "./owned-project-agent-machine";
import {
	authorizeOwnedAgentRead,
	refreshOwnedAgentRead,
} from "./owned-project-agent-status";

const listQuery = z.object({
	query: z.string().optional(),
	cursor: z.string().optional(),
	limit: z.coerce.number().optional(),
});
const describeQuery = z.object({ name: z.string() });

function queryValue(url: URL, name: string) {
	const values = url.searchParams.getAll(name);
	return values.length > 1 ? values : values[0];
}

function authenticationRequired(origin: string) {
	return problem(
		401,
		"authentication_required",
		"This server requires authentication to list capabilities. Connect an agent first, then retry with the agent JWT.",
		origin,
	);
}

/** Project fixtures expose the configured empty catalog only to a live machine principal. */
export async function readOwnedAgentCatalog(
	client: PoolClient,
	request: Request,
	path: "/capability/list" | "/capability/describe",
) {
	const url = new URL(request.url);
	const input =
		path === "/capability/describe"
			? describeQuery.safeParse({ name: queryValue(url, "name") })
			: listQuery.safeParse({
					query: queryValue(url, "query"),
					cursor: queryValue(url, "cursor"),
					limit: queryValue(url, "limit"),
				});
	if (!input.success)
		return json(
			{
				code: "VALIDATION_ERROR",
				message: "Validation error",
				originalMessage: input.error.issues
					.map(({ path, message }) => `[query.${path.join(".")}] ${message}`)
					.join("; "),
			},
			400,
		);
	const decoded = decodeAgentMachineJWT(request);
	if (!decoded) return authenticationRequired(url.origin);
	const audience = agentMachineAudience(url, path);
	if (decoded.typ === "host+jwt") {
		if (!validAgentIdentifier(decoded.claims.iss))
			return authenticationRequired(url.origin);
		const host = await readAgentMachineHost(
			client,
			decoded.claims.iss,
			"share",
		);
		if (!host?.userId || host.status !== "active")
			return authenticationRequired(url.origin);
		const proof = await verifyAgentMachineJWT(
			decoded.token,
			host,
			audience,
			url.origin,
		);
		if (proof instanceof Response) return authenticationRequired(url.origin);
	} else {
		const agent = await authorizeOwnedAgentRead(
			client,
			request,
			url,
			audience,
			decoded,
		);
		if (agent instanceof Response) return authenticationRequired(url.origin);
		const refreshed = await refreshOwnedAgentRead(client, agent, url.origin);
		if (refreshed instanceof Response)
			return authenticationRequired(url.origin);
	}
	return "name" in input.data
		? problem(
				404,
				"capability_not_found",
				`Capability "${input.data.name}" does not exist.`,
			)
		: json({ capabilities: [], has_more: false });
}
