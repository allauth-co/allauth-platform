import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { isServerTokenRequest } from "../features/helpers";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { projectUserResponse } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";

type Store = ReturnType<typeof createProjectEngineStore>;
const generatePath = "/one-time-token/generate";
const verifyPath = "/one-time-token/verify";
const tokenInput = z.object({ token: z.string().min(1).max(1024) });

function identifier(token: string) {
	return `one-time-token:${createHash("sha256").update(token).digest("base64url")}`;
}

function response(body: unknown, status = 200) {
	return Response.json(body, {
		status,
		headers: { "cache-control": "no-store", pragma: "no-cache" },
	});
}

const serverOnly = () =>
	response(
		{
			message: "One-time session tokens are reserved for server integrations.",
		},
		403,
	);

/** Legacy-compatible transfer of an existing session without creating or setting a cookie. */
export function createOwnedProjectOneTimeToken(options: {
	store: Store;
	readBody(request: Request): Promise<unknown>;
	trustedIP(request: Request): string | null;
	sessionToken(headers: Headers): string | null;
	eligible(
		token: string,
		client: PoolClient,
	): Promise<Awaited<ReturnType<Store["session"]>> | null>;
}) {
	const { store } = options;

	async function currentSession(headers: Headers, client: PoolClient) {
		const token = options.sessionToken(headers);
		const session = token && (await options.eligible(token, client));
		if (!session || !token) return null;
		return { token, userId: session.user.id };
	}

	async function issue(headers: Headers) {
		if (!isServerTokenRequest(headers)) return serverOnly();
		return store.transaction(async (client) => {
			const current = await currentSession(headers, client);
			if (
				!current ||
				!(await store.lockSession(client, current.token, current.userId, false))
			)
				return response({ message: "Unauthorized" }, 401);
			const token = randomBytes(24).toString("base64url");
			await client.query(
				`INSERT INTO "verification" (id,identifier,value,"expiresAt")
				 VALUES ($1,$2,$3,statement_timestamp()+interval '1 minute')`,
				[randomUUID(), identifier(token), current.token],
			);
			return response({ token });
		});
	}

	async function verify(token: string) {
		return store.transaction(async (client) => {
			const {
				rows: [record],
			} = await client.query<{ value: string; live: boolean }>(
				`WITH consumed AS (
					DELETE FROM "verification" WHERE identifier=$1
					RETURNING id,value,"createdAt","expiresAt"
				 )
				 SELECT value,"expiresAt">statement_timestamp() AS live
				 FROM consumed ORDER BY "createdAt" DESC,id DESC LIMIT 1`,
				[identifier(token)],
			);
			if (!record?.live) return response({ message: "Invalid token" }, 400);
			const {
				rows: [session],
			} = await client.query<{ live: boolean }>(
				`SELECT "expiresAt">statement_timestamp() AS live FROM "session"
				 WHERE token=$1 FOR SHARE`,
				[record.value],
			);
			if (!session) return response({ message: "Session not found" }, 400);
			if (!session.live) return response({ message: "Session expired" }, 400);
			const current = await options.eligible(record.value, client);
			if (!current) return response({ message: "Session not found" }, 400);
			return response({
				session: { ...current.session, token: record.value },
				user: {
					...projectUserResponse(current.user),
					directoryManaged: current.user.directoryManaged,
					directoryDisabled: current.user.directoryDisabled,
				},
			});
		});
	}

	async function dispatch(path: string, request: Request) {
		const generate = path === generatePath && request.method === "GET";
		if (!generate && !(path === verifyPath && request.method === "POST"))
			return null;
		const denied = await store.transaction((client) =>
			admitOwnedProjectNativeRoute(client, options.trustedIP(request), path, {
				max: 100,
				windowMs: 60_000,
			}),
		);
		if (denied) return denied;
		if (!isServerTokenRequest(request.headers)) return serverOnly();
		if (generate)
			return store.transaction(async (client) =>
				(await currentSession(request.headers, client))
					? response({ message: "Client requests are disabled" }, 400)
					: response({ message: "Unauthorized" }, 401),
			);
		const parsed = tokenInput.safeParse(await options.readBody(request));
		return parsed.success
			? verify(parsed.data.token)
			: response({ message: "Invalid token" }, 400);
	}

	return { dispatch, issue };
}
