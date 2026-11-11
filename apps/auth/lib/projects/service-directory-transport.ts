// cspell:words aabk
import { createHash } from "node:crypto";
import { APIError } from "better-auth";
import type { Project } from "./registry";
import type { SessionCheckAdmission } from "./session-introspection-admission";

const operations = {
	users: "serviceDirectoryUsers",
	organizations: "serviceDirectoryOrganizations",
	members: "serviceDirectoryMembers",
	roles: "serviceDirectoryRoles",
} as const;
export type DirectoryOperation = (typeof operations)[keyof typeof operations];
interface Dependencies {
	authorize: (headers: Headers) => Promise<void>;
	consume: (key: string) => Promise<SessionCheckAdmission>;
	read: (
		operation: DirectoryOperation,
		headers: Headers,
		query: Record<string, unknown>,
	) => Promise<Response>;
}
const failure = (status: number, code: string, retryAfter?: number) =>
	Response.json(
		{
			error:
				status === 429
					? "Directory reads are temporarily rate limited."
					: "Directory reads are temporarily unavailable.",
			code,
		},
		{
			status,
			headers: {
				"cache-control": "no-store",
				...(retryAfter ? { "retry-after": String(retryAfter) } : {}),
			},
		},
	);

/** Only a freshly verified scoped key can enter these four server-native read paths. */
export async function handleServiceDirectoryRequest(
	request: Request,
	project: Pick<Project, "id" | "slug">,
	dependencies: Dependencies,
): Promise<Response | null> {
	const url = new URL(request.url);
	const prefix = `/api/projects/${project.slug}/auth/service-directory/`;
	if (request.method !== "GET" || !url.pathname.startsWith(prefix)) return null;
	const collection = url.pathname.slice(prefix.length);
	if (!Object.hasOwn(operations, collection)) return null;
	const key = request.headers.get("allauth-backend-key") || "";
	if (!/^aabk_[a-f0-9-]{36}_[A-Za-z0-9_-]{43}$/.test(key)) return null;
	try {
		await dependencies.authorize(request.headers);
	} catch (error) {
		// Invalid credentials retain the ordinary HTTP handler and its IP admission.
		if (
			error instanceof APIError &&
			(error.statusCode === 401 || error.statusCode === 403)
		)
			return null;
		return failure(503, "ALLAUTH_DIRECTORY_UNAVAILABLE");
	}
	try {
		const digest = createHash("sha256")
			.update(JSON.stringify([project.id, key]))
			.digest("hex");
		const admission = await dependencies.consume(
			`backend-directory:v1:${digest}`,
		);
		if (!admission.allowed)
			return failure(
				429,
				"ALLAUTH_DIRECTORY_RATE_LIMITED",
				Math.max(1, Math.ceil(admission.retryAfter)),
			);
		const query: Record<string, unknown> = {};
		for (const name of new Set(url.searchParams.keys())) {
			const values = url.searchParams.getAll(name);
			query[name] = values.length === 1 ? values[0] : values;
		}
		// Directory authority is independent of browser cookies, bearer sessions and proxy claims.
		const headers = new Headers({ "allauth-backend-key": key });
		return await dependencies.read(
			operations[collection as keyof typeof operations],
			headers,
			query,
		);
	} catch (error) {
		if (
			error instanceof APIError &&
			error.statusCode >= 400 &&
			error.statusCode < 500
		)
			return Response.json(
				{
					error:
						error.body?.message || "The directory request is not permitted.",
				},
				{ status: error.statusCode, headers: { "cache-control": "no-store" } },
			);
		return failure(503, "ALLAUTH_DIRECTORY_UNAVAILABLE");
	}
}
