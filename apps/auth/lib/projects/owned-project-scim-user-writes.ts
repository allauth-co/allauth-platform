import { createOwnedProjectSCIMWriteAuthority } from "./owned-project-scim-authority";
import type { SCIMProfileAdmission } from "./owned-project-scim-directory-writes";
import { ownedSCIMDirectoryWriter } from "./owned-project-scim-directory-writes";
import {
	ownedSCIMError,
	ownedSCIMResponse,
	ownedSCIMURLs,
} from "./owned-project-scim-discovery";
import { ownedSCIMUserResource } from "./owned-project-scim-resources";
import {
	readAttributeProjection,
	readSCIMQuery,
} from "./owned-project-scim-resources-query";
import {
	parseOwnedSCIMUser,
	parseOwnedSCIMUserPatch,
	patchOwnedSCIMUser,
} from "./owned-project-scim-user-input";

async function readBody(request: Request): Promise<unknown> {
	const media = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	if (media !== "application/scim+json" && media !== "application/json")
		throw ownedSCIMError(
			415,
			"SCIM requests must use application/scim+json or application/json",
		);
	const reader = request.body?.getReader();
	const decoder = new TextDecoder();
	let size = 0;
	let body = "";
	if (reader) {
		try {
			while (true) {
				const chunk = await reader.read();
				if (chunk.done) break;
				size += chunk.value.byteLength;
				if (size > 262_144) {
					await reader.cancel().catch(() => undefined);
					throw ownedSCIMError(
						413,
						"SCIM User request exceeds the supported size",
					);
				}
				body += decoder.decode(chunk.value, { stream: true });
			}
			body += decoder.decode();
		} finally {
			reader.releaseLock();
		}
	}
	try {
		return JSON.parse(body);
	} catch {
		throw ownedSCIMError(
			400,
			"SCIM request body must contain valid JSON",
			"invalidSyntax",
		);
	}
}

function databaseCode(error: unknown) {
	return error && typeof error === "object" && "code" in error
		? error.code
		: undefined;
}

/** Handles candidate organization-bound SCIM User writes with transaction-bound profile admission. */
export function createOwnedProjectSCIMUserWrites(
	options: Parameters<typeof createOwnedProjectSCIMWriteAuthority>[0] & {
		baseURL: string;
		admitProfile: SCIMProfileAdmission;
	},
) {
	if (typeof options.admitProfile !== "function")
		throw new Error("SCIM profile admission is required.");
	const write = createOwnedProjectSCIMWriteAuthority(options);
	const { prefix, location } = ownedSCIMURLs(options.baseURL);
	return async function userWrites(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(prefix)) return null;
		const path = /^Users(?:\/([^/]+))?$/.exec(
			url.pathname.slice(prefix.length),
		);
		if (!path) return null;
		const id = path[1];
		const method = request.method;
		if (id ? !["PUT", "PATCH", "DELETE"].includes(method) : method !== "POST")
			return null;
		try {
			const query =
				method === "DELETE" ? {} : readSCIMQuery(url.searchParams, false);
			const body = method === "DELETE" ? undefined : await readBody(request);
			const profile =
				method === "POST" || method === "PUT"
					? parseOwnedSCIMUser(body)
					: undefined;
			const operations =
				method === "PATCH" ? parseOwnedSCIMUserPatch(body) : undefined;
			for (let attempt = 1; attempt <= 3; attempt++) {
				try {
					const result = await write(
						request.headers,
						"Users",
						async (client, connection) => {
							const writer = await ownedSCIMDirectoryWriter(
								client,
								connection,
								request,
								options.admitProfile,
							);
							if (id && method === "DELETE") {
								await writer.remove(id);
								return new Response(null, {
									status: 204,
									headers: {
										"Content-Type": "application/scim+json",
										"Cache-Control": "no-store",
										Pragma: "no-cache",
									},
								});
							}
							const projection = readAttributeProjection("User", query);
							const row = id
								? await writer.update(
										id,
										(current) =>
											operations
												? patchOwnedSCIMUser(current, operations)
												: profile!,
										method === "PATCH",
									)
								: await writer.create(profile!);
							const response = ownedSCIMResponse(
								ownedSCIMUserResource(row, location, projection),
								id ? 200 : 201,
							);
							const resourceLocation = location(
								`/scim/v2/Users/${encodeURIComponent(row.id)}`,
							);
							response.headers.set("Location", resourceLocation);
							if (!id)
								response.headers.set("Content-Location", resourceLocation);
							return response;
						},
					);
					return result.ok
						? result.value
						: ownedSCIMError(result.status, result.detail);
				} catch (error) {
					const code = databaseCode(error);
					if (code !== "40001" && code !== "40P01") throw error;
				}
			}
			return ownedSCIMError(
				409,
				"The SCIM User changed concurrently; retry the request",
			);
		} catch (error) {
			if (error instanceof Response) return error;
			const code = databaseCode(error);
			if (code === "23505")
				return ownedSCIMError(
					409,
					"The SCIM User identity is already in use",
					"uniqueness",
				);
			if (code === "PAA01")
				return ownedSCIMError(
					403,
					"Free organisations include up to 20 members",
				);
			return ownedSCIMError(500, "SCIM User mutation failed");
		}
	};
}
