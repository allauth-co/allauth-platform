import { createOwnedProjectSCIMWriteAuthority } from "./owned-project-scim-authority";
import { ownedSCIMError, ownedSCIMURLs } from "./owned-project-scim-discovery";
import {
	normalizeOwnedSCIMGroupMarker,
	parseOwnedSCIMGroup,
} from "./owned-project-scim-group-input";
import { ownedSCIMGroupWriter } from "./owned-project-scim-group-store";
import {
	ownedSCIMDatabaseCode,
	ownedSCIMMutationNoContent,
	ownedSCIMMutationResponse,
	parseOwnedSCIMPatch,
	readOwnedSCIMBody,
	retryOwnedSCIMMutation,
} from "./owned-project-scim-mutation";
import { ownedSCIMGroupResources } from "./owned-project-scim-resources";
import {
	readAttributeProjection,
	readSCIMQuery,
} from "./owned-project-scim-resources-query";

/** Handles candidate Group mutations within the established managed connection and organization. */
export function createOwnedProjectSCIMGroupWrites(
	options: Parameters<typeof createOwnedProjectSCIMWriteAuthority>[0] & {
		baseURL: string;
	},
) {
	const write = createOwnedProjectSCIMWriteAuthority(options);
	const { prefix, location } = ownedSCIMURLs(options.baseURL);
	return async function groupWrites(
		request: Request,
	): Promise<Response | null> {
		const url = new URL(request.url);
		if (!url.pathname.startsWith(prefix)) return null;
		const path = /^Groups(?:\/([^/]+))?$/.exec(
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
			const body =
				method === "DELETE"
					? undefined
					: normalizeOwnedSCIMGroupMarker(
							await readOwnedSCIMBody(request, "Group"),
							method === "POST",
						);
			const replacement =
				method === "POST" || method === "PUT"
					? parseOwnedSCIMGroup(body)
					: undefined;
			const operations =
				method === "PATCH" ? parseOwnedSCIMPatch(body) : undefined;
			return await retryOwnedSCIMMutation("Group", async () => {
				const result = await write(
					request.headers,
					"Groups",
					async (client, connection) => {
						const writer = await ownedSCIMGroupWriter(client, connection);
						if (id && method === "DELETE") {
							await writer.remove(id);
							return ownedSCIMMutationNoContent();
						}
						const projection = readAttributeProjection("Group", query);
						const group = id
							? await writer.update(id, replacement, operations)
							: await writer.create(replacement!);
						const [resource] = await ownedSCIMGroupResources(
							client,
							connection,
							[group],
							location,
							projection,
						);
						return ownedSCIMMutationResponse(
							resource!,
							location(`/scim/v2/Groups/${encodeURIComponent(group.id)}`),
							!id,
						);
					},
				);
				return result.ok
					? result.value
					: ownedSCIMError(result.status, result.detail);
			});
		} catch (error) {
			if (error instanceof Response) return error;
			const code = ownedSCIMDatabaseCode(error);
			if (code === "23505") {
				const constraint =
					error && typeof error === "object" && "constraint" in error
						? error.constraint
						: undefined;
				const detail =
					constraint === "scimGroup_displayNameKey_key"
						? "SCIM Group displayName already exists"
						: constraint === "scimGroup_externalIdKey_key"
							? "SCIM Group externalId already exists"
							: "The SCIM Group identity is already in use";
				return ownedSCIMError(409, detail, "uniqueness");
			}
			if (code === "PAA01")
				return ownedSCIMError(
					403,
					"Free organisations include up to 20 members",
				);
			return ownedSCIMError(500, "SCIM Group mutation failed");
		}
	};
}
