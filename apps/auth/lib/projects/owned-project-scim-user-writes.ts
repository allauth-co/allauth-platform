import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { createOwnedProjectSCIMWriteAuthority } from "./owned-project-scim-authority";
import type { SCIMProfileAdmission } from "./owned-project-scim-directory-writes";
import { ownedSCIMDirectoryWriter } from "./owned-project-scim-directory-writes";
import { ownedSCIMError, ownedSCIMURLs } from "./owned-project-scim-discovery";
import {
	ownedSCIMDatabaseCode,
	ownedSCIMMutationNoContent,
	ownedSCIMMutationResponse,
	parseOwnedSCIMPatch,
	readOwnedSCIMBody,
	retryOwnedSCIMMutation,
} from "./owned-project-scim-mutation";
import { ownedSCIMUserResource } from "./owned-project-scim-resources";
import {
	readAttributeProjection,
	readSCIMQuery,
} from "./owned-project-scim-resources-query";
import {
	parseOwnedSCIMUser,
	patchOwnedSCIMUser,
} from "./owned-project-scim-user-input";

/** Handles candidate organization-bound SCIM User writes with transaction-bound profile admission. */
export function createOwnedProjectSCIMUserWrites(
	options: Parameters<typeof createOwnedProjectSCIMWriteAuthority>[0] & {
		baseURL: string;
		admitProfile: SCIMProfileAdmission;
		emailAliases?: Pick<OwnedProjectEmailAliases, "reserved">;
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
			const body =
				method === "DELETE"
					? undefined
					: await readOwnedSCIMBody(request, "User");
			const profile =
				method === "POST" || method === "PUT"
					? parseOwnedSCIMUser(body)
					: undefined;
			const operations =
				method === "PATCH" ? parseOwnedSCIMPatch(body) : undefined;
			return await retryOwnedSCIMMutation("User", async () => {
				const result = await write(
					request.headers,
					"Users",
					async (client, connection) => {
						const writer = await ownedSCIMDirectoryWriter(
							client,
							connection,
							request,
							options.admitProfile,
							options.emailAliases,
						);
						if (id && method === "DELETE") {
							await writer.remove(id);
							return ownedSCIMMutationNoContent();
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
						return ownedSCIMMutationResponse(
							ownedSCIMUserResource(row, location, projection),
							location(`/scim/v2/Users/${encodeURIComponent(row.id)}`),
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
