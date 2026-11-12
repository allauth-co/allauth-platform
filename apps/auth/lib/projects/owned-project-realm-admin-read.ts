import * as z from "zod";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import { realmAdministratorRequestGuard } from "./owned-project-realm-admin-audit";
import {
	listRealmAdminUsers,
	readRealmAdminUser,
	realmAdminListQuery,
} from "./owned-project-realm-admin-directory";

const userPath = "/admin/get-user";
const listPath = "/admin/list-users";
const permissionPath = "/admin/has-permission";
const unauthorized = () =>
	new Response(null, { status: 401, headers: { "Cache-Control": "no-store" } });
const permissionSet = z.record(z.string(), z.array(z.string()));
const permissionInput = z.xor([
	z.object({ permissions: permissionSet }),
	z.object({ permission: permissionSet }),
]);

const realmAdminPermissions: ReadonlyMap<string, ReadonlySet<string>> = new Map(
	[
		[
			"user",
			new Set([
				"create",
				"list",
				"set-role",
				"ban",
				"impersonate",
				"delete",
				"set-password",
				"set-email",
				"get",
				"update",
			]),
		],
		["session", new Set(["list", "revoke", "delete"])],
	],
);

/** Read the current realm authority and its public user projection through native routes. */
export function createOwnedProjectRealmAdminRead(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	trustedRequest(headers: Headers, mutation: boolean): boolean;
	readBody(request: Request): Promise<unknown>;
	readSessionToken(headers: Headers): string | null;
	trustedIP(request: Request): string | null;
	requireMfa: boolean;
}) {
	const { store } = options;
	return async (path: string, request: Request) => {
		const userRead =
			(path === userPath || path === listPath) && request.method === "GET";
		const permissionCheck =
			path === permissionPath && request.method === "POST";
		if (!userRead && !permissionCheck) return;
		if (request.headers.has("authorization"))
			return accountLinkJson(
				{ message: "Use your signed-in browser session for this action." },
				403,
			);
		if (!options.trustedRequest(request.headers, permissionCheck))
			return accountLinkJson({ message: "Invalid origin" }, 403);

		return store.transaction(async (client) => {
			const ip = options.trustedIP(request);
			if (ip) {
				const limited = await admitOwnedProjectNativeRoute(client, ip, path, {
					max: 100,
					windowMs: 60_000,
				});
				if (limited) return limited;
			}
			const token = options.readSessionToken(request.headers);
			const current = token ? await store.session(token, 0, client) : null;
			if (!current || !token) return unauthorized();
			const blocked = realmAdministratorRequestGuard(current);
			if (blocked) return blocked;
			const actor = await store.lockUser(client, current.user.id);
			if (
				!actor ||
				actor.banned ||
				actor.directoryDisabled ||
				!(await store.lockSession(client, token, actor.id, false))
			)
				return unauthorized();
			const changed = realmAdministratorRequestGuard({
				...current,
				user: actor,
			});
			if (changed) return changed;
			if (options.requireMfa && !actor.twoFactorEnabled)
				return accountLinkJson(
					{
						message:
							"This application requires an already verified account enrolled in MFA.",
					},
					403,
				);
			const administrator = actor.role?.split(",").includes("admin") === true;

			if (permissionCheck) {
				const parsed = permissionInput.safeParse(
					await options.readBody(request),
				);
				if (!parsed.success)
					return accountLinkError(
						400,
						"VALIDATION_ERROR",
						"Invalid permission request.",
					);
				if (!("permissions" in parsed.data))
					return accountLinkJson(
						{
							message:
								"invalid permission check. no permission(s) were passed.",
						},
						400,
					);
				const requested = Object.entries(parsed.data.permissions);
				const success =
					administrator &&
					requested.length > 0 &&
					requested.every(
						([resource, actions]) =>
							actions.length > 0 &&
							actions.every(
								(action) =>
									realmAdminPermissions.get(resource)?.has(action) === true,
							),
					);
				return accountLinkJson({ error: null, success });
			}
			const listing = path === listPath;
			if (!administrator)
				return listing
					? accountLinkError(
							403,
							"YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
							"You are not allowed to list users",
						)
					: accountLinkError(
							403,
							"YOU_ARE_NOT_ALLOWED_TO_GET_USER",
							"You are not allowed to get user",
						);
			const query = new URL(request.url).searchParams;
			if (listing) {
				const parameters = Object.fromEntries(
					[...new Set(query.keys())].map((key) => {
						const values = query.getAll(key);
						return [key, values.length === 1 ? values[0] : values];
					}),
				);
				const parsed = realmAdminListQuery.safeParse(parameters);
				if (!parsed.success)
					return accountLinkError(
						400,
						"VALIDATION_ERROR",
						parsed.error.issues
							.map(
								({ path, message }) => `[query.${path.join(".")}] ${message}`,
							)
							.join("; "),
					);
				return accountLinkJson(await listRealmAdminUsers(client, parsed.data));
			}
			const id = query.get("id");
			if (id === null)
				return accountLinkError(
					400,
					"VALIDATION_ERROR",
					"[query.id] Invalid input: expected string, received undefined",
				);
			const user =
				id && !id.includes("\0") ? await readRealmAdminUser(client, id) : null;
			return user
				? accountLinkJson(user)
				: accountLinkError(404, "USER_NOT_FOUND", "User not found");
		});
	};
}
