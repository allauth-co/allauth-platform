import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { passwordPolicyError } from "../auth-policy/password";
import type { AuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import type { ControlPrincipal } from "../control/types";
import { reservedProjectEmailError } from "../project-email-alias-config";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import type { Project } from "./registry";

const routePrefix = "/project-admin/";
const publicFields = `id,email,name,"emailVerified",role,banned,"banReason","banExpires",image,"createdAt","updatedAt","publicMetadata"`;
const role = z.enum(["user", "admin"]);
const userId = z.string().min(1).max(160);
const user = z.strictObject({ userId });
const createInput = z.strictObject({
	email: z
		.email()
		.max(320)
		.transform((email) => email.toLowerCase()),
	name: z.string().trim().min(1).max(100),
	password: z.string().max(128).optional(),
	role: role.default("user"),
});
const banInput = z.strictObject({
	userId,
	banReason: z.string().trim().max(500).optional(),
	banExpiresIn: z
		.number()
		.int()
		.min(1)
		.max(365 * 86_400)
		.optional(),
});
const roleInput = z.strictObject({ userId, role });
const listInput = z.strictObject({
	limit: z.coerce.number().int().min(1).max(100).default(25),
	offset: z.coerce.number().int().min(0).max(100_000).default(0),
	searchValue: z.string().trim().max(128).optional(),
	searchField: z.enum(["email", "name", "id"]).default("email"),
	searchOperator: z.enum(["contains", "eq", "starts_with"]).default("contains"),
	sortBy: z.enum(["createdAt", "email", "name"]).default("createdAt"),
	sortDirection: z.enum(["asc", "desc"]).default("desc"),
});
const mutationInputs = new Map<string, z.ZodType<{ userId: string }>>([
	["ban-user", banInput],
	["unban-user", user],
	["set-role", roleInput],
	["revoke-user-sessions", user],
]);
type Store = ReturnType<typeof createProjectEngineStore>;
type PasswordSafety = "allowed" | "breached" | "unavailable";
type ListedUser = {
	createdAt: string;
	updatedAt: string;
	banExpires: string | null;
	[field: string]: unknown;
};

async function listUsers(client: PoolClient, input: z.infer<typeof listInput>) {
	const {
		limit,
		offset,
		searchField,
		searchOperator,
		searchValue,
		sortBy,
		sortDirection,
	} = input;
	const order = `"${sortBy}" ${sortDirection.toUpperCase()}`;
	const operator = searchOperator === "eq" ? "=" : "LIKE";
	const pattern = searchValue
		? `${searchOperator === "contains" ? "%" : ""}${searchValue}${searchOperator === "eq" ? "" : "%"}`
		: null;
	const {
		rows: [result],
	} = await client.query<{ users: ListedUser[]; total: number }>(
		`WITH filtered AS (
		 SELECT ${publicFields} FROM "user" WHERE $1::text IS NULL OR "${searchField}" ${operator} $1
		 )
		 SELECT (SELECT count(*)::integer FROM filtered) AS total,
		 COALESCE((SELECT json_agg(entries ORDER BY ${order})
		  FROM (SELECT * FROM filtered ORDER BY ${order} LIMIT $2 OFFSET $3) entries
		 ), '[]'::json) AS users`,
		[pattern, limit, offset],
	);
	return accountLinkJson({
		total: result!.total,
		limit,
		offset,
		users: result!.users.map((entry) => ({
			...entry,
			createdAt: new Date(entry.createdAt).toISOString(),
			updatedAt: new Date(entry.updatedAt).toISOString(),
			banExpires: entry.banExpires
				? new Date(entry.banExpires).toISOString()
				: null,
		})),
	});
}

async function event(
	client: PoolClient,
	path: string,
	actorId: string,
	targetId: string,
	type: string,
) {
	await client.query(
		`INSERT INTO "allauthEvent" (id,type,outcome,"actorId","userId","targetId","createdAt",metadata)
		 VALUES ($1,$2,'success',$3,$4,$4,statement_timestamp(),jsonb_build_object('path',$5::text,'signal','platform-project-management'))`,
		[randomUUID(), type, actorId, targetId, path],
	);
}

const forbidden = () =>
	accountLinkError(
		403,
		"FORBIDDEN",
		"A workspace owner or administrator is required.",
	);
const invalid = () =>
	accountLinkError(400, "INVALID_BODY", "The request contains invalid fields.");
const duplicate = () =>
	accountLinkError(
		400,
		"BAD_REQUEST",
		"A user with this email already exists in the selected project.",
	);

/** Manage users through the verified platform session in the selected project schema. */
export function createOwnedProjectAdminUsers(options: {
	store: Store;
	project: Pick<Project, "id" | "schemaName" | "slug" | "workspaceId">;
	origin: string;
	basePath: string;
	platformOrigin: string;
	policy: AuthPolicy;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	readBody(request: Request): Promise<unknown>;
	checkPasswordSafety?(password: string): Promise<PasswordSafety>;
	reservedEmail?(email: string): boolean;
	blockCreation(
		client: PoolClient,
		request: Request,
		email: string,
	): Promise<boolean>;
	revoke(
		client: PoolClient,
		request: Request,
		userId: string,
		path: string,
		actorId: string,
	): Promise<void>;
}) {
	const { store, project } = options;
	const direct = `/api/projects/${project.slug}/auth`;

	async function create(
		request: Request,
		principal: ControlPrincipal,
		path: string,
		input: z.infer<typeof createInput>,
	) {
		const { email, name, password, role } = input;
		let hashed: string | undefined;
		if (password !== undefined) {
			const error = passwordPolicyError(
				password,
				options.policy.passwordPolicy,
			);
			if (error) return accountLinkError(400, "BAD_REQUEST", error);
			// Do not perform password checks for an untrusted workspace identity.
			const allowed = await store.transaction((client) =>
				lockOwnedProjectWorkspaceAdministrator(client, project, principal),
			);
			if (!allowed) return forbidden();
			const safety = await options
				.checkPasswordSafety?.(password)
				.catch(() => "unavailable");
			if (safety === "breached")
				return accountLinkError(
					400,
					"PASSWORD_COMPROMISED",
					"The password you entered has been compromised. Please choose a different password.",
				);
			if (safety !== "allowed")
				return accountLinkError(
					503,
					"SERVICE_UNAVAILABLE",
					"Password safety is temporarily unavailable.",
				);
			hashed = await clerkCompatiblePasswords.hash(password);
		}

		return store.transaction(async (client) => {
			if (
				!(await lockOwnedProjectWorkspaceAdministrator(
					client,
					project,
					principal,
				))
			)
				return forbidden();
			if (options.reservedEmail?.(email))
				return accountLinkError(
					reservedProjectEmailError.status,
					reservedProjectEmailError.code,
					reservedProjectEmailError.message,
				);
			if (await options.blockCreation(client, request, email))
				return accountLinkError(
					429,
					"ALLAUTH_SECURITY_BLOCKED",
					"This authentication request is temporarily unavailable. Try again later.",
				);
			const id = randomUUID();
			const {
				rows: [created],
			} = await client.query(
				`INSERT INTO "user" (id,email,name,role,"emailVerified",banned,"twoFactorEnabled","isAnonymous","directoryManaged","directoryDisabled")
				 VALUES ($1,$2,$3,$4,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE)
				 ON CONFLICT (email) DO NOTHING RETURNING ${publicFields}`,
				[id, email, name, role],
			);
			if (!created) return duplicate();
			if (hashed)
				await client.query(
					`INSERT INTO "account" (id,"userId","accountId","providerId",password,"updatedAt")
					 VALUES ($1,$2,$2,'credential',$3,statement_timestamp())`,
					[randomUUID(), id, hashed],
				);
			await event(client, path, principal.user.id, id, "user.created");
			return accountLinkJson({ user: created });
		});
	}

	return async (request: Request, path: string): Promise<Response | null> => {
		if (!path.startsWith(routePrefix)) return null;
		const operation = path.slice(routePrefix.length);
		const list = operation === "list-users";
		const createUser = operation === "create-user";
		const input = mutationInputs.get(operation);
		if (
			(!list && !createUser && !input) ||
			request.method !== (list ? "GET" : "POST")
		)
			return null;
		const url = new URL(request.url);
		const caller = request.headers.get("origin");
		if (
			options.basePath !== direct ||
			options.origin !== options.platformOrigin ||
			url.origin !== options.platformOrigin ||
			url.pathname !== direct + path ||
			request.headers.has("authorization") ||
			request.headers.get("sec-fetch-site") === "cross-site" ||
			(list
				? caller !== null && caller !== options.platformOrigin
				: caller !== options.platformOrigin)
		)
			return forbidden();
		const principal = await options.readWorkspacePrincipal(request.headers);
		if (
			!principal ||
			principal.session.userId !== principal.user.id ||
			principal.session.impersonatedBy ||
			!principal.user.emailVerified ||
			principal.user.banned
		)
			return forbidden();
		if (list) {
			const parsed = listInput.safeParse(Object.fromEntries(url.searchParams));
			if (!parsed.success) return invalid();
			return store.transaction(async (client) =>
				(await lockOwnedProjectWorkspaceAdministrator(
					client,
					project,
					principal,
				))
					? listUsers(client, parsed.data)
					: forbidden(),
			);
		}

		const body = await options.readBody(request);
		if (createUser) {
			const parsed = createInput.safeParse(body);
			return parsed.success
				? create(request, principal, path, parsed.data)
				: invalid();
		}
		const parsed = input!.safeParse(body);
		if (!parsed.success) return invalid();
		const id = parsed.data.userId;
		return store.transaction(async (client) => {
			if (
				!(await lockOwnedProjectWorkspaceAdministrator(
					client,
					project,
					principal,
				))
			)
				return forbidden();
			if (!(await store.lockUser(client, id)))
				return accountLinkError(
					404,
					"NOT_FOUND",
					"This user does not exist in the selected project.",
				);
			const actor = principal.user.id;
			if (operation === "revoke-user-sessions") {
				await options.revoke(client, request, id, path, actor);
				await event(client, path, actor, id, "session.revoked-all");
				return accountLinkJson({ success: true });
			}
			if (operation === "set-role") {
				const { role } = parsed.data as z.infer<typeof roleInput>;
				const {
					rows: [changed],
				} = await client.query(
					`UPDATE "user" SET role=$2,"updatedAt"=statement_timestamp() WHERE id=$1 RETURNING ${publicFields}`,
					[id, role],
				);
				await options.revoke(client, request, id, path, actor);
				await event(client, path, actor, id, "user.role-changed");
				return accountLinkJson({ user: changed });
			}
			const banned = operation === "ban-user";
			const { banReason, banExpiresIn } = parsed.data as z.infer<
				typeof banInput
			>;
			const {
				rows: [changed],
			} = await client.query(
				`UPDATE "user" SET banned=$2,"banReason"=$3,
				 "banExpires"=statement_timestamp()+$4::integer*interval '1 second',"updatedAt"=statement_timestamp()
				 WHERE id=$1 RETURNING ${publicFields}`,
				[
					id,
					banned,
					banned ? banReason || "Administrator restriction" : null,
					banExpiresIn ?? null,
				],
			);
			if (banned) await options.revoke(client, request, id, path, actor);
			await event(
				client,
				path,
				actor,
				id,
				banned ? "user.banned" : "user.unbanned",
			);
			return accountLinkJson({ user: changed });
		});
	};
}
