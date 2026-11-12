import { randomInt, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import * as z from "zod";
import { defaultPasswordPolicy } from "../auth-policy/password";
import { clerkCompatiblePasswords } from "../clerk-password";
import type {
	ProjectAccountAuthority,
	ProjectAccountLinkOptions,
} from "./owned-project-account-links";
import {
	accountLinkError,
	accountLinkHeaders,
	accountLinkJson,
	accountLinkRedirect,
	createProjectAccountLinks,
} from "./owned-project-account-links";
import type { ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
const proofToken = /^[a-z0-9]{32}$/;
const startInput = z.object({
	callbackURL: z.string().max(2048).optional(),
	password: z.string().optional(),
	token: z.string().max(128).optional(),
});
const deleted = { success: true, message: "User deleted" };
const leasePrefix = "allauth-account-deletion:";

type DeletePath = "/delete-user" | "/delete-user/callback";
export interface AccountDeletionFence {
	/** Check the rows used by external cleanup after locking the user for erasure. */
	verify(client: PoolClient): Promise<boolean>;
}

/** Serialize self-service and administrator erasure while external cleanup runs. */
export async function claimProjectUserDeletion(
	client: PoolClient,
	userId: string,
	lease: string,
) {
	const key = `${leasePrefix}${userId}`;
	const acquired = await client.query(
		`INSERT INTO "verification" AS v (id,identifier,value,"expiresAt") VALUES ($1,$1,$2,statement_timestamp() + interval '5 minutes')
		 ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value,"expiresAt"=EXCLUDED."expiresAt","updatedAt"=statement_timestamp()
		 WHERE v."expiresAt" <= clock_timestamp()`,
		[key, lease],
	);
	return acquired.rowCount === 1 ? key : null;
}

export async function lockProjectUserDeletion(
	client: PoolClient,
	key: string,
	lease: string,
) {
	const reserved = await client.query(
		`SELECT id FROM "verification" WHERE id=$1 AND value=$2 AND "expiresAt" > clock_timestamp() FOR UPDATE`,
		[key, lease],
	);
	return reserved.rowCount === 1;
}

export async function releaseProjectUserDeletion(
	client: PoolClient,
	key: string,
	lease: string,
) {
	await client.query('DELETE FROM "verification" WHERE id=$1 AND value=$2', [
		key,
		lease,
	]);
}

/** The caller holds the user and deletion locks and has revoked live sessions. */
export async function eraseLockedProjectUser(
	client: PoolClient,
	userId: string,
	leaseKey: string,
) {
	const accounts = await client.query<{ id: string; providerId: string }>(
		'DELETE FROM "account" WHERE "userId"=$1 RETURNING id,"providerId"',
		[userId],
	);
	await client.query(
		`DELETE FROM "apikey" WHERE "referenceId"=$1 AND "configId"='default'`,
		[userId],
	);
	await client.query(
		`DELETE FROM "verification" WHERE id=$2 OR (value=$1 AND (
		 starts_with(identifier, 'delete-account-') OR starts_with(identifier, 'reset-password:')
		 OR starts_with(identifier, 'trust-device-') OR starts_with(identifier, '2fa-') OR starts_with(identifier, 'allauth-change-email-used:')
		 )) OR id=$3`,
		[userId, leaseKey, `allauth-change-email-generation:${userId}`],
	);
	const removed = await client.query('DELETE FROM "user" WHERE id=$1', [
		userId,
	]);
	if (removed.rowCount !== 1)
		throw new Error("Account deletion lost its user lock.");
	return accounts.rows;
}

export interface OwnedProjectAccountDeletionOptions
	extends ProjectAccountLinkOptions {
	/** Resolve the realm's existing avatar erasure and provider grant hooks before SQL deletion. */
	beforeDelete(input: {
		request: Request;
		user: ProjectUser;
	}): Promise<void | Response | AccountDeletionFence>;
	/** Revoke this realm's live sessions/grants and return the browser cookie-clearing headers. */
	revokeSessions(
		client: PoolClient,
		request: Request,
		userId: string,
		path: DeletePath,
	): Promise<Headers>;
}

function allowed(user: ProjectUser | null): user is ProjectUser {
	return Boolean(
		user &&
			!user.banned &&
			!user.isAnonymous &&
			!user.directoryManaged &&
			!user.directoryDisabled,
	);
}

function invalid() {
	return accountLinkError(404, "INVALID_TOKEN", "Invalid token");
}

/** Confirmed account deletion using native links and the project's configured cleanup hooks. */
export function createOwnedProjectAccountDeletion(
	options: OwnedProjectAccountDeletionOptions,
) {
	const links = createProjectAccountLinks(options);
	const store = createProjectEngineStore(
		options.database,
		options.project.schemaName,
	);

	async function lockAuthority(client: PoolClient, request: Request) {
		const authority = await options.authority(client, request);
		if (!authority || authority.impersonatedBy || authority.eligible === false)
			return null;
		const user = await store.lockUser(client, authority.userId);
		if (
			!allowed(user) ||
			!(await store.lockSession(client, authority.token, user.id, false))
		)
			return null;
		return { authority, user };
	}

	async function passwordError(
		client: PoolClient,
		userId: string,
		password?: string,
	) {
		if (!password) return null;
		if (password.length > defaultPasswordPolicy.maxLength)
			return accountLinkError(400, "PASSWORD_TOO_LONG", "Password too long");
		const result = await client.query<{ password: string | null }>(
			`SELECT password FROM "account" WHERE "userId"=$1 AND "providerId"='credential' AND "accountId"=$1 ORDER BY id LIMIT 2 FOR UPDATE`,
			[userId],
		);
		const hash = result.rows.length === 1 ? result.rows[0]?.password : null;
		if (!hash)
			return accountLinkError(
				400,
				"CREDENTIAL_ACCOUNT_NOT_FOUND",
				"Credential account not found",
			);
		if (!(await clerkCompatiblePasswords.verify({ hash, password })))
			return accountLinkError(400, "INVALID_PASSWORD", "Invalid password");
		return null;
	}

	async function consume(
		request: Request,
		token: string,
		path: DeletePath,
		callback?: URL,
		password?: string,
	) {
		const lease = randomUUID();
		const claim = await store.transaction(async (client) => {
			const current = await lockAuthority(client, request);
			if (!current)
				return path === "/delete-user"
					? accountLinkError(401, "UNAUTHORIZED", "Unauthorized")
					: accountLinkError(
							404,
							"FAILED_TO_GET_USER_INFO",
							"Failed to get user info",
						);
			const incorrect = await passwordError(client, current.user.id, password);
			if (incorrect) return incorrect;
			if (!proofToken.test(token)) return invalid();
			const identifier = `delete-account-${token}`;
			const { rows } = await client.query<{
				id: string;
				value: string;
				live: boolean;
			}>(
				`SELECT id,value,"expiresAt" > clock_timestamp() AS live FROM "verification" WHERE identifier=$1 ORDER BY "createdAt" DESC,id DESC LIMIT 2 FOR UPDATE`,
				[identifier],
			);
			const proof = rows.length === 1 ? rows[0] : null;
			if (!proof?.live || proof.value !== current.user.id) return invalid();
			const key = await claimProjectUserDeletion(
				client,
				current.user.id,
				lease,
			);
			if (!key)
				return accountLinkError(
					409,
					"DELETION_PENDING",
					"Account deletion is already being processed.",
				);
			await client.query('DELETE FROM "verification" WHERE id=$1', [proof.id]);
			return { ...current, key };
		});
		if (claim instanceof Response) return claim;

		let finished = false;
		try {
			// Avatar cleanup takes its own realm-scoped user lock. External grant
			// revocation and asset erasure must complete before the account disappears.
			let cleanup: Response | AccountDeletionFence | void;
			try {
				cleanup = await options.beforeDelete({ request, user: claim.user });
			} catch {
				return accountLinkError(
					503,
					"ACCOUNT_DELETION_UNAVAILABLE",
					"Account deletion is temporarily unavailable.",
				);
			}
			if (cleanup instanceof Response)
				return new Response(cleanup.body, {
					status: cleanup.status,
					headers: accountLinkHeaders(new Headers(cleanup.headers)),
				});
			const fence = cleanup;
			const result = await store.transaction(async (client) => {
				const current = await lockAuthority(client, request);
				if (
					!current ||
					!sameAuthority(claim.authority, current.authority) ||
					current.user.email !== claim.user.email
				)
					return invalid();
				if (!(await lockProjectUserDeletion(client, claim.key, lease)))
					return invalid();
				if (fence && !(await fence.verify(client)))
					return accountLinkError(
						503,
						"ACCOUNT_DELETION_UNAVAILABLE",
						"The linked account changed during deletion. Retry account deletion.",
					);
				const userId = current.user.id;
				const headers = await options.revokeSessions(
					client,
					request,
					userId,
					path,
				);
				const accounts = await eraseLockedProjectUser(
					client,
					userId,
					claim.key,
				);
				for (const account of accounts)
					await store.record(
						client,
						"account.deleted",
						"success",
						path,
						userId,
						account.id,
					);
				await store.record(
					client,
					"user.deleted",
					"success",
					path,
					userId,
					userId,
				);
				return { headers };
			});
			if (result instanceof Response) return result;
			finished = true;
			return callback
				? accountLinkRedirect(callback, result.headers)
				: accountLinkJson(deleted, 200, result.headers);
		} finally {
			if (!finished)
				await store.transaction((client) =>
					releaseProjectUserDeletion(client, claim.key, lease),
				);
		}
	}

	async function start(request: Request, input: unknown) {
		if (!links.requestURL(request, "POST", "/delete-user"))
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		const parsed = startInput.safeParse(input);
		if (!parsed.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"Invalid account deletion request.",
			);
		const destination = links.callback(
			parsed.data.callbackURL,
			request.headers.get("origin") ?? undefined,
		);
		if (!destination)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication destination is not permitted.",
			);
		if (parsed.data.token)
			return consume(
				request,
				parsed.data.token,
				"/delete-user",
				undefined,
				parsed.data.password,
			);
		const issued = await store.transaction(async (client) => {
			const current = await lockAuthority(client, request);
			if (!current)
				return accountLinkError(401, "UNAUTHORIZED", "Unauthorized");
			const incorrect = await passwordError(
				client,
				current.user.id,
				parsed.data.password,
			);
			if (incorrect) return incorrect;
			const token = Array.from(
				{ length: 32 },
				() => alphabet[randomInt(alphabet.length)],
			).join("");
			await client.query(
				`INSERT INTO "verification"(id,identifier,value,"expiresAt") VALUES ($1,$2,$3,statement_timestamp() + interval '1 day')`,
				[randomUUID(), `delete-account-${token}`, current.user.id],
			);
			return {
				kind: "delete-account",
				user: {
					id: current.user.id,
					email: current.user.email,
					name: current.user.name,
				},
				url: links.mail("/delete-user/callback", token, destination),
			} as const;
		});
		if (issued instanceof Response) return issued;
		links.schedule(issued);
		return accountLinkJson({
			success: true,
			message: "Verification email sent",
		});
	}

	async function confirm(request: Request) {
		const url = links.requestURL(request, "GET", "/delete-user/callback");
		if (!url)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication request is not permitted.",
			);
		const tokens = url.searchParams.getAll("token");
		if (tokens.length !== 1 || !tokens[0]) return invalid();
		const callbacks = url.searchParams.getAll("callbackURL");
		const destination = callbacks[0] ? links.callback(callbacks[0]) : undefined;
		if (callbacks.length > 1 || destination === null)
			return accountLinkError(
				403,
				"FORBIDDEN",
				"This authentication destination is not permitted.",
			);
		return consume(request, tokens[0], "/delete-user/callback", destination);
	}

	return { start, confirm };
}

function sameAuthority(
	initial: ProjectAccountAuthority,
	current: ProjectAccountAuthority,
) {
	return (
		initial.userId === current.userId &&
		initial.sessionId === current.sessionId &&
		initial.token === current.token
	);
}
