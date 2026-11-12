import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { checkedProjectSchema } from "./validation";

const supportedProvider = z.enum(["allauth", "google"]);
const oneDay = 86_400_000;

export const ownedProjectOAuthUnlinkInput = z
	.strictObject({
		accountId: z.string().min(1).max(512).optional(),
		providerId: supportedProvider.optional(),
	})
	.refine((input) => Boolean(input.accountId || input.providerId));

export type OwnedProjectOAuthUnlink = z.infer<
	typeof ownedProjectOAuthUnlinkInput
>;
export type LinkedAccountOperation =
	| "list"
	| "link"
	| "link-callback"
	| "unlink";
export type AuthorizeLinkedAccounts = (
	client: PoolClient,
	input: {
		request: Request;
		user: ProjectUser;
		operation: LinkedAccountOperation;
	},
) => Promise<boolean>;

const failures = {
	unauthorized: [401, "UNAUTHORIZED", "Unauthorized"],
	forbidden: [
		403,
		"FORBIDDEN",
		"This authentication request is not permitted.",
	],
	stale: [403, "SESSION_NOT_FRESH", "Session is not fresh"],
	invalid: [400, "INVALID_BODY", "Select an account to unlink."],
	notFound: [400, "ACCOUNT_NOT_FOUND", "Account not found"],
	last: [
		400,
		"FAILED_TO_UNLINK_LAST_ACCOUNT",
		"You can't unlink your last account",
	],
	ambiguous: [
		409,
		"ACCOUNT_SELECTION_AMBIGUOUS",
		"Select the specific account to unlink.",
	],
} as const;

type Failure = {
	status: "rejected";
	httpStatus: number;
	code: string;
	message: string;
};

function rejected(key: keyof typeof failures): Failure {
	const [httpStatus, code, message] = failures[key];
	return { status: "rejected", httpStatus, code, message };
}

interface PublicAccount {
	id: string;
	userId: string;
	accountId: string;
	providerId: string;
	createdAt: Date;
	updatedAt: Date;
	scope: string | null;
}

/** Scoped linked-account operations using the current signed project's live database session. */
export function createOwnedProjectLinkedAccounts(
	database: Pool,
	schemaName: string,
	authorize?: AuthorizeLinkedAccounts,
) {
	const schema = checkedProjectSchema(schemaName);
	const store = createProjectEngineStore(database, schema);

	async function lockAuthority(
		client: PoolClient,
		request: Request,
		token: string | null,
		operation: LinkedAccountOperation,
	) {
		const current = token && (await store.session(token, 0, client));
		if (!token || !current) return rejected("unauthorized");
		const user = await store.lockUser(client, current.user.id);
		if (
			!user ||
			user.banned ||
			user.directoryDisabled ||
			!(await store.lockSession(client, token, user.id, false))
		)
			return rejected("unauthorized");
		if (operation !== "list" && (user.directoryManaged || user.isAnonymous))
			return rejected("forbidden");
		if (
			operation === "unlink" &&
			new Date(current.session.createdAt).getTime() <= Date.now() - oneDay
		)
			return rejected("stale");
		if (authorize && !(await authorize(client, { request, user, operation })))
			return rejected("forbidden");
		return { status: "authorized" as const, user, session: current.session };
	}

	async function list(request: Request, token: string | null) {
		return store.transaction(async (client) => {
			const authority = await lockAuthority(client, request, token, "list");
			if (authority.status === "rejected") return authority;
			const accounts = await client.query<PublicAccount>(
				`SELECT id, "userId", "accountId", "providerId", "createdAt", "updatedAt", scope
				FROM "${schema}"."account" WHERE "userId" = $1 ORDER BY "createdAt", id`,
				[authority.user.id],
			);
			return {
				status: "listed" as const,
				accounts: accounts.rows.map(({ scope, ...row }) => ({
					...row,
					scopes:
						scope
							?.split(",")
							.map((value) => value.trim())
							.filter(Boolean) ?? [],
				})),
			};
		});
	}

	async function unlink(
		request: Request,
		token: string | null,
		input: OwnedProjectOAuthUnlink,
	) {
		const parsed = ownedProjectOAuthUnlinkInput.safeParse(input);
		if (!parsed.success) return rejected("invalid");
		const { accountId, providerId } = parsed.data;
		return store.transaction(async (client) => {
			const authority = await lockAuthority(client, request, token, "unlink");
			if (authority.status === "rejected") return authority;
			const userId = authority.user.id;
			const matches = await client.query<{ id: string }>(
				`SELECT id FROM "${schema}"."account" WHERE "userId" = $1
				AND "providerId" IN ('allauth', 'google') AND (
					($2::text IS NULL AND id = $3) OR
					("providerId" = $2 AND ($3::text IS NULL OR id = $3 OR "accountId" = $3))
				) ORDER BY id LIMIT 2 FOR UPDATE`,
				[userId, providerId ?? null, accountId ?? null],
			);
			if (matches.rows.length > 1) return rejected("ambiguous");
			const selected = matches.rows[0];
			if (!selected) return rejected("notFound");
			// The user lock serializes link and unlink so concurrent removals cannot delete every account.
			const another = await client.query(
				`SELECT 1 FROM "${schema}"."account" WHERE "userId" = $1 AND id <> $2 ORDER BY id LIMIT 1 FOR SHARE`,
				[userId, selected.id],
			);
			if (another.rowCount !== 1) return rejected("last");
			const removed = await client.query(
				`DELETE FROM "${schema}"."account" WHERE "userId" = $1 AND id = $2`,
				[userId, selected.id],
			);
			if (removed.rowCount !== 1) return rejected("notFound");
			await store.record(
				client,
				"account.deleted",
				"success",
				"/unlink-account",
				userId,
				selected.id,
			);
			await store.record(
				client,
				"account.unlinked",
				"success",
				"/unlink-account",
				userId,
				selected.id,
			);
			return { status: "unlinked" as const };
		});
	}

	return { lockAuthority, list, unlink, record: store.record };
}
