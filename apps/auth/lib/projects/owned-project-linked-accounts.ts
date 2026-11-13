import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ControlEventInput } from "../control/types";
import type { ProjectUser } from "./owned-project-engine-store";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { checkedProjectSchema } from "./validation";

const supportedProvider = z.enum(["allauth", "google", "microsoft", "apple"]);
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
	| "info"
	| "provider-token"
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
	disabledRemainder: [
		400,
		"FAILED_TO_UNLINK_LAST_ACCOUNT",
		"Keep a sign-in method that is enabled for this application.",
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

export interface LinkedAccountGrant {
	id: string;
	providerId: string;
	accountId: string;
	scope: string | null;
	accessToken: string | null;
	accessTokenExpiresAt: Date | null;
	refreshToken: string | null;
	refreshTokenExpiresAt: Date | null;
	idToken: string | null;
}

type RotatedAccountGrant = Pick<
	LinkedAccountGrant,
	| "accessToken"
	| "accessTokenExpiresAt"
	| "refreshToken"
	| "refreshTokenExpiresAt"
	| "idToken"
>;

interface LinkedAccountReadOptions {
	operation?: "info" | "provider-token";
	refresh?(
		account: LinkedAccountGrant,
	): Promise<RotatedAccountGrant | undefined>;
	forceRefresh?: boolean;
}

export function linkedAccountScopes(scope: string | null) {
	return (
		scope
			?.split(",")
			.map((value) => value.trim())
			.filter(Boolean) ?? []
	);
}

export function linkedAccessTokenNearExpiry(account: LinkedAccountGrant) {
	return Boolean(
		account.refreshToken &&
			account.accessTokenExpiresAt &&
			new Date(account.accessTokenExpiresAt).getTime() - Date.now() < 5_000,
	);
}

interface LinkedAccountAvailability {
	socialProviders: string[];
	passwordSignIn: boolean;
	passkeySignIn: boolean;
	otherSignIn?(client: PoolClient, user: ProjectUser): Promise<boolean>;
}

/** Scoped linked-account operations using the current signed project's live database session. */
export function createOwnedProjectLinkedAccounts(
	database: Pool,
	schemaName: string,
	authorize?: AuthorizeLinkedAccounts,
	availability?: LinkedAccountAvailability,
) {
	const schema =
		schemaName === "public" ? "public" : checkedProjectSchema(schemaName);
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
		if (
			operation !== "list" &&
			operation !== "info" &&
			operation !== "provider-token" &&
			(user.directoryManaged || user.isAnonymous)
		)
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
					scopes: linkedAccountScopes(scope),
				})),
			};
		});
	}

	async function info(
		request: Request,
		token: string | null,
		accountId: string | null,
		{
			operation = "info",
			refresh,
			forceRefresh,
		}: LinkedAccountReadOptions = {},
	) {
		return store.transaction(async (client) => {
			const authority = await lockAuthority(client, request, token, operation);
			if (authority.status === "rejected") return authority;
			const read = await client.query<LinkedAccountGrant>(
				`SELECT id,"providerId","accountId",scope,"accessToken","accessTokenExpiresAt","refreshToken","refreshTokenExpiresAt","idToken"
				 FROM "${schema}"."account" WHERE "userId"=$1 AND id=$2${refresh ? " FOR UPDATE" : ""}`,
				[authority.user.id, accountId],
			);
			let account = read.rows[0];
			if (!account) return rejected("notFound");
			if (refresh && (forceRefresh || linkedAccessTokenNearExpiry(account))) {
				const rotated = await refresh(account);
				if (!rotated) return { status: "found" as const, account };
				const persisted = await client.query(
					`UPDATE "${schema}"."account" SET "accessToken"=$3,"accessTokenExpiresAt"=$4,"refreshToken"=$5,"refreshTokenExpiresAt"=$6,"idToken"=$7,"updatedAt"=statement_timestamp()
					 WHERE "userId"=$1 AND id=$2`,
					[
						authority.user.id,
						accountId,
						rotated.accessToken,
						rotated.accessTokenExpiresAt,
						rotated.refreshToken,
						rotated.refreshTokenExpiresAt,
						rotated.idToken,
					],
				);
				if (persisted.rowCount !== 1) return rejected("notFound");
				account = { ...account, ...rotated };
			}
			return { status: "found" as const, account };
		});
	}

	async function unlink(
		request: Request,
		token: string | null,
		input: OwnedProjectOAuthUnlink,
		auditContext?: Pick<ControlEventInput, "ipAddress" | "userAgent">,
	) {
		const parsed = ownedProjectOAuthUnlinkInput.safeParse(input);
		if (!parsed.success) return rejected("invalid");
		const { accountId, providerId } = parsed.data;
		return store.transaction(async (client) => {
			const authority = await lockAuthority(client, request, token, "unlink");
			if (authority.status === "rejected") return authority;
			const userId = authority.user.id;
			const path = "/unlink-account";
			function recordUnlink(errorCode?: string) {
				return store.recordEvent(client, {
					...auditContext,
					type: "account.unlinked",
					outcome: errorCode ? "failure" : "success",
					actorId: userId,
					userId,
					metadata: { path, ...(errorCode && { errorCode }) },
				});
			}
			async function rejectUnlink(reason: keyof typeof failures) {
				const result = rejected(reason);
				await recordUnlink(result.code);
				return result;
			}
			const matches = await client.query<{ id: string; providerId: string }>(
				`SELECT id, "providerId" FROM "${schema}"."account" WHERE "userId" = $1
				AND (
					($2::text IS NULL AND id = $3) OR
					("providerId" = $2 AND ($3::text IS NULL OR id = $3 OR "accountId" = $3))
				) ORDER BY id LIMIT 2 FOR UPDATE`,
				[userId, providerId ?? null, accountId ?? null],
			);
			if (matches.rows.length > 1) return rejectUnlink("ambiguous");
			const selected = matches.rows[0];
			if (!selected) return rejectUnlink("notFound");
			// The user lock serializes link and unlink so concurrent removals cannot delete every account.
			const another = await client.query(
				`SELECT 1 FROM "${schema}"."account" WHERE "userId" = $1 AND id <> $2 ORDER BY id LIMIT 1 FOR SHARE`,
				[userId, selected.id],
			);
			if (another.rowCount !== 1) return rejectUnlink("last");
			// Preserve the native last-row rule and avoid leaving only disabled sign-in methods.
			const usableProviders = availability && [
				...availability.socialProviders,
				...(availability.passwordSignIn ? ["credential"] : []),
			];
			if (usableProviders?.includes(selected.providerId)) {
				const supported = await client.query(
					`SELECT 1 FROM "${schema}"."account" WHERE "userId"=$1 AND id<>$2 AND "providerId"=ANY($3::text[])
					 AND ("providerId"<>'credential' OR password IS NOT NULL) LIMIT 1 FOR SHARE`,
					[userId, selected.id, usableProviders],
				);
				const passkey =
					supported.rowCount !== 1 &&
					availability?.passkeySignIn &&
					(await client.query(
						`SELECT 1 FROM "${schema}"."passkey" WHERE "userId"=$1 LIMIT 1`,
						[userId],
					));
				if (
					supported.rowCount !== 1 &&
					(!passkey || passkey.rowCount !== 1) &&
					!(await availability?.otherSignIn?.(client, authority.user))
				)
					return rejectUnlink("disabledRemainder");
			}
			const removed = await client.query(
				`DELETE FROM "${schema}"."account" WHERE "userId" = $1 AND id = $2`,
				[userId, selected.id],
			);
			if (removed.rowCount !== 1) return rejectUnlink("notFound");
			await store.recordEvent(client, {
				type: "account.deleted",
				outcome: "success",
				actorId: userId,
				userId,
				targetId: selected.id,
				metadata: { path, provider: selected.providerId },
			});
			await recordUnlink();
			return { status: "unlinked" as const };
		});
	}

	return { lockAuthority, list, info, unlink, record: store.record };
}
