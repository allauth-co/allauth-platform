import { randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { getAddress, verifyMessage } from "viem";
import { parseSiweMessage, validateSiweMessage } from "viem/siwe";
import * as z from "zod";
import { walletMessageOriginMatches } from "../features/helpers";
import {
	accountLinkError,
	accountLinkJson,
} from "./owned-project-account-links";
import type {
	createProjectEngineStore,
	ProjectUser,
} from "./owned-project-engine-store";

const nonceInput = z.strictObject({});
const verifyInput = z.strictObject({
	message: z.string().min(1).max(16384),
	signature: z.string().min(1).max(1024),
	email: z
		.email()
		.max(320)
		.transform((email) => email.toLowerCase()),
});
const noncePattern = /^[A-Za-z0-9]{8,250}$/;
const addressPattern = /^0x[0-9a-fA-F]{40}$/;
type Store = ReturnType<typeof createProjectEngineStore>;
type Wallet = { address: `0x${string}`; chainId: number };

const mismatch = () =>
	accountLinkError(
		401,
		"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		"Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
	);
const invalidNonce = () =>
	accountLinkError(
		401,
		"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
		"Unauthorized: Invalid or expired nonce",
	);
const invalidSignature = () =>
	accountLinkError(
		401,
		"UNAUTHORIZED_INVALID_SIGNATURE",
		"Unauthorized: Invalid signature",
	);

/** Preserve the existing wallet and one-time challenge records in the selected project. */
export function createOwnedProjectWallet(options: {
	store: Store;
	schemaName: string;
	signingOrigin: string;
	signUpEnabled: boolean;
	readBody(request: Request): Promise<unknown>;
	admit(
		client: PoolClient,
		request: Request,
		email?: string,
	): Promise<Response | null>;
	complete(
		client: PoolClient,
		request: Request,
		user: ProjectUser,
		wallet: Wallet,
	): Promise<Response>;
}) {
	const { store } = options;
	const origin = new URL(options.signingOrigin);

	async function bind(client: PoolClient, wallet: Wallet, email: string) {
		const { address, chainId } = wallet;
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`${options.schemaName}\nwallet\n${address.toLowerCase()}`],
		);
		const owners = await client.query<{ userId: string }>(
			`SELECT DISTINCT "userId" FROM "walletAddress" WHERE lower(address)=lower($1) LIMIT 2`,
			[address],
		);
		if (owners.rows.length > 1) return mismatch();
		const owner = owners.rows[0]?.userId;
		let userId = owner;
		if (!userId) {
			if (!options.signUpEnabled)
				return accountLinkError(
					403,
					"FORBIDDEN",
					"New account registration is disabled for this application.",
				);
			const id = randomUUID();
			const placeholder = `${address.toLowerCase()}@siwe.placeholder.invalid`;
			for (const candidate of new Set([email, placeholder])) {
				const result = await client.query(
					`INSERT INTO "user" (id,name,email,image,role,"emailVerified","isAnonymous")
					 VALUES ($1,$2,$3,'','user',FALSE,FALSE)
					 ON CONFLICT (email) DO NOTHING RETURNING id`,
					[id, address, candidate],
				);
				if (result.rowCount === 1) {
					userId = id;
					break;
				}
			}
		}
		const user = userId ? await store.lockUser(client, userId) : null;
		if (
			!user ||
			user.banned ||
			user.directoryDisabled ||
			user.directoryManaged ||
			user.isAnonymous
		)
			return mismatch();
		const recorded = await client.query(
			`SELECT 1 FROM "walletAddress" WHERE lower(address)=lower($1) AND "chainId"=$2 AND "userId"=$3 LIMIT 1`,
			[address, chainId, user.id],
		);
		if (!recorded.rowCount) {
			const subject = `${address}:${chainId}`;
			const conflicts = await client.query(
				`SELECT 1 FROM "account" WHERE "providerId"='siwe' AND lower("accountId")=lower($1) LIMIT 1`,
				[subject],
			);
			if (conflicts.rowCount) return mismatch();
			await client.query(
				`INSERT INTO "walletAddress" (id,"userId",address,"chainId","isPrimary","createdAt")
				 VALUES ($1,$2,$3,$4,$5,statement_timestamp())`,
				[randomUUID(), user.id, address, chainId, !owner],
			);
			await client.query(
				`INSERT INTO "account" (id,"userId","providerId","accountId","updatedAt")
				 VALUES ($1,$2,'siwe',$3,statement_timestamp())`,
				[randomUUID(), user.id, subject],
			);
		}
		return user;
	}

	async function issue(request: Request) {
		if (
			request.body &&
			!nonceInput.safeParse(await options.readBody(request)).success
		)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"Invalid wallet sign-in request.",
			);
		return store.transaction(async (client) => {
			const blocked = await options.admit(client, request);
			if (blocked) return blocked;
			const nonce = randomBytes(16).toString("hex");
			await client.query(
				`INSERT INTO "verification" (id,identifier,value,"expiresAt")
				 VALUES ($1,$2,$3,statement_timestamp()+interval '15 minutes')`,
				[randomUUID(), `siwe:${nonce}`, nonce],
			);
			return accountLinkJson({ nonce });
		});
	}

	async function verify(request: Request) {
		const input = verifyInput.safeParse(await options.readBody(request));
		if (!input.success)
			return accountLinkError(
				400,
				"INVALID_BODY",
				"Invalid wallet sign-in request.",
			);
		const { message, signature, email } = input.data;
		const parsed = parseSiweMessage(message);
		const { nonce, domain, scheme, uri, chainId, address: rawAddress } = parsed;
		if (!nonce || !noncePattern.test(nonce)) return mismatch();
		const refusal = await store.transaction(async (client) => {
			const blocked = await options.admit(client, request, email);
			if (blocked) return blocked;
			const consumed = await client.query(
				`DELETE FROM "verification" WHERE identifier=$1 AND value=$2
				 AND "expiresAt">statement_timestamp() RETURNING id`,
				[`siwe:${nonce}`, nonce],
			);
			return consumed.rowCount === 1 ? null : invalidNonce();
		});
		if (refusal) return refusal;
		if (
			!rawAddress ||
			!addressPattern.test(rawAddress) ||
			typeof chainId !== "number" ||
			!Number.isInteger(chainId) ||
			chainId < 1 ||
			chainId > 2147483647 ||
			domain?.toLowerCase() !== origin.host ||
			(scheme !== undefined && `${scheme.toLowerCase()}:` !== origin.protocol)
		)
			return mismatch();
		const now = new Date();
		if (parsed.expirationTime && now >= parsed.expirationTime)
			return accountLinkError(
				401,
				"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
				"Unauthorized: SIWE message has expired",
			);
		if (parsed.notBefore && now < parsed.notBefore)
			return accountLinkError(
				401,
				"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
				"Unauthorized: SIWE message is not yet valid",
			);
		if (
			!walletMessageOriginMatches(uri, origin.origin) ||
			!/^0x[0-9a-fA-F]+$/.test(signature)
		)
			return invalidSignature();
		let address: Wallet["address"];
		try {
			address = getAddress(rawAddress);
			if (
				!validateSiweMessage({ message: parsed, address, nonce, time: now }) ||
				!(await verifyMessage({
					address,
					message,
					signature: signature as `0x${string}`,
				}))
			)
				return invalidSignature();
		} catch {
			return invalidSignature();
		}
		const wallet = { address, chainId };
		try {
			return await store.transaction(async (client) => {
				const user = await bind(client, wallet, email);
				if (user instanceof Response) throw user;
				const result = await options.complete(client, request, user, wallet);
				if (result.status >= 400) throw result;
				return result;
			});
		} catch (error) {
			return error instanceof Response
				? error
				: accountLinkError(
						503,
						"SERVICE_UNAVAILABLE",
						"Wallet sign-in is temporarily unavailable.",
					);
		}
	}

	return (path: string, request: Request) =>
		path === "/siwe/verify" ? verify(request) : issue(request);
}
