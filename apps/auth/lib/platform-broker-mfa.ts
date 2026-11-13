import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type {
	BrokerTwoFactorAttempt,
	BrokerTwoFactorClient,
	BrokerTwoFactorIdentity,
	BrokerTwoFactorStore,
} from "./broker-two-factor-protocol";
import {
	completeStoredBrokerTwoFactor,
	issueBrokerTwoFactor,
	verifyStoredBrokerTwoFactor,
} from "./broker-two-factor-protocol";
import { ConsoleRequestError } from "./console/request-error";
import type { LegacyMfaKeys } from "./projects/legacy-mfa-record";
import {
	openLegacyMfaRecord,
	sealLegacyMfaRecord,
} from "./projects/legacy-mfa-record";
import { readLegacySessionCookie } from "./projects/legacy-session-cookie";
import { readSignedProjectIssuerQuery } from "./projects/owned-project-issuer-authorization-query";

export function createPlatformBrokerMfa(options: {
	database: Pool;
	issuer: string;
	signingSecret: string;
	keys: LegacyMfaKeys;
	dispatch: (request: Request) => Promise<Response | undefined>;
}) {
	const { database, issuer, signingSecret, keys } = options;
	const prefix = `${issuer.startsWith("https:") ? "__Secure-" : ""}better-auth.`;
	const cookieName = prefix + "two_factor";
	const store: BrokerTwoFactorStore = {
		async read(identifier) {
			const { rows } = await database.query<{ value: string; expiresAt: Date }>(
				'SELECT value, "expiresAt" FROM public."verification" WHERE identifier=$1 ORDER BY "createdAt" DESC, id DESC LIMIT 1',
				[identifier],
			);
			return rows[0] ?? null;
		},
		async consume(identifier) {
			const result = await database.query(
				'DELETE FROM public."verification" WHERE identifier=$1 AND "expiresAt">clock_timestamp() RETURNING id',
				[identifier],
			);
			return result.rowCount === 1;
		},
		async write({ identifier, value, expiresAt }) {
			await database.query(
				'INSERT INTO public."verification" (id, identifier, value, "expiresAt") VALUES ($1,$2,$3,$4)',
				[randomUUID(), identifier, value, expiresAt],
			);
		},
		async client(clientId) {
			const { rows } = await database.query<BrokerTwoFactorClient>(
				'SELECT disabled, "redirectUris", metadata FROM public."oauthClient" WHERE "clientId"=$1',
				[clientId],
			);
			return rows[0] ?? null;
		},
		async open(value) {
			return openLegacyMfaRecord(value, keys);
		},
		async seal(value) {
			return sealLegacyMfaRecord(value, keys);
		},
	};

	return {
		async browserHandoff(headers: Headers, serialized: string) {
			const signed = readSignedProjectIssuerQuery(serialized, signingSecret);
			if (
				!signed ||
				signed.consentSessionId ||
				signed.params.get("allauth_mfa") !== "app-v1"
			)
				return { url: null };
			const identifier = readLegacySessionCookie(
				headers,
				cookieName,
				signingSecret,
			);
			if (!identifier) return { url: null };
			const pending = await store.read(identifier);
			if (!pending || pending.expiresAt.getTime() <= Date.now())
				return { url: null };
			const pairs = headers
				.get("cookie")
				?.split(";")
				.map((value) => value.trim())
				.filter((value) => value.startsWith(cookieName + "="));
			if (pairs?.length !== 1) return { url: null };
			const url = await issueBrokerTwoFactor(
				new URLSearchParams(serialized),
				true,
				store.client,
				cookieName,
				prefix + "dont_remember",
				headers,
				new Headers({ "set-cookie": pairs[0]! }),
				async (key, data, expiresAt) =>
					store.write({
						identifier: key,
						value: await store.seal(data),
						expiresAt,
					}),
			);
			return { url: url ?? null };
		},
		verify(
			identity: BrokerTwoFactorIdentity,
			input: BrokerTwoFactorAttempt,
			headers: Headers,
		) {
			return verifyStoredBrokerTwoFactor(
				store,
				issuer,
				identity,
				input,
				headers,
				async (request) =>
					(await options.dispatch(request)) ??
					new Response(null, { status: 401 }),
				async (clientId, serialized) => {
					const signed = readSignedProjectIssuerQuery(
						serialized,
						signingSecret,
					);
					if (!signed || signed.consentSessionId)
						throw new ConsoleRequestError(
							401,
							"This sign-in has expired. Start again.",
						);
					if (signed.params.get("client_id") !== clientId)
						throw new ConsoleRequestError(403);
					const client = await store.client(clientId);
					if (!client || client.disabled)
						throw new ConsoleRequestError(
							404,
							"The OAuth client is unavailable.",
						);
				},
			);
		},
		complete(request: Request) {
			return completeStoredBrokerTwoFactor(store, request, options.dispatch);
		},
	};
}
