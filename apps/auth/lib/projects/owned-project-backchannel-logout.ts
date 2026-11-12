import { randomBytes } from "node:crypto";
import { SignJWT } from "jose";
import type { Pool } from "pg";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import {
	fetchPublicProjectHttps,
	publicProjectHttpsURL,
} from "./owned-project-https";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";

const event = "http://schemas.openid.net/event/backchannel-logout";
const tokenLifetimeSeconds = 120;
type LogoutTransport = (
	url: URL,
	body: URLSearchParams,
	signal: AbortSignal,
) => Promise<number>;

const postToRelyingParty: LogoutTransport = async (url, body, signal) => {
	const response = await fetchPublicProjectHttps(
		new Request(url, {
			method: "POST",
			body,
			signal,
			headers: { Accept: "application/json" },
		}),
		{ timeoutMs: 5000, headersOnly: true },
	);
	return response.status;
};

export interface ProjectBackchannelTarget {
	clientId: string;
	sessionId: string;
	userId: string;
	url: string;
}

interface BackchannelOptions {
	database: Pool;
	schemaName: string;
	issuer: string;
	keys: LegacyMfaKeys;
	/** Pass an in-process transport in an isolated integration test. */
	post?: LogoutTransport;
	defer?(delivery: () => Promise<void>): void;
	observe?(result: { clientId: string; outcome: "delivered" | "failed" }): void;
}

export function createOwnedProjectBackchannelLogout(
	options: BackchannelOptions,
) {
	const { signingKey } = createOwnedProjectIssuerKeys(options);

	const post = options.post ?? postToRelyingParty;
	async function deliver(targets: readonly ProjectBackchannelTarget[]) {
		let signing: ReturnType<typeof signingKey> | undefined;
		await Promise.allSettled(
			targets.map(async (target) => {
				let outcome: "delivered" | "failed" = "failed";
				try {
					const url = publicProjectHttpsURL(target.url, true);
					const { id, alg, key } = await (signing ??= signingKey());
					const iat = Math.floor(Date.now() / 1000);
					const token = await new SignJWT({
						sid: target.sessionId,
						events: { [event]: {} },
					})
						.setProtectedHeader({ alg, kid: id, typ: "logout+jwt" })
						.setIssuer(options.issuer)
						.setAudience(target.clientId)
						.setSubject(target.userId)
						.setJti(randomBytes(16).toString("hex"))
						.setIssuedAt(iat)
						.setExpirationTime(iat + tokenLifetimeSeconds)
						.sign(key);
					const status = await post(
						url,
						new URLSearchParams({ logout_token: token }),
						AbortSignal.timeout(5000),
					);
					if (status === 200 || status === 204) outcome = "delivered";
				} finally {
					options.observe?.({ clientId: target.clientId, outcome });
				}
			}),
		);
	}

	return async (targets: readonly ProjectBackchannelTarget[]) => {
		if (!targets.length) return;
		if (!options.defer) {
			await deliver(targets);
			return;
		}
		let pending: Promise<void> | undefined;
		const run = () => (pending ??= deliver(targets));
		try {
			options.defer(run);
		} catch {
			await run();
		}
	};
}
