import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { betterAuth } from "better-auth";
import { symmetricEncrypt } from "better-auth/crypto";
import type { Kysely } from "kysely";
import type { Pool } from "pg";
import { expect } from "vitest";
import { createAuthOptions } from "../auth";
import type { AuthPolicy } from "../auth-policy/policy";
import { defaultAuthPolicy } from "../auth-policy/policy";
import {
	newWebhookSigningSecret,
	webhookSignature,
} from "../control/webhook-contract";
import type { ControlWebhookEnvelope } from "../control/webhook-delivery";
import { deliverPendingWebhooks } from "../control/webhook-delivery";

type ScopedDatabase = Kysely<Record<string, Record<string, unknown>>>;
type Dispatch = (request: Request) => Promise<Response>;

export function enterpriseSavedDevicePolicy(
	mfaMode: AuthPolicy["mfaMode"],
): AuthPolicy {
	return {
		...defaultAuthPolicy,
		mfaMode,
		signUpEnabled: mfaMode === "optional",
	};
}

/** Compare the actual installed project plugins against the owned enterprise writer. */
export async function checkEnterpriseSavedDeviceWebhook(options: {
	database: Pool;
	scoped: ScopedDatabase;
	schema: string;
	origin: string;
	idpOrigin: string;
	cookiePrefix: string;
	secret: string;
	destination: string;
	policy: AuthPolicy;
	callbackPath: "/sso/callback/:providerId" | "/sso/saml2/sp/acs/:providerId";
	userId: string;
	browserUserId: string;
	owned: Dispatch;
	prepare(dispatch: Dispatch, ip: string, rejected?: boolean): Promise<Request>;
}) {
	const {
		database,
		scoped,
		schema,
		origin,
		idpOrigin,
		cookiePrefix,
		secret,
		destination,
		policy,
		callbackPath,
		userId,
		browserUserId,
		owned,
		prepare,
	} = options;
	const native = betterAuth({
		...createAuthOptions(
			{ db: scoped, type: "postgres", transaction: true },
			{
				ALLAUTH_AUTH_URL: origin,
				ALLAUTH_AUTH_SECRET: secret,
				AUTH_RUNTIME: "node",
				SCIM_CREDENTIAL_HASH_SECRET: "synthetic-scim-webhook-fixture-hash-key",
			},
			{
				name: "Enterprise webhook fixture",
				basePath: "/api/auth",
				cookiePrefix,
				primaryOrigin: origin,
				publicOrigin: origin,
				origins: [idpOrigin],
				broker: {
					clientId: "fixture-broker",
					clientSecret: "synthetic-broker-secret",
				},
				async authorizeAdmin() {
					return null;
				},
				management: { id: "enterprise-webhook-fixture" },
			},
			policy,
		),
		logger: { disabled: true },
	});
	const primaryName = `__Secure-${cookiePrefix}.session_token`;
	const trustName = `__Secure-${cookiePrefix}.trust_device`;
	const cookieValue = (response: Response, name: string) =>
		response.headers
			.getSetCookie()
			.find(
				(cookie) =>
					cookie.startsWith(`${name}=`) && !cookie.includes("Max-Age=0"),
			)
			?.split(";", 1)[0];
	const sign = (name: string, token: string) =>
		`${name}=${encodeURIComponent(`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`)}`;
	const browserSession = (cookie: string) =>
		native.api.getSession({
			headers: new Headers({ cookie }),
			query: { disableRefresh: true },
		});
	async function savedSession(ownerId: string) {
		const id = randomUUID();
		const token = randomUUID().replaceAll("-", "");
		await database.query(
			`INSERT INTO "${schema}"."session"(id,token,"userId","expiresAt","updatedAt") VALUES ($1,$2,$3,now()+interval '1 day',now())`,
			[id, token, ownerId],
		);
		const deviceName = `${primaryName}_multi-${token}`;
		return {
			id,
			token,
			deviceName,
			primary: sign(primaryName, token),
			device: sign(deviceName, token),
		};
	}

	async function trustEnrolledDevice(totpSecret: string) {
		const ip = "192.0.2.140";
		const request = await prepare(native.handler, ip);
		request.headers.set("x-real-ip", ip);
		const pending = await native.handler(request);
		expect(new URL(pending.headers.get("location")!).pathname).toBe(
			"/two-factor",
		);
		const challenge = cookieValue(
			pending,
			`__Secure-${cookiePrefix}.two_factor`,
		);
		expect(challenge).toBeTruthy();
		const { code } = await native.api.generateTOTP({
			body: { secret: totpSecret },
		});
		const verified = await native.handler(
			new Request(`${origin}/api/auth/two-factor/verify-totp`, {
				method: "POST",
				headers: {
					origin,
					"x-real-ip": ip,
					cookie: challenge!,
					"content-type": "application/json",
				},
				body: JSON.stringify({ code, trustDevice: true }),
			}),
		);
		expect(verified.status, await verified.clone().text()).toBe(200);
		const trusted = cookieValue(verified, trustName);
		expect(trusted).toBeTruthy();
		return trusted;
	}

	const factorIds: string[] = [];
	const enrolledUsers =
		policy.mfaMode === "required"
			? (
					await database.query<{
						id: string;
						twoFactorEnabled: boolean | null;
					}>(
						`SELECT id,"twoFactorEnabled" FROM "${schema}"."user" WHERE id=ANY($1::text[])`,
						[[userId, browserUserId]],
					)
				).rows
			: [];
	try {
		let trustedDevice: string | undefined;
		if (policy.mfaMode === "required") {
			expect(enrolledUsers).toHaveLength(2);
			const totpSecret = randomBytes(16).toString("hex");
			for (const owner of enrolledUsers) {
				const id = randomUUID();
				await database.query(
					`INSERT INTO "${schema}"."twoFactor"(id,secret,"backupCodes","userId",verified) VALUES ($1,$2,$3,$4,TRUE)`,
					[
						id,
						await symmetricEncrypt({ key: secret, data: totpSecret }),
						await symmetricEncrypt({ key: secret, data: "[]" }),
						owner.id,
					],
				);
				factorIds.push(id);
				await database.query(
					`UPDATE "${schema}"."user" SET "twoFactorEnabled"=TRUE WHERE id=$1`,
					[owner.id],
				);
			}
			trustedDevice = await trustEnrolledDevice(totpSecret);
		}

		let nextIP = 141;
		const scenarios =
			policy.mfaMode === "required"
				? ([
						"active",
						"absent",
						"expired-other",
						"expired-owner",
						"rejected",
						...(callbackPath === "/sso/saml2/sp/acs/:providerId"
							? (["malformed-ingress"] as const)
							: []),
					] as const)
				: (["active", "absent"] as const);
		for (const [writer, dispatch, start] of [
			["native", native.handler, owned],
			["owned", owned, native.handler],
		] as const) {
			for (const scenario of scenarios) {
				const malformed = scenario === "malformed-ingress";
				const rejected = scenario === "rejected" || malformed;
				const previous = await savedSession(userId);
				const unrelated = await savedSession(userId);
				const browser = await savedSession(browserUserId);
				expect((await browserSession(browser.primary))?.user.id).toBe(
					browserUserId,
				);
				const expired =
					scenario === "expired-owner"
						? { ...previous, userId }
						: scenario === "expired-other" || rejected
							? { ...browser, userId: browserUserId }
							: undefined;
				if (expired)
					await database.query(
						`UPDATE "${schema}"."session" SET "expiresAt"=now()-interval '1 minute' WHERE id=$1`,
						[expired.id],
					);
				const expiredRemoved = malformed ? undefined : expired;
				const clientId = expired && randomUUID();
				const grants = expired
					? ["access", "online", "offline"].map((kind) => ({
							id: randomUUID(),
							kind,
						}))
					: [];
				if (expired && clientId) {
					await database.query(
						`INSERT INTO "${schema}"."oauthClient"(id,"clientId","redirectUris") VALUES ($1,$1,'[]')`,
						[clientId],
					);
					for (const { id, kind } of grants) {
						const table =
							kind === "access" ? "oauthAccessToken" : "oauthRefreshToken";
						await database.query(
							`INSERT INTO "${schema}"."${table}"(id,token,"clientId","userId","sessionId","expiresAt","createdAt",scopes)
							 VALUES ($1,$1,$2,$3,$4,now()+interval '1 hour',now(),$5)`,
							[
								id,
								clientId,
								expired.userId,
								expired.id,
								JSON.stringify(
									kind === "offline"
										? ["openid", "offline_access"]
										: ["openid"],
								),
							],
						);
					}
				}
				const endpoint = randomUUID();
				const url = "https://enterprise-webhook.fixture.example/events";
				const signingKey = newWebhookSigningSecret();
				await database.query(
					`INSERT INTO "${schema}"."allauthWebhookEndpoint"(id,url,"eventTypes","encryptedSecret") VALUES ($1,$2,'["session.deleted"]',$3)`,
					[
						endpoint,
						url,
						await symmetricEncrypt({ key: secret, data: signingKey }),
					],
				);
				try {
					const ip = `192.0.2.${nextIP++}`;
					const pending = await prepare(start, ip, scenario === "rejected");
					const request = malformed
						? new Request(pending.url, {
								method: "POST",
								headers: pending.headers,
								body: "{",
							})
						: pending;
					if (malformed)
						request.headers.set("content-type", "application/json");
					request.headers.set("x-real-ip", ip);
					request.headers.set(
						"cookie",
						[
							request.headers.get("cookie"),
							previous.device,
							browser.device,
							trustedDevice,
							expired?.primary ??
								(scenario === "active" ? browser.primary : undefined),
						]
							.filter(Boolean)
							.join("; "),
					);
					const response = await dispatch(request);
					const location = response.headers.get("location");
					const cookies = response.headers.getSetCookie();
					const primary = cookieValue(response, primaryName);
					if (expired)
						expect(
							cookies.some((value) => value.startsWith(`${primaryName}=;`)),
						).toBe(false);
					if (rejected) {
						if (malformed) expect(response.status).toBe(400);
						else if (callbackPath === "/sso/callback/:providerId") {
							expect(response.status).toBe(302);
							expect(new URL(location!).searchParams.get("error")).toBe(
								"access_denied",
							);
						} else if (response.status === 302) {
							expect(new URL(location!).searchParams.has("error")).toBe(true);
						} else {
							expect(response.status).toBe(400);
							expect(await response.json()).toMatchObject({
								code: "INVALID_SAML_RESPONSE",
							});
						}
						expect(primary).toBeUndefined();
						expect(cookieValue(response, trustName)).toBeUndefined();
					} else {
						expect(location, await response.clone().text()).toBe(destination);
						expect(primary).toBeTruthy();
						expect(await browserSession(primary!)).toMatchObject({
							user: { id: userId },
						});
						if (policy.mfaMode === "required") {
							const rotated = cookieValue(response, trustName);
							expect(rotated).toBeTruthy();
							expect(rotated).not.toBe(trustedDevice);
							trustedDevice = rotated;
						}
					}
					expect(
						cookies.some(
							(value) =>
								value.startsWith(`${previous.deviceName}=;`) &&
								value.includes("Max-Age=0"),
						),
					).toBe(!rejected && expired?.id !== previous.id);
					const stored = await database.query<{ id: string }>(
						`SELECT id FROM "${schema}"."session" WHERE id=ANY($1::text[])`,
						[[previous.id, unrelated.id, browser.id]],
					);
					expect(
						new Set(stored.rows.map(({ id }) => id)),
						`${writer} ${scenario} session rows`,
					).toEqual(
						new Set([
							unrelated.id,
							...(rejected ? [previous.id] : []),
							...(expiredRemoved?.id !== browser.id ? [browser.id] : []),
						]),
					);
					if (expired && clientId) {
						const { rows } = await database.query<{
							id: string;
							revoked: boolean;
							sessionId: string | null;
						}>(
							`SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM "${schema}"."oauthAccessToken" WHERE "clientId"=$1
							 UNION ALL SELECT id,revoked IS NOT NULL AS revoked,"sessionId" FROM "${schema}"."oauthRefreshToken" WHERE "clientId"=$1`,
							[clientId],
						);
						expect(rows).toHaveLength(grants.length);
						for (const { id, kind } of grants)
							expect(rows.find((row) => row.id === id)).toEqual({
								id,
								revoked: Boolean(expiredRemoved && kind !== "offline"),
								sessionId: expiredRemoved ? null : expired.id,
							});
					}
					const expectedEvents = [
						...(expiredRemoved
							? [
									{
										userId: expiredRemoved.userId,
										targetId: expiredRemoved.id,
										actorId: expiredRemoved.userId,
									},
								]
							: []),
						...(!rejected && expired?.id !== previous.id
							? [
									{
										userId,
										targetId: previous.id,
										actorId:
											policy.mfaMode === "required" && scenario === "active"
												? browserUserId
												: undefined,
									},
								]
							: []),
					];
					const events: ControlWebhookEnvelope[] = [];
					expect(
						await deliverPendingWebhooks({
							database: scoped,
							secret,
							now: () => new Date(Date.now() + 2_000),
							resolver: async () => [{ address: "93.184.216.34", family: 4 }],
							async transport({ destination, body, headers }) {
								expect(destination.url.href).toBe(url);
								expect(headers["webhook-signature"]).toBe(
									await webhookSignature(
										signingKey,
										headers["webhook-id"]!,
										headers["webhook-timestamp"]!,
										body,
									),
								);
								for (const value of [
									previous.token,
									unrelated.token,
									browser.token,
									signingKey,
								])
									expect(body).not.toContain(value);
								events.push(JSON.parse(body) as ControlWebhookEnvelope);
								return 204;
							},
						}),
					).toEqual({
						claimed: expectedEvents.length,
						delivered: expectedEvents.length,
						failed: 0,
						retried: 0,
					});
					for (const expected of expectedEvents) {
						const envelope = events.find(
							({ data }) => data.event.targetId === expected.targetId,
						);
						const { id, createdAt } = envelope!.data.event;
						expect(
							envelope,
							`${writer} enterprise callback ${scenario}`,
						).toEqual({
							id,
							type: "session.deleted",
							timestamp: createdAt,
							data: {
								event: {
									id,
									createdAt,
									type: "session.deleted",
									outcome: "success",
									...(expected.actorId ? { actorId: expected.actorId } : {}),
									userId: expected.userId,
									targetId: expected.targetId,
									metadata: { path: callbackPath },
								},
							},
						});
					}
				} finally {
					await database.query(
						`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
						[endpoint],
					);
					if (clientId)
						await database.query(
							`DELETE FROM "${schema}"."oauthClient" WHERE id=$1`,
							[clientId],
						);
				}
			}
		}
	} finally {
		if (factorIds.length) {
			await database.query(
				`DELETE FROM "${schema}"."twoFactor" WHERE id=ANY($1::text[])`,
				[factorIds],
			);
			await database.query(
				`DELETE FROM "${schema}"."verification" WHERE value=$1 AND starts_with(identifier,'trust-device-')`,
				[userId],
			);
			for (const owner of enrolledUsers)
				await database.query(
					`UPDATE "${schema}"."user" SET "twoFactorEnabled"=$2 WHERE id=$1`,
					[owner.id, owner.twoFactorEnabled],
				);
		}
	}
}
