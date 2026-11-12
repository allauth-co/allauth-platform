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
	prepare(dispatch: Dispatch, ip: string): Promise<Request>;
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
		for (const [writer, dispatch, start] of [
			["native", native.handler, owned],
			["owned", owned, native.handler],
		] as const) {
			for (const withBrowser of [true, false]) {
				const previous = await savedSession(userId);
				const unrelated = await savedSession(userId);
				const browser = await savedSession(browserUserId);
				expect((await browserSession(browser.primary))?.user.id).toBe(
					browserUserId,
				);
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
					const request = await prepare(start, ip);
					request.headers.set("x-real-ip", ip);
					request.headers.set(
						"cookie",
						[
							request.headers.get("cookie"),
							previous.device,
							browser.device,
							trustedDevice,
							...(withBrowser ? [browser.primary] : []),
						]
							.filter(Boolean)
							.join("; "),
					);
					const response = await dispatch(request);
					expect(
						response.headers.get("location"),
						await response.clone().text(),
					).toBe(destination);
					const cookies = response.headers.getSetCookie();
					const primary = cookies
						.find((value) => value.startsWith(`${primaryName}=`))
						?.split(";", 1)[0];
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
					expect(
						cookies.find((value) =>
							value.startsWith(`${previous.deviceName}=;`),
						),
					).toContain("Max-Age=0");
					expect(await browserSession(previous.primary)).toBeNull();
					expect((await browserSession(unrelated.primary))?.user.id).toBe(
						userId,
					);
					expect((await browserSession(browser.primary))?.user.id).toBe(
						browserUserId,
					);
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
					).toEqual({ claimed: 1, delivered: 1, failed: 0, retried: 0 });
					const { id, createdAt } = events[0]!.data.event;
					expect(
						events,
						`${writer} enterprise callback with ${withBrowser ? "an active browser" : "only saved devices"}`,
					).toEqual([
						{
							id,
							type: "session.deleted",
							timestamp: createdAt,
							data: {
								event: {
									id,
									createdAt,
									type: "session.deleted",
									outcome: "success",
									...(policy.mfaMode === "required" && withBrowser
										? { actorId: browserUserId }
										: {}),
									userId,
									targetId: previous.id,
									metadata: { path: callbackPath },
								},
							},
						},
					]);
				} finally {
					await database.query(
						`DELETE FROM "${schema}"."allauthWebhookEndpoint" WHERE id=$1`,
						[endpoint],
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
