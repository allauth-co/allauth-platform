import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { AuthPolicy } from "./auth-policy/policy";
import { canonicalIP } from "./control/security-policy";
import { isServerTokenRequest } from "./features/helpers";
import { MCP_DEVICE_CLIENT_ID } from "./features/mcp-device-contract";
import { readDeviceBody } from "./platform-issuer-device-routing";
import type { createPlatformIssuerStore } from "./platform-issuer-store";
import { recordOwnedProjectEvent } from "./projects/owned-project-engine-store";
import { projectDeviceGrantType } from "./projects/owned-project-issuer-device";
import {
	issuerFormParameters,
	issuerJSON,
	ProjectOAuthError,
} from "./projects/owned-project-issuer-http";
import { admitOwnedProjectNativeRoute } from "./projects/owned-project-native-admission";

interface DeviceGrant {
	id: string;
	userId: string | null;
	clientId: string | null;
	oauthClientId: string | null;
	status: string;
	expiresAt: Date;
	lastPolledAt: Date | null;
	pollingInterval: number | null;
	scope: string | null;
}

interface PlatformMcpDeviceTokenOptions {
	issuer: string;
	signingSecret: string;
	store: ReturnType<typeof createPlatformIssuerStore>;
	policy: () => Promise<AuthPolicy>;
	trustedIP: (request: Request) => string | null;
}

const invalidGrant = (description = "Invalid device code") =>
	new ProjectOAuthError("invalid_grant", description);
const accessDenied = () =>
	new ProjectOAuthError("access_denied", "Device authorization was denied");

async function tokenInput(request: Request) {
	const type = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	const raw = await readDeviceBody(request);
	try {
		const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
		const body: unknown =
			type === "application/x-www-form-urlencoded"
				? Object.fromEntries(issuerFormParameters(new URLSearchParams(text)))
				: type === "application/json"
					? JSON.parse(text)
					: null;
		if (
			body &&
			typeof body === "object" &&
			"grant_type" in body &&
			body.grant_type === projectDeviceGrantType &&
			"device_code" in body &&
			typeof body.device_code === "string" &&
			body.device_code.length > 0 &&
			body.device_code.length <= 191 &&
			"client_id" in body &&
			typeof body.client_id === "string" &&
			body.client_id.length <= 256
		)
			return { code: body.device_code, clientId: body.client_id };
	} catch (error) {
		if (error instanceof ProjectOAuthError) throw error;
	}
	throw new ProjectOAuthError(
		"invalid_request",
		"Invalid device token request",
	);
}

/** Redeem standalone MCP grants against the installed platform session and MFA formats. */
export function createPlatformMcpDeviceToken(
	options: PlatformMcpDeviceTokenOptions,
) {
	const secure = options.issuer.startsWith("https:");
	const cookiePrefix = secure ? "__Secure-better-auth." : "better-auth.";

	function cookie(
		response: Response,
		name: string,
		value: string,
		maxAge: number,
	) {
		const signature = createHmac("sha256", options.signingSecret)
			.update(value)
			.digest("base64");
		response.headers.append(
			"set-cookie",
			`${cookiePrefix}${name}=${encodeURIComponent(`${value}.${signature}`)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`,
		);
	}

	async function findGrant(client: PoolClient, code: string, lock = false) {
		const { rows } = await client.query<DeviceGrant>(
			`SELECT id,"userId","clientId","oauthClientId",status,"expiresAt","lastPolledAt","pollingInterval",scope
			 FROM public."deviceCode" WHERE "deviceCode"=$1${lock ? " FOR UPDATE" : ""}`,
			[code],
		);
		return rows[0];
	}

	async function startMfa(client: PoolClient, userId: string) {
		const maxAge = 600;
		const identifier = `2fa-${randomBytes(15).toString("base64url")}`;
		await client.query(
			`INSERT INTO public."verification" (id,identifier,value,"expiresAt","updatedAt")
			 VALUES ($1,$2,$3,now()+interval '10 minutes',now()), ($4,$5,'0',now()+interval '10 minutes',now())`,
			[
				randomUUID(),
				identifier,
				userId,
				randomUUID(),
				`2fa-attempts-${identifier}`,
			],
		);
		const { rowCount } = await client.query(
			'SELECT 1 FROM public."twoFactor" WHERE "userId"=$1 AND verified IS DISTINCT FROM false LIMIT 1',
			[userId],
		);
		const response = issuerJSON({
			twoFactorRedirect: true,
			twoFactorMethods: rowCount ? ["totp"] : [],
		});
		cookie(response, "two_factor", identifier, maxAge);
		return response;
	}

	return async function redeem(request: Request) {
		try {
			const origin = request.headers.get("origin");
			if (
				request.headers.has("authorization") ||
				request.headers.get("sec-fetch-site") === "cross-site" ||
				(origin !== null && origin !== options.issuer)
			)
				throw accessDenied();
			const limited = await options.store.transaction((client) =>
				admitOwnedProjectNativeRoute(
					client,
					options.trustedIP(request),
					"/device/token",
					{
						max: 100,
						windowMs: 60_000,
					},
				),
			);
			if (limited) return limited;
			const { code, clientId } = await tokenInput(request);
			const policy = await options.policy();
			return await options.store.transaction(async (client) => {
				const observed = await findGrant(client, code);
				if (!observed) return invalidGrant().response();
				if (observed.clientId !== clientId)
					return invalidGrant("Client ID mismatch").response();
				if (observed.oauthClientId !== null)
					return invalidGrant(
						"This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
					).response();
				if (clientId !== MCP_DEVICE_CLIENT_ID)
					return invalidGrant("Invalid client ID").response();

				// Approval and account revocation take the account lock before the grant lock.
				const user =
					observed.status === "approved" && observed.userId
						? await options.store.lockUser(client, observed.userId)
						: null;
				const grant = await findGrant(client, code, true);
				if (
					!grant ||
					grant.id !== observed.id ||
					grant.clientId !== clientId ||
					grant.oauthClientId !== null
				)
					return invalidGrant().response();
				if (grant.status === "approved" && observed.status === "pending")
					return new ProjectOAuthError(
						"authorization_pending",
						"Authorization pending",
					).response();

				const now = Date.now();
				if (
					grant.lastPolledAt &&
					grant.pollingInterval &&
					now - grant.lastPolledAt.getTime() < grant.pollingInterval
				)
					return new ProjectOAuthError(
						"slow_down",
						"Polling too frequently",
					).response();
				if (grant.expiresAt.getTime() <= now || grant.status === "denied") {
					await client.query('DELETE FROM public."deviceCode" WHERE id=$1', [
						grant.id,
					]);
					return (
						grant.status === "denied" && grant.expiresAt.getTime() > now
							? accessDenied()
							: new ProjectOAuthError(
									"expired_token",
									"Device code has expired",
								)
					).response();
				}
				if (grant.status === "pending") {
					await client.query(
						'UPDATE public."deviceCode" SET "lastPolledAt"=clock_timestamp() WHERE id=$1',
						[grant.id],
					);
					return new ProjectOAuthError(
						"authorization_pending",
						"Authorization pending",
					).response();
				}
				if (
					grant.status !== "approved" ||
					!user ||
					grant.userId !== user.id ||
					!user.emailVerified ||
					user.banned ||
					user.directoryDisabled ||
					user.directoryManaged ||
					user.isAnonymous ||
					(policy.mfaMode === "required" && !user.twoFactorEnabled)
				)
					return accessDenied().response();

				await client.query('DELETE FROM public."deviceCode" WHERE id=$1', [
					grant.id,
				]);
				if (user.twoFactorEnabled) return startMfa(client, user.id);

				const id = randomUUID();
				const token = randomBytes(32).toString("base64url");
				const lifetime = policy.sessionExpiresInSeconds;
				await client.query(
					`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt","ipAddress","userAgent")
					 VALUES ($1,$2,$3,now()+$4::integer*interval '1 second',now(),$5,$6)`,
					[
						id,
						token,
						user.id,
						lifetime,
						canonicalIP(options.trustedIP(request)) ?? "",
						request.headers.get("user-agent") ?? "",
					],
				);
				await recordOwnedProjectEvent(client, {
					type: "session.created",
					outcome: "success",
					userId: user.id,
					targetId: id,
					metadata: { path: "/device/token" },
				});
				const response = issuerJSON({
					access_token: token,
					token_type: "Bearer",
					expires_in: lifetime,
					scope: grant.scope ?? "",
				});
				if (isServerTokenRequest(request.headers))
					cookie(response, "session_token", token, lifetime);
				return response;
			});
		} catch (error) {
			if (error instanceof ProjectOAuthError) return error.response();
			throw error;
		}
	};
}
