import { afterEach, describe, expect, it, vi } from "vitest";
import { exportPKCS8, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { getTestInstance } from "better-auth/test";
import { APIError } from "better-auth";
import type { BetterAuthOptions } from "better-auth";
import { guardAvatarUserDeletion } from "../avatars/deletion";
import { setTokenUtil } from "better-auth/oauth2";
import {
	guardAppleUserDeletion,
	revokeAppleBeforeUserDeletion,
} from "./apple-deletion";
import { createAuthOptions } from "../auth";

const origin = "http://localhost:3000";
const subject = "fixture-apple-subject";
afterEach(() => vi.unstubAllGlobals());
async function fixture({
	native = false,
	audience,
	tokenSubject = subject,
	expired = false,
	productionHook = false,
	ownedCleanup,
	refreshToken = "fixture-apple-refresh",
	accessToken = "fixture-apple-access",
}: {
	native?: boolean;
	audience?: string;
	tokenSubject?: string;
	expired?: boolean;
	productionHook?: boolean;
	ownedCleanup?: (userId: string) => Promise<void>;
	refreshToken?: string | null;
	accessToken?: string | null;
} = {}) {
	const signing = await generateKeyPair("ES256", { extractable: true }),
		apple = await generateKeyPair("RS256");
	const configured = {
		clientId: "com.fixture.web",
		appBundleIdentifier: "com.fixture.native",
		teamId: "TEAM123456",
		keyId: "KEY1234567",
		privateKey: await exportPKCS8(signing.privateKey),
	};
	const options: BetterAuthOptions = {
		account: { encryptOAuthTokens: true },
		socialProviders: {
			apple: {
				clientId: [configured.clientId, configured.appBundleIdentifier],
				clientSecret: "fixture-client-secret",
			},
		},
		user: { deleteUser: { enabled: true } },
		logger: { disabled: true },
	};
	const cleanup = vi.fn(async (_userId: string) => {});
	if (productionHook) {
		const production = createAuthOptions(
			undefined,
			{
				BETTER_AUTH_URL: origin,
				BETTER_AUTH_SECRET: "fixture-secret-with-thirty-two-characters",
				SCIM_CREDENTIAL_HASH_SECRET: "fixture-scim-with-thirty-two-characters",
			},
			{
				name: "Fixture",
				slug: "fixture-apple",
				basePath: "/api/auth",
				cookiePrefix: "fixture-apple",
				primaryOrigin: "https://fixture.example",
				origins: ["https://fixture.example"],
				broker: {
					clientId: "fixture-broker",
					clientSecret: "fixture-broker-secret",
				},
				authorizeAdmin: async () => null,
				management: { id: "fixture-management" },
				apple: configured,
				beforeDeleteUser: ownedCleanup,
			},
		);
		const initialize = production.plugins.find(
			(plugin) => plugin.id === "allauth-production",
		);
		if (!initialize || !("init" in initialize))
			throw Error("Fixture initialization absent");
		options.plugins = [
			{ id: "fixture-allauth-context", init: initialize.init },
		];
		options.user = {
			deleteUser: {
				enabled: true,
				beforeDelete: async (user) => {
					await production.user.deleteUser.beforeDelete(user);
					await cleanup(user.id);
				},
			},
		};
	}
	const f = await getTestInstance(options);
	const ctx = await f.auth.$context,
		found = await ctx.internalAdapter.findUserByEmail(f.testUser.email);
	if (!found) throw Error("Fixture user absent");
	const provider = ctx.socialProviders.find((value) => value.id === "apple");
	if (!provider?.idToken || !("jwks" in provider.idToken))
		throw Error("Fixture provider absent");
	provider.idToken.jwks = async () => apple.publicKey;
	const iat = Math.floor(Date.now() / 1000) - (expired ? 86400 * 30 : 0);
	const idToken = await new SignJWT({})
		.setProtectedHeader({ alg: "RS256", kid: "fixture-apple-key" })
		.setIssuer("https://appleid.apple.com")
		.setAudience(
			audience ??
				(native ? configured.appBundleIdentifier : configured.clientId),
		)
		.setSubject(tokenSubject)
		.setIssuedAt(iat)
		.setExpirationTime(iat + 3600)
		.sign(apple.privateKey);
	const account = await ctx.internalAdapter.createAccount({
		userId: found.user.id,
		providerId: "apple",
		accountId: subject,
		idToken,
		refreshToken: await setTokenUtil(refreshToken, ctx),
		accessToken: await setTokenUtil(accessToken, ctx),
	});
	const requests: { url: string; init: RequestInit }[] = [];
	let response = () => new Response(null, { status: 200 });
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init: RequestInit) => {
			requests.push({ url, init });
			return response();
		}),
	);
	return {
		...f,
		ctx,
		configured,
		signing,
		account,
		cleanup,
		userId: found.user.id,
		requests,
		setResponse(next: typeof response) {
			response = next;
		},
		async callDelete() {
			const login = await f.auth.api.signInEmail({
				body: { email: f.testUser.email, password: f.testUser.password },
				asResponse: true,
			});
			const cookie = login.headers
				.getSetCookie()
				.map((value) => value.split(";")[0])
				.join("; ");
			return f.auth.handler(
				new Request(`${origin}/api/auth/delete-user`, {
					method: "POST",
					headers: { origin, cookie, "content-type": "application/json" },
					body: JSON.stringify({ password: f.testUser.password }),
				}),
			);
		},
	};
}

/** @see https://developer.apple.com/documentation/signinwithapplerestapi/revoke-tokens */
describe("owning-realm Apple revocation before deletion", () => {
	it("decrypts the stored refresh grant and binds the request and server-signed secret to the ID-token client", async () => {
		for (const native of [false, true]) {
			const f = await fixture({ native, expired: true });
			await revokeAppleBeforeUserDeletion(f.ctx, f.userId, f.configured);
			expect(f.requests).toHaveLength(1);
			const { url, init } = f.requests[0];
			expect(url).toBe("https://appleid.apple.com/auth/revoke");
			expect(init.method).toBe("POST");
			expect(init.redirect).toBe("error");
			expect(init.signal).toBeInstanceOf(AbortSignal);
			const body = new URLSearchParams(String(init.body)),
				clientId = native
					? f.configured.appBundleIdentifier
					: f.configured.clientId;
			expect(body.get("client_id")).toBe(clientId);
			expect(body.get("token_type_hint")).toBe("refresh_token");
			expect(body.get("token")).toBe("fixture-apple-refresh");
			await expect(
				jwtVerify(body.get("client_secret")!, f.signing.publicKey, {
					issuer: f.configured.teamId,
					subject: clientId,
					audience: "https://appleid.apple.com",
					algorithms: ["ES256"],
				}),
			).resolves.toBeTruthy();
			expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
		}
	});
	it("never borrows another realm's configuration or accepts an account/client mismatch", async () => {
		for (const options of [
			{ audience: "com.other.realm" },
			{ tokenSubject: "different-apple-person" },
		]) {
			const f = await fixture(options);
			await expect(
				revokeAppleBeforeUserDeletion(f.ctx, f.userId, f.configured),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(f.requests).toHaveLength(0);
		}
		const f = await fixture();
		await expect(
			revokeAppleBeforeUserDeletion(f.ctx, f.userId, undefined),
		).rejects.toMatchObject({ statusCode: 503 });
		expect(f.requests).toHaveLength(0);
		await expect(
			revokeAppleBeforeUserDeletion(f.ctx, f.userId, {
				...f.configured,
				clientId: "com.other.realm",
				appBundleIdentifier: undefined,
			}),
		).rejects.toMatchObject({ statusCode: 503 });
		expect(f.requests).toHaveLength(0);
	});
	it("refuses access-only or absent tokens and cannot treat a decodable forged identity as binding", async () => {
		const f = await fixture({ refreshToken: null });
		await expect(
			revokeAppleBeforeUserDeletion(f.ctx, f.userId, f.configured),
		).rejects.toMatchObject({
			statusCode: 503,
			body: { code: "APPLE_BROWSER_REAUTHENTICATION_REQUIRED" },
		});
		expect(f.requests).toHaveLength(0);
		const wrongSigner = await generateKeyPair("RS256");
		const forged = await new SignJWT({})
			.setProtectedHeader({ alg: "RS256", kid: "fixture-apple-key" })
			.setIssuer("https://appleid.apple.com")
			.setAudience(f.configured.clientId)
			.setSubject(subject)
			.setIssuedAt()
			.setExpirationTime("1h")
			.sign(wrongSigner.privateKey);
		await f.ctx.internalAdapter.updateAccount(f.account.id, {
			refreshToken: await setTokenUtil("fixture-refresh", f.ctx),
			idToken: forged,
		});
		await expect(
			revokeAppleBeforeUserDeletion(f.ctx, f.userId, f.configured),
		).rejects.toMatchObject({ statusCode: 503 });
		expect(f.requests).toHaveLength(0);
	});
	it("keeps account and user rows on provider refusal, redirect, malformed success or network failure, and safely retries", async () => {
		const f = await fixture();
		guardAppleUserDeletion(f.ctx, f.configured);
		guardAppleUserDeletion(f.ctx, f.configured);
		for (const status of [400, 302, 204, 500]) {
			f.setResponse(() => new Response(null, { status }));
			await expect(
				f.ctx.internalAdapter.deleteUser(f.userId),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
			expect(await f.ctx.internalAdapter.findAccounts(f.userId)).toHaveLength(
				2,
			);
		}
		f.setResponse(() => {
			throw Error("fixture-private-provider-error");
		});
		await expect(
			f.ctx.internalAdapter.deleteUser(f.userId),
		).rejects.not.toThrow("fixture-private-provider-error");
		f.setResponse(() => new Response(null, { status: 200 }));
		await f.ctx.internalAdapter.deleteUser(f.userId);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).toBeNull();
		expect(f.requests).toHaveLength(6);
	});
	it("retries the same grant if Apple accepted revocation but later local deletion failed", async () => {
		const f = await fixture(),
			remove = f.ctx.internalAdapter.deleteUser.bind(f.ctx.internalAdapter);
		let failLocalDeletion = true;
		f.ctx.internalAdapter.deleteUser = async (userId) => {
			if (failLocalDeletion) throw Error("fixture-local-delete-failed");
			return remove(userId);
		};
		guardAppleUserDeletion(f.ctx, f.configured);
		await expect(f.ctx.internalAdapter.deleteUser(f.userId)).rejects.toThrow(
			"fixture-local-delete-failed",
		);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
		failLocalDeletion = false;
		await f.ctx.internalAdapter.deleteUser(f.userId);
		expect(f.requests).toHaveLength(2);
		expect(
			new URLSearchParams(String(f.requests[0].init.body)).get("token"),
		).toBe(new URLSearchParams(String(f.requests[1].init.body)).get("token"));
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).toBeNull();
	});
	it("a different user's Apple rows are outside the deleting user's adapter query", async () => {
		const f = await fixture(),
			other = await f.ctx.internalAdapter.createUser(
				{
					email: "other-fixture@example.com",
					name: "Other fixture",
					emailVerified: true,
				},
				{ method: "admin" },
			);
		guardAppleUserDeletion(f.ctx, f.configured);
		await f.ctx.internalAdapter.deleteUser(other.id);
		expect(f.requests).toHaveLength(0);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
		expect(
			(await f.ctx.internalAdapter.findAccounts(f.userId)).some(
				(account) => account.id === f.account.id,
			),
		).toBe(true);
	});
	it("pending owned-photo erasure preserves Apple grants and retry credentials on the actual delete endpoint", async () => {
		let pending = true;
		const ownedCleanup = vi.fn(async (_userId: string) => {
			if (pending) throw new APIError("SERVICE_UNAVAILABLE", { message: "Profile photo erasure is pending." });
		});
		const f = await fixture({ productionHook: true, ownedCleanup });
		expect((await f.callDelete()).status).toBe(503);
		expect(f.requests).toHaveLength(0);
		expect(f.cleanup).not.toHaveBeenCalled();
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
		expect(await f.ctx.internalAdapter.findAccounts(f.userId)).toHaveLength(2);
		pending = false;
		expect((await f.callDelete()).status).toBe(200);
		expect(f.requests).toHaveLength(1);
		expect(ownedCleanup).toHaveBeenCalledTimes(2);
		expect(f.cleanup).toHaveBeenCalledWith(f.userId);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).toBeNull();
	});
	it("the composed realm adapter completes owned erasure before Apple revocation or user deletion", async () => {
		const f = await fixture();
		let pending = true;
		const ownedCleanup = vi.fn(async (_userId: string) => {
			if (pending) throw new APIError("SERVICE_UNAVAILABLE", { message: "Profile photo erasure is pending." });
		});
		guardAppleUserDeletion(f.ctx, f.configured);
		guardAvatarUserDeletion(f.ctx.internalAdapter, ownedCleanup);
		await expect(f.ctx.internalAdapter.deleteUser(f.userId)).rejects.toMatchObject({ statusCode: 503 });
		expect(f.requests).toHaveLength(0);
		expect(await f.ctx.internalAdapter.findAccounts(f.userId)).toHaveLength(2);
		pending = false;
		await f.ctx.internalAdapter.deleteUser(f.userId);
		expect(f.requests).toHaveLength(1);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).toBeNull();
	});
	it("production beforeDelete revokes before the following account cleanup callback", async () => {
		const f = await fixture({ productionHook: true });
		f.setResponse(() => new Response(null, { status: 503 }));
		expect((await f.callDelete()).status).toBe(503);
		expect(f.cleanup).not.toHaveBeenCalled();
		f.setResponse(() => new Response(null, { status: 200 }));
		expect((await f.callDelete()).status).toBe(200);
		expect(f.cleanup).toHaveBeenCalledWith(f.userId);
		expect(f.requests).toHaveLength(2);
	});
	it("the actual user-delete endpoint cannot erase Apple accounts before provider acknowledgement", async () => {
		const f = await fixture();
		guardAppleUserDeletion(f.ctx, f.configured);
		f.setResponse(() => new Response(null, { status: 503 }));
		const denied = await f.callDelete();
		expect(denied.status).toBe(503);
		expect(JSON.stringify(await denied.json())).not.toContain(
			"fixture-apple-refresh",
		);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).not.toBeNull();
		f.setResponse(() => new Response(null, { status: 200 }));
		expect((await f.callDelete()).status).toBe(200);
		expect(await f.ctx.internalAdapter.findUserById(f.userId)).toBeNull();
	});
	it("accounts without an Apple link delete normally when Apple configuration is absent", async () => {
		const f = await fixture();
		await f.ctx.adapter.delete({
			model: "account",
			where: [{ field: "id", value: f.account.id }],
		});
		guardAppleUserDeletion(f.ctx, undefined);
		expect((await f.callDelete()).status).toBe(200);
		expect(f.requests).toHaveLength(0);
	});
});
