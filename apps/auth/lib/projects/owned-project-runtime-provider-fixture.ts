import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { verifyAssetRequest } from "../branding/asset-signature";

export const runtimeFixtureAssetOrigin =
	"https://assets.runtime.fixture.example";
export const runtimeFixtureAssetSecret =
	"isolated-runtime-fixture-asset-signing-key";

export const runtimeFixtureGoogle = {
	clientId: "fixture-runtime-google.apps.googleusercontent.com",
	clientSecret: "fixture-runtime-google-client-secret",
	email: "google-user@runtime.fixture.example",
	subject: "fixture-runtime-google-subject",
};

export const runtimeFixtureMicrosoft = {
	clientId: "11111111-2222-4333-8444-555555555555",
	clientSecret: "fixture-runtime-microsoft-client-secret",
	tenantId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	email: "microsoft-user@runtime.fixture.example",
	subject: "cccccccc-aaaa-4bbb-8ddd-eeeeeeeeeeee",
};

const microsoftOrigin = "https://login.microsoftonline.com";
const microsoftBase = `${microsoftOrigin}/${runtimeFixtureMicrosoft.tenantId}`;
const endpoints = {
	google: {
		token: "https://oauth2.googleapis.com/token",
		keys: "https://www.googleapis.com/oauth2/v3/certs",
		issuer: "accounts.google.com",
	},
	microsoft: {
		token: `${microsoftBase}/oauth2/v2.0/token`,
		keys: `${microsoftBase}/discovery/v2.0/keys`,
		issuer: `${microsoftBase}/v2.0`,
	},
};

type RuntimeProvider = keyof typeof endpoints;

/** Carry the simulated IdP's expected values through the fixture callback only. */
export function runtimeProviderFixtureCode(authorization: URL) {
	return Buffer.from(
		JSON.stringify({
			challenge: authorization.searchParams.get("code_challenge"),
			redirectURI: authorization.searchParams.get("redirect_uri"),
			nonce: authorization.searchParams.get("nonce"),
		}),
	).toString("base64url");
}

/** Exact in-process IdP endpoints. No other HTTP requests are sent. */
export function runtimeProviderFixtureFetch() {
	const keys = generateKeyPair("RS256", { extractable: true });
	const kid = "runtime-provider-fixture-key";
	return async function fetchFixture(
		input: RequestInfo | URL,
		init?: RequestInit,
	) {
		const request = new Request(input, init);
		if (new URL(request.url).origin === runtimeFixtureAssetOrigin) {
			const data = await verifyAssetRequest(request, runtimeFixtureAssetSecret);
			return data && request.headers.get("content-type") === "image/jpeg"
				? Response.json({ url: request.url }, { status: 201 })
				: new Response(null, { status: 403 });
		}
		const provider = (Object.keys(endpoints) as RuntimeProvider[]).find(
			(name) =>
				[endpoints[name].keys, endpoints[name].token].includes(request.url),
		);
		if (!provider)
			throw new Error(
				"The project runtime fixture does not perform outbound HTTP.",
			);
		const endpoint = endpoints[provider];
		const pair = await keys;
		if (request.url === endpoint.keys && request.method === "GET")
			return Response.json({
				keys: [{ ...(await exportJWK(pair.publicKey)), alg: "RS256", kid }],
			});
		if (request.url !== endpoint.token || request.method !== "POST")
			throw new Error(
				"The provider fixture request did not match the configured method.",
			);
		const form = new URLSearchParams(await request.text());
		const authorization = JSON.parse(
			Buffer.from(form.get("code") ?? "", "base64url").toString(),
		) as {
			challenge: string | null;
			redirectURI: string | null;
			nonce: string | null;
		};
		const config =
			provider === "google" ? runtimeFixtureGoogle : runtimeFixtureMicrosoft;
		if (
			form.get("client_id") !== config.clientId ||
			form.get("client_secret") !== config.clientSecret ||
			form.get("redirect_uri") !== authorization.redirectURI ||
			createHash("sha256")
				.update(form.get("code_verifier") ?? "")
				.digest("base64url") !== authorization.challenge
		)
			throw new Error(
				"The provider fixture token exchange did not preserve its configuration.",
			);
		const claims = {
			email: config.email,
			name: "Fixture Direct Provider User",
			...(authorization.nonce ? { nonce: authorization.nonce } : {}),
			...(provider === "google"
				? { email_verified: true }
				: { oid: config.subject, tid: runtimeFixtureMicrosoft.tenantId }),
		};
		const idToken = await new SignJWT(claims)
			.setProtectedHeader({ alg: "RS256", kid })
			.setSubject(
				provider === "google"
					? config.subject
					: "fixture-microsoft-pairwise-subject",
			)
			.setIssuer(endpoint.issuer)
			.setAudience(config.clientId)
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(pair.privateKey);
		return Response.json({
			access_token: "synthetic-direct-access",
			token_type: "Bearer",
			expires_in: 300,
			id_token: idToken,
		});
	};
}
