import { createHmac, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createAuth } from "./auth";
import { MCP_DEVICE_CLIENT_ID } from "./features/mcp-device";
import {
	platformIssuerDevicePath,
	routePlatformIssuerDevice,
} from "./platform-issuer-device-routing";
import { createPlatformIssuerSessionReader } from "./platform-issuer-session";
import { createPlatformIssuerStore } from "./platform-issuer-store";
import { postgresDatabase } from "./postgres-database";
import {
	createOwnedProjectIssuerDevice,
	projectDeviceGrantType,
} from "./projects/owned-project-issuer-device";
import { maximumIssuerFormBytes } from "./projects/owned-project-issuer-http";
import { dropClosedFixtureDatabase } from "./testing/postgres-fixture";

const fixture = new URL(
	"../../../.secrets/local-postgres.json",
	import.meta.url,
);
const issuer = "https://platform-device.fixture.example";
const endpointBase = `${issuer}/api/auth`;
const secret = "synthetic-platform-device-session-secret";
const cookieName = "__Secure-better-auth.session_token";
const env = {
	AUTH_RUNTIME: "node",
	ALLAUTH_AUTH_URL: issuer,
	ALLAUTH_AUTH_SECRET: secret,
	SCIM_CREDENTIAL_HASH_SECRET: "synthetic-platform-device-directory-secret",
};

function request(
	path: string,
	body?: Record<string, unknown> | URLSearchParams,
	cookie?: string,
) {
	const headers = new Headers({ "x-real-ip": "192.0.2.14" });
	if (cookie) {
		headers.set("origin", issuer);
		headers.set("cookie", cookie);
	}
	if (body && !(body instanceof URLSearchParams))
		headers.set("content-type", "application/json");
	return new Request(`${endpointBase}${path}`, {
		method: body ? "POST" : "GET",
		headers,
		body: body instanceof URLSearchParams ? body : body && JSON.stringify(body),
	});
}

describe.skipIf(!existsSync(fixture))(
	"shared OAuth and MCP device routing in PostgreSQL",
	() => {
		const databaseName = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool | undefined;
		let database: Pool;
		let native: ReturnType<typeof createAuth>;
		let owned: ReturnType<typeof createOwnedProjectIssuerDevice>;
		const readBody = vi.fn((request: Request) => request.json());
		let user: string;
		let cookie: string;

		beforeAll(async () => {
			const configuration = JSON.parse(readFileSync(fixture, "utf8"));
			const url = new URL(configuration.DATABASE_URL);
			if (
				configuration.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			for (const name of [
				"001-initial-auth.sql",
				"002-control-plane.sql",
				"004-webhooks.sql",
				"005-free-plugins.sql",
			])
				await database.query(
					readFileSync(
						new URL(`../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			user = randomUUID();
			const token = randomUUID();
			const signature = createHmac("sha256", secret)
				.update(token)
				.digest("base64");
			cookie = `${cookieName}=${encodeURIComponent(`${token}.${signature}`)}`;
			await database.query(
				`INSERT INTO public."user" (id,name,email,"emailVerified") VALUES ($1,'Fixture',$2,true)`,
				[user, `${user}@fixture.example`],
			);
			await database.query(
				`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt") VALUES
			 ($1,$2,$3,now()+interval '1 hour',now())`,
				[randomUUID(), token, user],
			);
			native = createAuth(postgresDatabase(database), env);
			const store = createPlatformIssuerStore(database);
			const session = createPlatformIssuerSessionReader(env);
			owned = createOwnedProjectIssuerDevice({
				database,
				schemaName: store.schemaName,
				store,
				issuer,
				endpointBase,
				platformOrigin: issuer,
				readBody,
				readSession: (request, client) => session(request.headers, client),
				trustedIP: (request) => request.headers.get("x-real-ip"),
			});
		});

		afterAll(async () => {
			await database?.end();
			if (administrator) {
				try {
					await dropClosedFixtureDatabase(administrator, databaseName);
				} finally {
					await administrator.end();
				}
			}
		});

		async function register(clientId: string) {
			await database.query(
				`INSERT INTO public."oauthClient" (id,"clientId","redirectUris","grantTypes","tokenEndpointAuthMethod",scopes,"applicationType")
			 VALUES ($1,$2,'[]',$3,'none','["openid"]','native')`,
				[randomUUID(), clientId, JSON.stringify([projectDeviceGrantType])],
			);
		}

		async function dispatch(incoming: Request, kind: "native" | "oauth") {
			const selected = await routePlatformIssuerDevice(database, incoming);
			expect(selected?.kind).toBe(kind);
			if (selected?.kind === "native") return native.handler(selected.request);
			if (selected?.kind === "oauth") {
				const response = await owned(
					selected.path,
					selected.request,
					selected.prepared,
				);
				if (response) return response;
			}
			throw new Error("Device request was not dispatched.");
		}

		async function deviceRow(deviceCode: string) {
			const {
				rows: [row],
			} = await database.query(
				`SELECT "oauthClientId","userId",status,"lastPolledAt" FROM public."deviceCode" WHERE "deviceCode"=$1`,
				[deviceCode],
			);
			return row;
		}

		it("keeps the exact standalone MCP code, review, approval and signed token handoff native", async () => {
			const form = new URLSearchParams([
				["client_id", ""],
				["client_id", MCP_DEVICE_CLIENT_ID],
			]);
			const code = await dispatch(request("/device/code", form), "native");
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(issued).toMatchObject({
				verification_uri: `${issuer}/device`,
				expires_in: 600,
				interval: 5,
			});
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: null,
				userId: null,
				status: "pending",
			});
			const review = await dispatch(
				request(`/device?user_code=${issued.user_code}`, undefined, cookie),
				"native",
			);
			expect(review.status).toBe(200);
			const approve = await dispatch(
				request("/device/approve", { userCode: issued.user_code }, cookie),
				"native",
			);
			expect(approve.status).toBe(200);
			const poll = request("/device/token", {
				client_id: MCP_DEVICE_CLIENT_ID,
				device_code: issued.device_code,
				grant_type: projectDeviceGrantType,
			});
			expect(platformIssuerDevicePath(poll)).toBeUndefined();
			const token = await dispatch(poll, "native");
			expect(token.status).toBe(200);
			expect(token.headers.get("cache-control")).toBe("no-store");
			const issuedCookie = token.headers
				.getSetCookie()
				.find((value) => value.startsWith(`${cookieName}=`));
			expect(issuedCookie).toBeDefined();
			const session = await native.handler(
				request("/get-session", undefined, issuedCookie?.split(";", 1)[0]),
			);
			expect(await session.json()).toMatchObject({ user: { id: user } });
			expect(await deviceRow(issued.device_code)).toBeUndefined();
		});

		it("routes a root managed OAuth client to AllAuth and retains the native wrong-endpoint response", async () => {
			const clientId = "managed-device-fixture";
			await register(clientId);
			const code = await dispatch(
				request(
					"/device/code",
					new URLSearchParams({ client_id: clientId, scope: "openid" }),
				),
				"oauth",
			);
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(issued).toMatchObject({
				verification_uri: `${issuer}/device`,
				expires_in: 600,
				interval: 5,
			});
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: clientId,
				userId: null,
				status: "pending",
			});
			const display =
				`${issued.user_code.slice(0, 4)}-${issued.user_code.slice(4)}`.toLowerCase();
			const review = await dispatch(
				request(`/device?user_code=${display}`, undefined, cookie),
				"oauth",
			);
			expect(review.status).toBe(200);
			expect(await review.json()).toMatchObject({
				client_id: clientId,
				scope: "openid",
				status: "pending",
			});
			const approve = await dispatch(
				request("/device/approve", { userCode: display }, cookie),
				"oauth",
			);
			expect(approve.status).toBe(200);
			expect(await approve.json()).toEqual({ success: true });
			const state = await deviceRow(issued.device_code);
			expect(state).toMatchObject({
				oauthClientId: clientId,
				userId: user,
				status: "approved",
				lastPolledAt: null,
			});
			const wrongEndpoint = await dispatch(
				request("/device/token", {
					client_id: clientId,
					device_code: issued.device_code,
					grant_type: projectDeviceGrantType,
				}),
				"native",
			);
			expect(wrongEndpoint.status).toBe(400);
			expect(await wrongEndpoint.json()).toEqual({
				error: "invalid_grant",
				error_description:
					"This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
			});
			expect(wrongEndpoint.headers.getSetCookie()).toEqual([]);
			expect(await deviceRow(issued.device_code)).toEqual(state);
			expect(readBody).not.toHaveBeenCalled();
		});

		it("keeps credential attempts and registered exact-ID collisions in OAuth admission", async () => {
			const conflicting = request("/device/code", {
				client_id: MCP_DEVICE_CLIENT_ID,
				client_secret: "fixture-secret",
			});
			expect(
				(await routePlatformIssuerDevice(database, conflicting))?.kind,
			).toBe("oauth");
			const authenticated = request("/device/code", {
				client_id: MCP_DEVICE_CLIENT_ID,
			});
			authenticated.headers.set("authorization", "Basic malformed-fixture");
			expect(
				(await routePlatformIssuerDevice(database, authenticated))?.kind,
			).toBe("oauth");
			const repeated = request(
				"/device/code",
				new URLSearchParams([
					["client_id", MCP_DEVICE_CLIENT_ID],
					["client_id", MCP_DEVICE_CLIENT_ID],
				]),
			);
			const duplicate = await dispatch(repeated, "oauth");
			expect(duplicate.status).toBe(400);
			expect(await duplicate.json()).toMatchObject({
				error: "invalid_request",
			});
			await register(MCP_DEVICE_CLIENT_ID);
			const code = await dispatch(
				request("/device/code", { client_id: MCP_DEVICE_CLIENT_ID }),
				"oauth",
			);
			expect(code.status).toBe(200);
			const issued = (await code.json()) as {
				device_code: string;
				user_code: string;
			};
			expect(await deviceRow(issued.device_code)).toMatchObject({
				oauthClientId: MCP_DEVICE_CLIENT_ID,
				status: "pending",
			});
		});

		it("bounds unread OAuth device bodies without querying routing state", async () => {
			const lookup = { query: vi.fn() };
			const oversized = new Request(`${endpointBase}/device/code`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: new Uint8Array(maximumIssuerFormBytes + 1),
			});
			const selected = await routePlatformIssuerDevice(lookup, oversized);
			expect(selected?.kind).toBe("response");
			if (selected?.kind !== "response")
				throw new Error("Expected request size rejection.");
			expect(selected.response.status).toBe(400);
			expect(await selected.response.json()).toMatchObject({
				error: "invalid_request",
			});
			expect(lookup.query).not.toHaveBeenCalled();
		});
	},
);
