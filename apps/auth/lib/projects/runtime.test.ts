import type { Pool } from "pg";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuthEnvironment } from "../configuration";
import { projectEmailAliasVariable } from "../project-email-alias-config";
import type { Project } from "./registry";
import { verifyInternalProjectEngineReadiness } from "./project-engine-internal-readiness";
import { closeProjectInstances, withHostedProjectAuthEngine, withProjectAuth, withProjectAuthEngine } from "./runtime";
import * as projectRuntime from "./runtime";
import { platformWorkspaceId } from "../workspaces/types";
import { defaultStoredAuthPolicy } from "../auth-policy/policy";

const fixture = vi.hoisted(() => {
	const unexpectedDatabaseWrite = async () => { throw new Error("The runtime-cache fixture must not issue database writes."); };
	return {
		getProject: vi.fn(), readAuthPolicy: vi.fn(),
		resolveHostedBinding: vi.fn(),
		admitted: { writer: "legacy" as "legacy" | "allauth", revision: 0 },
		readGoogleProvider: vi.fn(async () => ({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null as string | null })),
		createOwned: vi.fn(async (_options: unknown) => ({
			dispatch: async () => new Response(null, { status: 202 }),
		})),
		createAuth: vi.fn((..._arguments: unknown[]) => ({
			handler: async () => new Response(null, { status: 204 }),
			$context: Promise.resolve({
				adapter: { create: unexpectedDatabaseWrite, update: unexpectedDatabaseWrite, transaction: unexpectedDatabaseWrite },
				internalAdapter: { deleteUser: async () => {} },
			}),
		})),
		end: vi.fn(async () => {}),
	};
});
vi.mock("../project-providers/repository", () => ({ readGoogleProvider: fixture.readGoogleProvider, googleProviderCredentials: async (stored: { enabled: boolean; clientId: string }) => stored.enabled ? { clientId: stored.clientId, clientSecret: "fixture-direct-secret" } : undefined }));
vi.mock("../auth-policy/storage", () => ({ readAuthPolicy: fixture.readAuthPolicy }));
vi.mock("../domains/hosting", () => ({ resolveHostedBinding: fixture.resolveHostedBinding }));
vi.mock("./project-engine-writer-lease", async (original) => {
	const implementation = await original<typeof import("./project-engine-writer-lease")>();
	return {
		...implementation,
		createProjectEngineWriterLease: vi.fn(() => ({
			withCurrent: async (work: (lease: typeof fixture.admitted) => Promise<unknown>) =>
				work({ ...fixture.admitted }),
		})),
	};
});
vi.mock("./owned-project-runtime-factory", () => ({
	createOwnedProjectRuntimeCandidate: fixture.createOwned,
}));
vi.mock("./registry", () => ({ getProject: fixture.getProject, projectBrokerSecret: async () => "fixture-broker-secret" }));
vi.mock("../auth", () => ({ auth: {}, createAuth: fixture.createAuth, getAuthEnvironment: async () => ({}), postgresDatabase: () => ({ fixture: true }) }));
vi.mock("pg", () => ({ Pool: vi.fn(function fixturePool() { return { on: vi.fn(), end: fixture.end }; }) }));

const environment: AuthEnvironment = { BETTER_AUTH_URL: "https://allauth.example", BETTER_AUTH_SECRET: "fixture-runtime-auth-secret-longer-than-thirty-two", SCIM_CREDENTIAL_HASH_SECRET: "fixture-runtime-scim-secret-longer-than-thirty-two", DATABASE_URL: "postgres://fixture:fixture@127.0.0.1:1/never-connected" };
const project = (): Project => ({ id: "fixture-runtime-project", slug: "fixture-app", name: "Fixture App", schemaName: "allauth_project_0123456789abcdef0123456789abcdef", applicationId: "fixture-application", workspaceId: "7046c686-3816-42ae-82e3-ad71b96d3282", environment: "production", primaryOrigin: "https://app.example", origins: ["https://app.example"], brokerClientId: "fixture-broker", brokerSecret: "fixture-encrypted", proxyVersion: "old-proxy-version", createdBy: "fixture-owner", createdAt: new Date(), updatedAt: new Date() });
afterEach(async () => {
	await closeProjectInstances();
	fixture.admitted = { writer: "legacy", revision: 0 };
	vi.clearAllMocks();
});

describe("project runtime transport rotation", () => {
	it("rebuilds origin trust and RP options when registry origins change without policy or credential rotation", async () => {
		fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		const first = project(), changed = { ...first, primaryOrigin: "https://staging.example", origins: ["https://staging.example", "http://localhost:5100"] };
		fixture.getProject.mockResolvedValueOnce(first).mockResolvedValueOnce(changed).mockResolvedValueOnce({ ...changed, origins: [...changed.origins].reverse() });
		let original: unknown, rebuilt: unknown;
		await withProjectAuth(first.slug, async (instance) => { original = instance; }, environment);
		await withProjectAuth(first.slug, async (instance) => { rebuilt = instance; expect(instance).not.toBe(original); }, environment);
		await withProjectAuth(first.slug, async (instance) => { expect(instance).toBe(rebuilt); }, environment);
		expect(fixture.createAuth).toHaveBeenCalledTimes(2);
		expect(fixture.createAuth.mock.calls[1]?.[2]).toMatchObject({ primaryOrigin: changed.primaryOrigin, origins: changed.origins });
	});
	it("uses each request's fresh registry version without rebuilding the native auth instance or pool", async () => {
		fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		const first = project(); const rotated = { ...first, proxyVersion: "rotated-proxy-version", updatedAt: new Date(Date.now() + 1) }; fixture.getProject.mockResolvedValueOnce(first).mockResolvedValueOnce(rotated);
		let original: unknown;
		await withProjectAuth(first.slug, async (instance, _env, current) => { original = instance; expect(current.proxyVersion).toBe("old-proxy-version"); }, environment);
		await withProjectAuth(first.slug, async (instance, _env, current) => { expect(instance).toBe(original); expect(current.proxyVersion).toBe("rotated-proxy-version"); expect(current).toBe(rotated); }, environment);
		expect(fixture.createAuth).toHaveBeenCalledTimes(1); expect(fixture.getProject).toHaveBeenCalledTimes(2); expect(fixture.end).not.toHaveBeenCalled();
	});
	it("rebuilds the native instance in the same process when only its stored policy version changes", async () => {
		const current = project(); fixture.getProject.mockResolvedValue(current);
		const initial = defaultStoredAuthPolicy(); const changed = { version: 1, policy: { ...initial.policy, signUpEnabled: false, sessionExpiresInSeconds: 1800, passwordPolicy: { ...initial.policy.passwordPolicy, minLength: 6, requireNumber: true } }, updatedAt: new Date().toISOString() };
		fixture.readAuthPolicy.mockResolvedValueOnce(initial).mockResolvedValueOnce(changed).mockResolvedValueOnce(changed);
		let original: unknown; let rebuilt: unknown;
		await withProjectAuth(current.slug, async (instance) => { original = instance; }, environment);
		await withProjectAuth(current.slug, async (instance) => { rebuilt = instance; expect(instance).not.toBe(original); }, environment);
		await withProjectAuth(current.slug, async (instance) => { expect(instance).toBe(rebuilt); }, environment);
		expect(fixture.createAuth).toHaveBeenCalledTimes(2);
		expect(fixture.createAuth.mock.calls[1]?.[3]).toEqual(changed.policy);
	});
	it("rebuilds only this environment's native provider when its credential settings version changes", async () => {
		const current = project(); fixture.getProject.mockResolvedValue(current);
		fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		fixture.readGoogleProvider.mockResolvedValueOnce({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null })
			.mockResolvedValue({ version: 1, enabled: true, clientId: "tenant.apps.googleusercontent.com", encryptedClientSecret: "fixture-encrypted", updatedAt: new Date().toISOString() });
		let previous: unknown;
		await withProjectAuth(current.slug, async (instance) => { previous = instance; }, environment);
		await withProjectAuth(current.slug, async (instance) => { expect(instance).not.toBe(previous); }, environment);
		expect(fixture.createAuth).toHaveBeenCalledTimes(2);
		expect(fixture.createAuth.mock.calls[1]?.[2]).toMatchObject({ google: { clientId: "tenant.apps.googleusercontent.com", clientSecret: "fixture-direct-secret" } });
	});

});

describe("Apple runtime isolation", () => {
	it("rebuilds only when this exact environment's Apple signing configuration changes", async () => {
		const current = project(); fixture.getProject.mockResolvedValue(current);fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		fixture.readGoogleProvider.mockResolvedValue({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null });
		const provider = { clientId: "com.fixture.web", teamId: "TEAM123456", keyId: "KEY1234567", privateKey: `-----BEGIN PRIVATE KEY-----\n${"A".repeat(100)}\n-----END PRIVATE KEY-----` };
		const configured = { ...environment, ALLAUTH_PROJECT_APPLE_PROVIDERS: JSON.stringify({ [current.slug]: provider }) };
		let original: unknown;
		await withProjectAuth(current.slug, async instance => { original = instance; }, configured);
		await withProjectAuth(current.slug, async instance => { expect(instance).toBe(original); }, { ...configured, ALLAUTH_PROJECT_APPLE_PROVIDERS: JSON.stringify({ [current.slug]: provider, "another-environment": { ...provider, keyId: "OTHER12345" } }) });
		await withProjectAuth(current.slug, async instance => { expect(instance).not.toBe(original); }, { ...configured, ALLAUTH_PROJECT_APPLE_PROVIDERS: JSON.stringify({ [current.slug]: { ...provider, keyId: "OTHER12345" } }) });
		expect(fixture.createAuth).toHaveBeenCalledTimes(2);
		expect(fixture.createAuth.mock.calls[1]?.[2]).toMatchObject({ apple: { ...provider, keyId: "OTHER12345" } });
	});
});

describe("Microsoft runtime isolation", () => {
	it("rebuilds only when this exact environment's Microsoft credentials or account restriction changes", async () => {
		const current = project(); fixture.getProject.mockResolvedValue(current); fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		fixture.readGoogleProvider.mockResolvedValue({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null });
		const provider = { clientId: "7fa3f49c-1fa6-43df-8e2c-b3aff4bd9d0e", clientSecret: "fixture-microsoft-private-secret", tenantId: "common" };
		const configured = { ...environment, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ [current.slug]: provider }) };
		let original: unknown;
		await withProjectAuth(current.slug, async instance => { original = instance; }, configured);
		await withProjectAuth(current.slug, async instance => { expect(instance).toBe(original); }, { ...configured, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ [current.slug]: provider, "another-environment": { ...provider, clientSecret: "another-private-secret" } }) });
		await withProjectAuth(current.slug, async instance => { expect(instance).not.toBe(original); }, { ...configured, ALLAUTH_PROJECT_MICROSOFT_PROVIDERS: JSON.stringify({ [current.slug]: { ...provider, tenantId: "organizations" } }) });
		expect(fixture.createAuth).toHaveBeenCalledTimes(2);
		expect(fixture.createAuth.mock.calls[1]?.[2]).toMatchObject({ microsoft: { ...provider, tenantId: "organizations" } });
	});
});

describe("native passkey policy cache isolation", () => {
	it("rebuilds for only this immutable environment's signing policy and keeps its capability scoped", async () => {
		const current = { ...project(), id: "7046c686-3816-42ae-82e3-ad71b96d3282" }; fixture.getProject.mockResolvedValue(current); fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		fixture.readGoogleProvider.mockResolvedValue({ version: 0, enabled: false, clientId: "", encryptedClientSecret: "", updatedAt: null });
		const native = { enabled: true, projectId: current.id, environment: current.environment, rpOrigin: current.primaryOrigin, ios: { teamId: "TESTTEAM01", bundleId: "com.nativeapp.mobile" }, android: [] };
		const configured = { ...environment, ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [current.slug]: native }) };
		let first: unknown;
		await withProjectAuth(current.slug, async instance => { first = instance; }, configured);
		await withProjectAuth(current.slug, async instance => { expect(instance).toBe(first); }, { ...configured, ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [current.slug]: native, another: { enabled: true } }) });
		await withProjectAuth(current.slug, async instance => { expect(instance).not.toBe(first); }, { ...configured, ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [current.slug]: { ...native, ios: { ...native.ios, teamId: "OTHER12345" } } }) });
		expect(fixture.createAuth).toHaveBeenCalledTimes(2); expect(fixture.createAuth.mock.calls[0]?.[2]).toMatchObject({ nativePasskeys: { enabled: true, ios: true, android: false, rpId: "app.example" } });
	});
});

describe("protected internal project writer selection", () => {
	it("rebuilds the active candidate when the project's configured aliases change", async () => {
		const id = "8d0da368-94b3-4897-988e-39c320a3e852";
		const internal: Project = {
			...project(),
			id,
			schemaName: `allauth_project_${id.replaceAll("-", "")}`,
			workspaceId: platformWorkspaceId,
			environment: "development",
		};
		const aliasSetting = projectEmailAliasVariable(internal.slug);
		const selected = {
			...environment,
			ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id,
			[aliasSetting]: '{"old@example.test":"first-fixture-user"}',
		};
		fixture.getProject.mockResolvedValue(internal);
		fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		fixture.admitted = { writer: "allauth", revision: 1 };
		const engine = (env: AuthEnvironment) => withProjectAuthEngine(
			internal.slug, async ({ engine }) => engine, env,
		);
		const initial = await engine(selected);
		expect(await engine({ ...selected })).toBe(initial);
		const updated = await engine({ ...selected, [aliasSetting]: '{"old@example.test":"second-fixture-user"}' });
		expect(updated).not.toBe(initial);
		expect(fixture.createOwned).toHaveBeenCalledTimes(2);
	});

	it("selects the exact development realm and its verified hosted transport, then restores legacy", async () => {
		const id = "8d0da368-94b3-4897-988e-39c320a3e852";
		const internal: Project = {
			...project(),
			id,
			schemaName: `allauth_project_${id.replaceAll("-", "")}`,
			workspaceId: platformWorkspaceId,
			environment: "development",
		};
		const selected = { ...environment, ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id };
		fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
		const dispatch = (realm: Project, settings: AuthEnvironment) => {
			fixture.getProject.mockResolvedValueOnce(realm);
			return withProjectAuthEngine(
				realm.slug,
				({ engine }) => engine.dispatch(new Request("https://allauth.example/request")),
				settings,
			);
		};
		expect((await dispatch(internal, environment)).status).toBe(204);
		expect((await dispatch(internal, selected)).status).toBe(204);
		fixture.admitted = { writer: "allauth", revision: 1 };
		expect((await dispatch(internal, selected)).status).toBe(202);
		const hostname = "accounts.internal.fixture.example";
		const hosted = await withHostedProjectAuthEngine(
			internal,
			hostname,
			(engine) => engine.dispatch(new Request(`https://${hostname}/api/auth/get-session`)),
			selected,
		);
		expect(hosted.status).toBe(202);
		await expect(dispatch(internal, environment)).rejects.toThrow("The internal project writer is unavailable.");
		for (const rejected of [
			{ ...internal, workspaceId: project().workspaceId },
			{ ...internal, environment: "production" as const },
			{ ...internal, schemaName: project().schemaName },
			{ ...internal, id: "0953c4f5-a783-4e91-9055-a05ead278cd0" },
		])
			expect((await dispatch(rejected, selected)).status).toBe(204);
		await expect(dispatch(internal, { ...selected, ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: `${id},*` }))
			.rejects.toThrow("The internal project writer is unavailable.");
		fixture.admitted = { writer: "legacy", revision: 2 };
		expect((await dispatch(internal, selected)).status).toBe(204);
		expect((await dispatch(internal, environment)).status).toBe(204);
		expect(fixture.createOwned).toHaveBeenCalledTimes(2);
		expect(fixture.createOwned.mock.calls[0]?.[0]).toMatchObject({
			project: { id, workspaceId: platformWorkspaceId },
			transport: { kind: "direct" },
		});
		expect(fixture.createOwned.mock.calls[1]?.[0]).toMatchObject({
			project: { id, workspaceId: platformWorkspaceId },
			transport: { kind: "hosted", origin: `https://${hostname}` },
		});
	});
});

it("rejects readiness when either verified transport loses the exact internal realm", async () => {
	const id = "8d0da368-94b3-4897-988e-39c320a3e852";
	const internal: Project = {
		...project(),
		id,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		workspaceId: platformWorkspaceId,
		environment: "development",
	};
	const selected = { ...environment, ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id };
	const query = vi.fn(async (sql: string) => ({ rows: sql.includes('"allauthCustomHostname"') ? [] : [{ slug: internal.slug, webhookGuardInstalled: true }] }));
	const database = { query } as unknown as Pick<Pool, "query">;
	query.mockResolvedValueOnce({ rows: [{ slug: internal.slug, webhookGuardInstalled: false }] });
	await expect(verifyInternalProjectEngineReadiness(database, selected))
		.rejects.toThrow("The project webhook writer migration is unavailable.");
	const hostname = "fixture-app-accounts.allauth.co";
	fixture.getProject.mockReset().mockResolvedValue(internal);
	fixture.resolveHostedBinding.mockResolvedValueOnce({
		kind: "accounts", hostname, project: { ...internal, schemaName: project().schemaName },
	});
	await expect(verifyInternalProjectEngineReadiness(database, selected)).rejects.toThrow(
		"The internal project accounts hostname is unavailable.",
	);
	expect(fixture.createOwned).not.toHaveBeenCalled();
	fixture.resolveHostedBinding.mockResolvedValueOnce({ kind: "accounts", hostname, project: internal });
	fixture.getProject
		.mockResolvedValueOnce(internal)
		.mockResolvedValueOnce({ ...internal, id: "0953c4f5-a783-4e91-9055-a05ead278cd0" });
	const confirm = vi.spyOn(projectRuntime, "confirmInternalProjectEngine").mockResolvedValue(undefined);
	try {
		await expect(verifyInternalProjectEngineReadiness(database, selected)).rejects.toThrow(
			"The internal project selection changed during readiness.",
		);
		expect(confirm).toHaveBeenNthCalledWith(1, internal, selected);
		expect(confirm).toHaveBeenNthCalledWith(2, internal, selected, hostname);
	} finally {
		confirm.mockRestore();
	}
});

it("requires each active custom accounts transport to prepare the selected project", async () => {
	const id = "8d0da368-94b3-4897-988e-39c320a3e852";
	const internal: Project = {
		...project(),
		id,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		workspaceId: platformWorkspaceId,
		environment: "development",
	};
	const selected = { ...environment, ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id };
	const managed = "fixture-app-accounts.allauth.co";
	const custom = "accounts.customer.fixture.example";
	const additional = "accounts.other.fixture.example";
	let customHostnames = [custom, additional];
	const query = vi.fn(async (sql: string) => ({
		rows: sql.includes('"allauthCustomHostname"')
			? customHostnames.map((hostname) => ({ hostname }))
			: [{ slug: internal.slug, webhookGuardInstalled: true }],
	}));
	const database = { query } as unknown as Pick<Pool, "query">;
	fixture.getProject.mockReset().mockResolvedValue(internal);
	fixture.resolveHostedBinding.mockImplementation(async (hostname: string) => ({
		kind: "accounts", hostname, project: internal,
	}));
	const confirm = vi.spyOn(projectRuntime, "confirmInternalProjectEngine").mockImplementation(
		async (_project, _settings, hostname) => {
			if (hostname === custom) throw new Error("Fixture custom transport is unavailable.");
		},
	);
	try {
		await expect(verifyInternalProjectEngineReadiness(database, selected)).rejects.toThrow(
			"Fixture custom transport is unavailable.",
		);
		expect(confirm).toHaveBeenCalledWith(internal, selected);
		for (const hostname of [managed, custom, additional])
			expect(confirm).toHaveBeenCalledWith(internal, selected, hostname);
		confirm.mockResolvedValue(undefined);
		await expect(verifyInternalProjectEngineReadiness(database, selected)).resolves.toBeUndefined();
		fixture.resolveHostedBinding.mockImplementation(async (hostname: string) => ({
			kind: "accounts",
			hostname,
			project: hostname === custom ? { ...internal, id: "0953c4f5-a783-4e91-9055-a05ead278cd0" } : internal,
		}));
		await expect(verifyInternalProjectEngineReadiness(database, selected)).rejects.toThrow(
			"The internal project accounts hostname is unavailable.",
		);
		fixture.resolveHostedBinding.mockImplementation(async (hostname: string) => ({
			kind: "accounts", hostname, project: internal,
		}));
		confirm.mockImplementation(async (_project, _settings, hostname) => {
			if (hostname === managed) customHostnames = [custom];
		});
		await expect(verifyInternalProjectEngineReadiness(database, selected)).rejects.toThrow(
			"The internal project accounts hostnames changed during readiness.",
		);
	} finally {
		fixture.resolveHostedBinding.mockReset();
		confirm.mockRestore();
	}
});

it("rechecks candidate compatibility at activation and checks legacy readiness after rollback", async () => {
	const id = "8d0da368-94b3-4897-988e-39c320a3e852";
	const internal: Project = {
		...project(),
		id,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		workspaceId: platformWorkspaceId,
		environment: "development",
	};
	const env = { ...environment, ALLAUTH_PROJECT_ENGINE_INTERNAL_ID: id };
	fixture.getProject.mockResolvedValue(internal);
	fixture.readAuthPolicy.mockResolvedValue(defaultStoredAuthPolicy());
	await projectRuntime.confirmInternalProjectEngine(internal, env);
	expect(fixture.createOwned).toHaveBeenCalledTimes(1);

	fixture.admitted = { writer: "allauth", revision: 1 };
	fixture.createOwned.mockRejectedValueOnce(new Error("Incompatible persisted setting."));
	await expect(withProjectAuthEngine(internal.slug, async () => undefined, env))
		.rejects.toThrow("Incompatible persisted setting.");
	expect(fixture.createOwned).toHaveBeenCalledTimes(2);

	fixture.admitted = { writer: "legacy", revision: 2 };
	await projectRuntime.confirmInternalProjectEngine(internal, env);
	expect(fixture.createOwned).toHaveBeenCalledTimes(2);
	expect(fixture.createAuth).toHaveBeenCalledOnce();

	fixture.createOwned.mockRejectedValueOnce(new Error("Incompatible reactivation configuration."));
	await expect(projectRuntime.confirmInternalProjectEngine(internal, {
		...env, ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION: "2",
	})).rejects.toThrow("Incompatible reactivation configuration.");
	expect(fixture.createOwned).toHaveBeenCalledTimes(3);
});
