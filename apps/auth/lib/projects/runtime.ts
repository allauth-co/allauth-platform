import { createHmac } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { Pool } from "pg";
import {
	auth,
	createAuth,
	getAuthEnvironment,
	postgresDatabase,
	withAuth,
	withAuthEngine,
} from "../auth";
import type { AuthEngine, ProjectAuthScope } from "../auth-engine";
import type { AuthPolicy } from "../auth-policy/policy";
import { readAuthPolicy } from "../auth-policy/storage";
import { guardAvatarUserDeletion } from "../avatars/deletion";
import {
	eraseOwnedAvatarsBeforeDelete,
	ownedAvatarReady,
	ownedAvatarSelected,
	storeOwnedAvatar,
} from "../avatars/lifecycle";
import { readApplicationBranding } from "../branding/repository";
import { guardCommercialAdapter } from "../billing/entitlements";
import { storeBrandingAsset } from "../branding/storage-client";
import { brandingStorage } from "../branding/validation";
import type { AuthEnvironment } from "../configuration";
import {
	authConfiguration,
	authOrigin,
	isPlatformAdmin,
	setting,
} from "../configuration";
import type { ControlPrincipal } from "../control";
import {
	revokeAuthenticationChallenges,
	revokeUserGrants,
} from "../enterprise";
import { legacyAuthEngine } from "../legacy-auth-engine";
import { projectEmailAliasVariable } from "../project-email-alias-config";
import {
	nativePasskeyCapability,
	selectedNativePasskeys,
} from "../project-native-passkeys";
import {
	appleConfigurationVersion,
	readProjectAppleProvider,
} from "../project-providers/apple";
import { guardAppleUserDeletion } from "../project-providers/apple-deletion";
import type { StoredGoogleProvider } from "../project-providers/google";
import {
	microsoftConfigurationVersion,
	readProjectMicrosoftProvider,
} from "../project-providers/microsoft";
import {
	googleProviderCredentials,
	readGoogleProvider,
} from "../project-providers/repository";
import {
	projectAdministrator,
	requireWorkspacePrincipal,
} from "../workspaces/authorization";
import { backendCredentialRepository } from "./backend-credentials";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { createBoundedProjectCache } from "./cache";
import { observeProjectEngine, projectEngineMetricsSelected } from "./engine-metrics";
import { projectManagement } from "./management-plugin";
import { projectOriginFingerprint } from "./origins";
import type { OwnedProjectSCIMConsole } from "./owned-project-scim-console";
import { projectSamlApprovalValue } from "./project-engine-binding";
import {
	projectAgentReplayApprovalValue,
	projectAgentReplayApproved,
	projectAgentReplayBridgeSelected,
	projectEnginePreparationRevision,
	projectEngineSelected,
	selectProjectEngine,
} from "./project-engine-internal-selection";
import { projectWriterLease } from "./project-engine-internal-writer";
import { selectRehearsalProjectEngine } from "./project-engine-rehearsal-selection";
import { projectWriterUnavailable } from "./project-engine-unavailable";
import {
	projectEngineWriterConnectionOptions,
	type ProjectEngineWriterState,
} from "./project-engine-writer-lease";
import { localizeProjectErrors } from "./project-error-localization";
import { verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import {
	getProject,
	projectBrokerSecret,
	projectRegistryPool,
} from "./registry";
import { consumeProxySessionCheck } from "./session-introspection-admission";
import { readProjectSessionPrincipal } from "./session-principal";
import { observeProjectSessions, projectSessionShadowSelected } from "./session-shadow";
import { checkedProjectSchema } from "./validation";

type Instance = ReturnType<typeof createAuth>;
interface EntryBase {
	engine: AuthEngine;
	env: AuthEnvironment;
	project: Project;
	pool: Pool;
}
interface LegacyEntry extends EntryBase {
	kind: "legacy";
	auth: Instance;
	shadowPool?: Pool;
}
type Entry = LegacyEntry | (EntryBase & { kind: "owned" });
const entries = createBoundedProjectCache<Entry>(8, async (entry) => {
	await Promise.all([
		entry.pool.end(),
		entry.kind === "legacy" ? entry.shadowPool?.end() : undefined,
	]);
});
const instances = new WeakMap<Instance, LegacyEntry>();

/** Assemble a realm's selected engine with the same authority as the legacy runtime. */
export type ProjectEngineBuilder = (input: {
	database: Pool;
	project: Project;
	policy: AuthPolicy;
	baseURL: string;
	basePath: string;
	signingSecret: string;
	credentialHashSecret: string;
}) => AuthEngine | Promise<AuthEngine>;

interface IsolatedProjectEngineFixture {
	projectId: string;
	schemaName: string;
	databaseURL: string;
	build: ProjectEngineBuilder;
}

let fixture: Readonly<IsolatedProjectEngineFixture> | undefined;
let projectRuntimeStarted = false;

/** Install once, before any project is used, in a disposable local test process. */
export function installIsolatedProjectEngineFixture(
	selection: IsolatedProjectEngineFixture,
) {
	const url = new URL(selection.databaseURL);
	if (
		process.env.NODE_ENV !== "test" ||
		fixture ||
		projectRuntimeStarted ||
		!/^postgres(?:ql)?:$/.test(url.protocol) ||
		url.hostname !== "127.0.0.1" ||
		url.port !== "55445" ||
		!/^\/allauth_hosted_[a-f0-9]{32}$/.test(url.pathname) ||
		!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(selection.projectId) ||
		selection.schemaName !== `allauth_project_${selection.projectId.replaceAll("-", "")}`
	)
		throw new Error("The owned project engine fixture requires a new isolated development realm.");
	fixture = Object.freeze({ ...selection, databaseURL: url.href });
}

function fixtureFor(project: Project, env: AuthEnvironment) {
	if (!fixture || fixture.projectId !== project.id) return;
	if (
		project.environment !== "development" ||
		project.schemaName !== fixture.schemaName ||
		new URL(setting(env, "DATABASE_URL")).href !== fixture.databaseURL
	)
		throw new APIError("SERVICE_UNAVAILABLE", { message: "The selected project fixture is unavailable." });
	return fixture;
}

function legacyInstance(entry: Entry) {
	if (entry.kind !== "legacy")
		throw new APIError("SERVICE_UNAVAILABLE", {
			message: "This operation is unavailable in the selected authentication realm.",
		});
	return entry.auth;
}

/** Platform authority is read afresh from the platform DB, never copied from a project role. */
export async function platformProjectAdministrator(
	headers: Headers,
): Promise<ControlPrincipal | null> {
	const current = await withAuthEngine((engine) =>
		engine.readPrincipal(headers),
	);
	return current && isPlatformAdmin(current.user, current.session)
		? current
		: null;
}
export const projectInstance = (instance: Instance) => instances.get(instance);

/** Workspace authority applies only to this selected realm and is checked on every request. */
export async function selectedProjectAdministrator(
	project: Project,
	headers: Headers,
	env: AuthEnvironment,
): Promise<ControlPrincipal | null> {
	try {
		const principal = await runWithAdapter((await auth.$context).adapter, () =>
			requireWorkspacePrincipal(auth, headers),
		);
		return await projectAdministrator(project, principal, env);
	} catch (error) {
		if (error instanceof APIError) return null;
		throw error;
	}
}

/** Distinct keys isolate signed cookies, encrypted credentials, and security counters. */
export function projectSecret(env: AuthEnvironment, projectId: string): string {
	return createHmac("sha256", setting(env, "BETTER_AUTH_SECRET"))
		.update(`allauth:project:${projectId}`)
		.digest("hex");
}

function bindOwnedDirectTransport(engine: AuthEngine, origin: string): AuthEngine {
	function bind(request: Request) {
		const incoming = new URL(request.url);
		if (incoming.origin === origin) return request;
		// Standalone Next may use the listener address in Request.url. The project
		// route already selects the realm and verifies signed requests before dispatch.
		const url = new URL(origin);
		url.pathname = incoming.pathname;
		url.search = incoming.search;
		return new Request(url, request);
	}
	return {
		...engine,
		dispatch: (request) => engine.dispatch(bind(request)),
		readSession: (request) => engine.readSession(bind(request)),
	};
}

async function build(
	project: Project,
	environment: AuthEnvironment,
	policy: AuthPolicy,
	googleProvider: StoredGoogleProvider,
	publicOrigin?: string,
	owned?: ProjectEngineBuilder,
	writer?: ProjectEngineWriterState,
): Promise<Entry> {
	const schema = checkedProjectSchema(project.schemaName);
	const pool = new Pool({
		connectionString: setting(environment, "DATABASE_URL"),
		max: 2,
		connectionTimeoutMillis: 10000,
		idleTimeoutMillis: 10000,
		allowExitOnIdle: true,
		options: writer
			? `-c search_path=${schema} ${projectEngineWriterConnectionOptions(project.id, writer)}`
			: `-c search_path=${schema}`,
	});
	pool.on("error", () =>
		console.error("AllAuth project database connection error."),
	);
	let shadowPool: Pool | undefined;
	const secret = projectSecret(environment, project.id);
	const env = {
		...environment,
		ALLAUTH_AUTH_SECRET: secret,
		BETTER_AUTH_SECRET: secret,
		SCIM_CREDENTIAL_HASH_SECRET: createHmac(
			"sha256",
			setting(environment, "SCIM_CREDENTIAL_HASH_SECRET"),
		)
			.update(project.id)
			.digest("hex"),
	};
	try {
		const basePath = publicOrigin
			? "/api/auth"
			: `/api/projects/${project.slug}/auth`;
		const metricsEnabled = projectEngineMetricsSelected(environment, project.id);
		const observe = (engine: AuthEngine, writer: "legacy" | "allauth") =>
			metricsEnabled ? observeProjectEngine(engine, {
				projectId: project.id,
				writer,
				transport: publicOrigin ? "hosted" : "project",
				basePath,
			}) : engine;
		if (owned) {
			const baseURL = publicOrigin ?? authOrigin(environment);
			const engine = await owned({
				database: pool,
				project,
				policy,
				baseURL,
				basePath,
				signingSecret: secret,
				credentialHashSecret: env.SCIM_CREDENTIAL_HASH_SECRET,
			});
			const boundEngine = publicOrigin
				? engine
				: bindOwnedDirectTransport(engine, baseURL);
			return {
				kind: "owned",
				engine: observe(localizeProjectErrors(boundEngine), "allauth"),
				env,
				project,
				pool,
			};
		}
		const requirePlatformAdmin = async (ctx: GenericEndpointContext) => {
			const currentProject = await getProject(project.slug, environment);
			const principal = await selectedProjectAdministrator(
				currentProject,
				ctx.headers || new Headers(),
				environment,
			);
			if (!principal)
				throw new APIError("FORBIDDEN", {
					message: "A workspace owner or administrator is required.",
				});
			return principal;
		};
		const google = await googleProviderCredentials(
			googleProvider,
			project.id,
			environment,
		);
		const apple = readProjectAppleProvider(environment, project.slug);
		const microsoft = readProjectMicrosoftProvider(environment, project.slug);
		const nativePasskeys = selectedNativePasskeys(
			environment,
			project,
			publicOrigin,
		);
		const avatarScope = {
			projectId: project.id,
			workspaceId: project.workspaceId,
			applicationId: project.applicationId,
			schemaName: project.schemaName,
		};
		const ownedAvatars = ownedAvatarSelected(environment, project.id);
		const instance = createAuth(
			postgresDatabase(pool),
			env,
			{
				...(projectAgentReplayBridgeSelected(project, environment)
					? { agentReplayBridge: { projectId: project.id, database: pool } }
					: {}),
				...(google ? { google } : {}),
				...(apple ? { apple } : {}),
				...(microsoft ? { microsoft } : {}),
				nativePasskeys,
				name: project.name,
					workspaceId: project.workspaceId,
				slug: project.slug,
				basePath,
				cookiePrefix: `allauth_project_${project.slug}`,
				primaryOrigin: project.primaryOrigin,
				origins: project.origins,
				publicOrigin,
				getBranding: () => readApplicationBranding(project.id, environment),
				broker: {
					clientId: project.brokerClientId,
					clientSecret: await projectBrokerSecret(project, environment),
				},
				authorizeAdmin: (headers) =>
					selectedProjectAdministrator(project, headers, environment),
				beforeDeleteUser: (userId) =>
					eraseOwnedAvatarsBeforeDelete(userId, avatarScope, pool, environment),
				management: projectManagement({
					async brokerTwoFactor(request, body) {
						const current = await getProject(project.slug, environment);
						if (!request.headers.has("allauth-proxy-signature"))
							throw new APIError("FORBIDDEN");
						const verified = await verifiedProjectRequest(
							request, current, environment,
						);
						return withAuth(platform => projectBrokerTwoFactor(
							verified, current, platform, authOrigin(environment), body,
						));
					},
					directory: {
						project: project.slug,
						projectId: project.id,
						environment: project.environment,
						authorize: (headers) =>
							backendCredentialRepository(
								projectRegistryPool(environment),
							).authorize(project.id, headers),
					},
					beforeDeleteUser: (userId) =>
						eraseOwnedAvatarsBeforeDelete(
							userId,
							avatarScope,
							pool,
							environment,
						),
					nativePasskeys: nativePasskeyCapability(nativePasskeys),
					projectId: project.id,
					projectSlug: project.slug,
					baseURL: authOrigin(environment),
					googleEnabled: authConfiguration(environment).google,
					getBranding: () => readApplicationBranding(project.id, environment),
					...(ownedAvatars
						? {
								avatarOwnershipAndDeletion: () =>
									ownedAvatarReady(pool, avatarScope, environment),
								uploadAvatar: (asset, userId) =>
									storeOwnedAvatar(
										asset,
										userId,
										avatarScope,
										pool,
										environment,
									),
							}
						: brandingStorage(environment).available
							? {
									uploadAvatar: (asset) =>
										storeBrandingAsset(
											asset,
											{
												workspaceId: project.workspaceId,
												applicationId: project.applicationId,
											},
											environment,
										),
								}
							: {}),
					requirePlatformAdmin,
					support: {
						projectId: project.id,
						projectSlug: project.slug,
						workspaceId: project.workspaceId,
						platformOrigin: authOrigin(environment),
						requirePlatformAdmin,
						configuration: async () => {
							const currentProject = await getProject(
								project.slug,
								environment,
							);
							const access = (await readAuthPolicy(project.id, environment))
								.policy.supportAccess;
							if (
								!access?.enabled ||
								!currentProject.origins.includes(
									new URL(access.callbackUrl).origin,
								)
							)
								return null;
							return {
								callbackUrl: access.callbackUrl,
								proxyVersion: currentProject.proxyVersion,
								...(access.applicationInitiated
									? {
											applicationInitiated: {
												...access.applicationInitiated,
												primaryOrigin: currentProject.primaryOrigin,
											},
										}
									: {}),
							};
						},
						authorizeStoredActor: async (principal) => {
							if (
								!(await projectAdministrator(
									await getProject(project.slug, environment),
									principal,
									environment,
								))
							)
								throw new APIError("FORBIDDEN");
						},
						verifyProxy: async (request) => {
							if (!request.headers.has("allauth-proxy-signature"))
								throw new APIError("FORBIDDEN");
							const currentProject = await getProject(
								project.slug,
								environment,
							);
							await verifiedProjectRequest(
								request,
								currentProject,
								environment,
							);
							return {
								origin: request.headers.get("allauth-proxy-origin")!,
								proxyVersion: currentProject.proxyVersion,
							};
						},
					},
					async onRevokeUser(adapter, userId) {
						await revokeUserGrants(adapter, userId);
						await revokeAuthenticationChallenges(adapter, userId);
					},
				}),
			},
			policy,
		);
		guardAppleUserDeletion(await instance.$context, apple);
		guardCommercialAdapter((await instance.$context).adapter);
		guardAvatarUserDeletion(
			(await instance.$context).internalAdapter,
			(userId) =>
				eraseOwnedAvatarsBeforeDelete(userId, avatarScope, pool, environment),
		);
		const legacy = legacyAuthEngine(instance);
		let engine = legacy;
		if (projectSessionShadowSelected(environment, project)) {
			const context = await instance.$context;
			const shadow = new Pool({
				connectionString: setting(environment, "DATABASE_URL"),
				max: 1,
				connectionTimeoutMillis: 150,
				idleTimeoutMillis: 5000,
				statement_timeout: 100,
				allowExitOnIdle: true,
				options: "-c default_transaction_read_only=on",
			});
			shadow.on("error", () => console.error("AllAuth project session comparison connection error."));
			shadowPool = shadow;
			engine = observeProjectSessions(legacy, {
				projectId: project.id,
				basePath,
				read: (headers) => readProjectSessionPrincipal(shadow, project, headers, {
					signingSecret: context.secret,
					secureCookies: context.authCookies.sessionToken.attributes.secure === true,
				}),
			});
		}
		const entry: LegacyEntry = { kind: "legacy", auth: instance, engine: observe(engine, "legacy"), env, project, pool, shadowPool };
		instances.set(instance, entry);
		return entry;
	} catch (error) {
		await Promise.all([pool.end(), shadowPool?.end()]);
		throw error;
	}
}

/** Cache and connection counts remain bounded, including when many different projects are requested. */
async function withProjectEntry<T>(
	project: Project,
	env: AuthEnvironment,
	publicOrigin: string | undefined,
	callback: (entry: Entry, project: Project) => Promise<T>,
): Promise<T> {
	projectRuntimeStarted = true;
	const rehearsal =
		fixtureFor(project, env)?.build ??
		(await selectRehearsalProjectEngine(project, env));
	if (rehearsal)
		return withConfiguredProjectEntry(project, env, publicOrigin, callback, rehearsal);
	const lease = projectWriterLease(project, env);
	if (!lease) return withConfiguredProjectEntry(project, env, publicOrigin, callback);
	return lease.withCurrent(({ writer, revision }) => {
		const candidate = writer === "allauth"
			? selectProjectEngine(project, env, { revision, preparing: false })
			: undefined;
		if (writer === "allauth" && !candidate)
			throw projectWriterUnavailable();
		return withConfiguredProjectEntry(
			project, env, publicOrigin, callback, candidate, { writer, revision },
		);
	});
}

async function withConfiguredProjectEntry<T>(
	project: Project,
	env: AuthEnvironment,
	publicOrigin: string | undefined,
	callback: (entry: Entry, project: Project) => Promise<T>,
	owned?: ProjectEngineBuilder,
	writer?: ProjectEngineWriterState,
	preparing = false,
) {
	const [configured, googleProvider] = await Promise.all([
		readAuthPolicy(project.id, env),
		readGoogleProvider(project.id, env),
	]);
	const apple = readProjectAppleProvider(env, project.slug);
	const microsoft = readProjectMicrosoftProvider(env, project.slug);
	const aliasConfiguration = owned && setting(env, projectEmailAliasVariable(project.slug));
	const aliasVersion = aliasConfiguration
		? createHmac("sha256", setting(env, "ALLAUTH_AUTH_SECRET"))
				.update(aliasConfiguration)
				.digest("hex")
		: "";
	const samlApproval = owned && writer && projectSamlApprovalValue(project, env);
	const samlApprovalVersion = samlApproval
		? createHmac("sha256", setting(env, "ALLAUTH_AUTH_SECRET")).update(samlApproval).digest("hex")
		: "";
	const agentApproval = owned && writer && projectAgentReplayApprovalValue(project, env);
	const agentApprovalVersion = agentApproval
		? createHmac("sha256", setting(env, "ALLAUTH_AUTH_SECRET")).update(agentApproval).digest("hex")
		: "";
	const agentBridge = projectAgentReplayBridgeSelected(project, env);
	// Transport secrets can rotate while the native auth instance remains cached.
	// Verification must receive the registry row read for this request.
	return entries.use(
		`${project.id}:${configured.version}:engine:${preparing ? "preflight:" : ""}${writer ? `${writer.writer}:${writer.revision}` : owned ? "owned-fixture" : "legacy"}:metrics:${projectEngineMetricsSelected(env, project.id)}:shadow:${projectSessionShadowSelected(env, project)}:origins:${projectOriginFingerprint(project)}:owned-avatars:${ownedAvatarSelected(env, project.id)}:native-passkeys:${selectedNativePasskeys(env, project, publicOrigin).version}:google:${googleProvider.version}:microsoft:${microsoftConfigurationVersion(microsoft)}:apple:${appleConfigurationVersion(apple)}:${apple ? Math.floor(Date.now() / 86400000) : 0}:aliases:${aliasVersion}:saml:${samlApprovalVersion}:agent:${agentBridge}:${agentApprovalVersion}:${publicOrigin ?? ""}`,
		() => build(project, env, configured.policy, googleProvider, publicOrigin, owned, writer),
		(entry) => callback(entry, project),
	);
}

async function withDirectProjectEntry<T>(
	slug: string,
	callback: (entry: Entry, project: Project) => Promise<T>,
	environment?: AuthEnvironment,
) {
	const env = environment || (await getAuthEnvironment());
	const project = await getProject(slug, env);
	return withProjectEntry(project, env, undefined, callback);
}

export function withProjectAuth<T>(
	slug: string,
	callback: (
		instance: Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment?: AuthEnvironment,
): Promise<T> {
	return withDirectProjectEntry(
		slug,
		(entry, project) => callback(legacyInstance(entry), entry.env, project),
		environment,
	);
}

/** Use the selected writer for the existing directory console API. */
export function withProjectSCIMConsole(
	slug: string,
	callback: (
		manage: OwnedProjectSCIMConsole | undefined,
		readLegacy: () => Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<Response>,
) {
	return withDirectProjectEntry(slug, (entry, project) =>
		callback(
			entry.engine.manageSCIMConsole,
			() => legacyInstance(entry),
			entry.env,
			project,
		),
	);
}

/** The console uses the selected project engine and only opens a native instance in a legacy realm. */
export function withProjectOrganizationConsole(
	slug: string,
	callback: (
		manage: AuthEngine["manageOrganizationConsole"],
		readLegacy: () => Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<Response>,
) {
	return withDirectProjectEntry(slug, (entry, project) =>
		callback(
			entry.engine.manageOrganizationConsole,
			() => legacyInstance(entry),
			entry.env,
			project,
		),
	);
}

export function withProjectUserConsole(
	slug: string,
	callback: (
		manage: AuthEngine["manageUserConsole"],
		readLegacy: () => Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<Response>,
) {
	return withDirectProjectEntry(slug, (entry, project) =>
		callback(entry.engine.manageUserConsole, () => legacyInstance(entry), entry.env, project),
	);
}

export function withProjectApplicationConsole(
	slug: string,
	callback: (
		manage: AuthEngine["manageApplicationConsole"],
		readLegacy: () => Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<Response>,
) {
	return withDirectProjectEntry(slug, (entry, project) =>
		callback(entry.engine.manageApplicationConsole, () => legacyInstance(entry), entry.env, project),
	);
}

export async function closeProjectInstances() {
	await entries.close();
}

/** Pair dispatch and admission with the same checked PostgreSQL project schema. */
export async function withProjectAuthEngine<T>(
	slug: string,
	callback: (
		scope: ProjectAuthScope,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment?: AuthEnvironment,
): Promise<T> {
	const env = environment || (await getAuthEnvironment());
	return withResolvedProjectAuthEngine(await getProject(slug, env), callback, env);
}

/** Admit the same immutable registry binding used to verify the app proxy. */
export function withResolvedProjectAuthEngine<T>(
	project: Project,
	callback: (
		scope: ProjectAuthScope,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment: AuthEnvironment,
): Promise<T> {
	return withProjectEntry(project, environment, undefined, (entry, current) =>
		callback(
			{
				engine: entry.engine,
				consumeAdmission: (key) => consumeProxySessionCheck(entry.pool, key),
			},
			entry.env,
			current,
		),
	);
}

/** Callers must supply a hostname from the verified gateway/domain lookup, never a request Host alone. */
export function withHostedProjectAuth<T>(
	project: Project,
	hostname: string,
	callback: (
		instance: Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment: AuthEnvironment,
): Promise<T> {
	return withProjectEntry(
		project,
		environment,
		`https://${hostname}`,
		(entry, current) => callback(legacyInstance(entry), entry.env, current),
	);
}

/** Check the active writer and prepare a selected candidate without dispatching a request. */
export function confirmProjectEngine(
	project: Project,
	env: AuthEnvironment,
	hostname?: string,
) {
	const lease = projectWriterLease(project, env);
	if (!projectEngineSelected(env, project) || !lease)
		throw new Error("The project selection changed.");
	const origin = hostname ? `https://${hostname}` : undefined;
	return lease.withCurrent(async ({ writer, revision }) => {
		// Keep preflight separate from live cache entries. Legacy can
		// still change configuration until the database commits the switch.
		const preparing = writer === "legacy" && revision === projectEnginePreparationRevision(env, project);
		if (preparing)
			projectAgentReplayApproved(project, env, { revision, preparing });
		const useCandidate = preparing || writer === "allauth";
		const candidate = useCandidate ? selectProjectEngine(project, env, { revision, preparing }) : undefined;
		if (useCandidate && !candidate)
			throw new Error("The project writer is unavailable.");
		await withConfiguredProjectEntry(
			project,
			env,
			origin,
			async (entry) => {
				const expected = useCandidate ? "owned" : "legacy";
				if (entry.kind !== expected || !projectEngineSelected(env, entry.project))
					throw new Error("The project writer is unavailable.");
				if (entry.kind === "owned") await entry.engine.verifySamlReadiness?.();
			},
			candidate,
			preparing ? { writer: "allauth", revision: revision + 1 } : { writer, revision },
			preparing,
		);
	});
}

/** Use the same verified custom hostname binding and project pool as hosted auth. */
export function withHostedProjectAuthEngine<T>(
	project: Project,
	hostname: string,
	callback: (engine: AuthEngine, env: AuthEnvironment) => Promise<T>,
	environment: AuthEnvironment,
): Promise<T> {
	return withProjectEntry(
		project,
		environment,
		`https://${hostname}`,
		(entry) => callback(entry.engine, entry.env),
	);
}
