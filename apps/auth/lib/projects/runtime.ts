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
import { createBoundedProjectCache } from "./cache";
import { projectManagement } from "./management-plugin";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { projectOriginFingerprint } from "./origins";
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
interface Entry {
	auth: Instance;
	engine: AuthEngine;
	env: AuthEnvironment;
	project: Project;
	pool: Pool;
	shadowPool?: Pool;
}
const entries = createBoundedProjectCache<Entry>(8, async (entry) => {
	await Promise.all([entry.pool.end(), entry.shadowPool?.end()]);
});
const instances = new WeakMap<Instance, Entry>();

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

async function build(
	project: Project,
	environment: AuthEnvironment,
	policy: AuthPolicy,
	googleProvider: StoredGoogleProvider,
	publicOrigin?: string,
): Promise<Entry> {
	const schema = checkedProjectSchema(project.schemaName);
	const pool = new Pool({
		connectionString: setting(environment, "DATABASE_URL"),
		max: 2,
		connectionTimeoutMillis: 10000,
		idleTimeoutMillis: 10000,
		allowExitOnIdle: true,
		options: `-c search_path=${schema}`,
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
		const entry = { auth: instance, engine, env, project, pool, shadowPool };
		instances.set(instance, entry);
		return entry;
	} catch (error) {
		await Promise.all([pool.end(), shadowPool?.end()]);
		throw error;
	}
}

/** Cache and connection counts remain bounded, including when many different projects are requested. */
export async function withProjectAuth<T>(
	slug: string,
	callback: (
		instance: Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment?: AuthEnvironment,
): Promise<T> {
	const env = environment || (await getAuthEnvironment());
	const project = await getProject(slug, env);
	const [configured, googleProvider] = await Promise.all([
		readAuthPolicy(project.id, env),
		readGoogleProvider(project.id, env),
	]);
	const apple = readProjectAppleProvider(env, project.slug);
	const microsoft = readProjectMicrosoftProvider(env, project.slug);
	// Transport secrets can rotate while the native auth instance remains cached.
	// Verification must receive the registry row read for this request.
	return entries.use(
		`${project.id}:${configured.version}:shadow:${projectSessionShadowSelected(env, project)}:origins:${projectOriginFingerprint(project)}:owned-avatars:${ownedAvatarSelected(env, project.id)}:native-passkeys:${selectedNativePasskeys(env, project).version}:google:${googleProvider.version}:microsoft:${microsoftConfigurationVersion(microsoft)}:apple:${appleConfigurationVersion(apple)}:${apple ? Math.floor(Date.now() / 86400000) : 0}`,
		() => build(project, env, configured.policy, googleProvider),
		(entry) => callback(entry.auth, entry.env, project),
	);
}

export async function closeProjectInstances() {
	await entries.close();
}

/** Pair dispatch and admission with the same checked PostgreSQL project schema. */
export function withProjectAuthEngine<T>(
	slug: string,
	callback: (
		scope: ProjectAuthScope,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment?: AuthEnvironment,
): Promise<T> {
	return withProjectAuth(
		slug,
		(instance, env, project) => {
			const entry = instances.get(instance);
			if (!entry) throw new Error("Project instance is unavailable.");
			return callback(
				{
					engine: entry.engine,
					consumeAdmission: (key) => consumeProxySessionCheck(entry.pool, key),
				},
				env,
				project,
			);
		},
		environment,
	);
}

/** Callers must supply a hostname from the verified gateway/domain lookup, never a request Host alone. */
export async function withHostedProjectAuth<T>(
	project: Project,
	hostname: string,
	callback: (
		instance: Instance,
		env: AuthEnvironment,
		project: Project,
	) => Promise<T>,
	environment: AuthEnvironment,
): Promise<T> {
	const [configured, googleProvider] = await Promise.all([
		readAuthPolicy(project.id, environment),
		readGoogleProvider(project.id, environment),
	]);
	const apple = readProjectAppleProvider(environment, project.slug);
	const microsoft = readProjectMicrosoftProvider(environment, project.slug);
	const origin = `https://${hostname}`;
	return entries.use(
		`${project.id}:${configured.version}:shadow:${projectSessionShadowSelected(environment, project)}:origins:${projectOriginFingerprint(project)}:owned-avatars:${ownedAvatarSelected(environment, project.id)}:native-passkeys:${selectedNativePasskeys(environment, project, origin).version}:google:${googleProvider.version}:microsoft:${microsoftConfigurationVersion(microsoft)}:apple:${appleConfigurationVersion(apple)}:${apple ? Math.floor(Date.now() / 86400000) : 0}:${origin}`,
		() =>
			build(project, environment, configured.policy, googleProvider, origin),
		(entry) => callback(entry.auth, entry.env, project),
	);
}

/** Use the same verified custom hostname binding and project pool as hosted auth. */
export function withHostedProjectAuthEngine<T>(
	project: Project,
	hostname: string,
	callback: (engine: AuthEngine, env: AuthEnvironment) => Promise<T>,
	environment: AuthEnvironment,
): Promise<T> {
	return withHostedProjectAuth(
		project,
		hostname,
		(instance, env) => {
			const entry = instances.get(instance);
			if (!entry) throw new Error("Hosted project instance is unavailable.");
			return callback(entry.engine, env);
		},
		environment,
	);
}
