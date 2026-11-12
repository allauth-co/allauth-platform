import type { Pool } from "pg";
import { withAuth, withAuthEngine } from "../auth";
import type { AuthEngine } from "../auth-engine";
import type { AuthPolicy } from "../auth-policy/policy";
import { readAuthPolicy } from "../auth-policy/storage";
import {
	eraseOwnedAvatarsBeforeDelete,
	ownedAvatarReady,
	ownedAvatarSelected,
	storeOwnedAvatar,
} from "../avatars/lifecycle";
import { readWorkspaceEntitlements } from "../billing/entitlements";
import { readApplicationBranding } from "../branding/repository";
import { storeBrandingAsset } from "../branding/storage-client";
import { brandingStorage } from "../branding/validation";
import type { AuthEnvironment } from "../configuration";
import {
	authConfiguration,
	authOrigin,
	projectEmailEnvironment,
	setting,
} from "../configuration";
import { canonicalIP } from "../control/security-policy";
import { authenticationEmail } from "../email/authentication";
import { emailConfigured, sendAuthEmail } from "../email/send";
import { projectEmailAliasVariable } from "../project-email-aliases";
import {
	nativePasskeyCapability,
	realmPasskeyOptions,
	selectedNativePasskeys,
} from "../project-native-passkeys";
import {
	appleCallbackURL,
	readProjectAppleProvider,
} from "../project-providers/apple";
import { generateAppleClientSecret } from "../project-providers/apple-client-secret";
import {
	googleCallbackURL,
	googleClientId,
	googleClientSecret,
} from "../project-providers/google";
import {
	microsoftCallbackURL,
	readProjectMicrosoftProvider,
} from "../project-providers/microsoft";
import {
	googleProviderCredentials,
	googleProviderRepository,
} from "../project-providers/repository";
import { projectAdministrator } from "../workspaces/authorization";
import { backendCredentialRepository } from "./backend-credentials";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { readLegacyProjectKeyring } from "./legacy-project-keyring";
import { createOwnedEmailVerification } from "./owned-email-verification";
import { createOwnedProjectAppleDeletion } from "./owned-project-apple-deletion";
import { createOwnedProjectApplicationConsole } from "./owned-project-application-console";
import { createOwnedProjectEmailCallbackPolicy } from "./owned-project-email-callback";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import { createOwnedProjectOrganizationConsole } from "./owned-project-organization-console";
import { createOwnedProjectInvitationEmail } from "./owned-project-organization-email";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";
import { createOwnedProjectSCIMConsole } from "./owned-project-scim-console";
import { checkProjectOidcConfiguration } from "./owned-project-sso-oidc";
import { readStoredSsoConfiguration } from "./owned-project-sso-projection";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import type { ProjectEncryptedSamlFixtureAdmission } from "./owned-project-sso-saml-fixture-admission";
import { allowsEncryptedSamlFixtureProvider } from "./owned-project-sso-saml-fixture-admission";
import { projectSamlAcs } from "./owned-project-sso-saml-management";
import { createProjectCustomSamlTransport } from "./owned-project-sso-saml-transport";
import { ssoProviderId } from "./owned-project-sso-store";
import { createOwnedProjectUserConsole } from "./owned-project-user-console";
import type { ProjectAvatarStorage } from "./project-avatar-upload";
import { verifiedProjectRequest } from "./proxy";
import type { Project } from "./registry";
import {
	getProject,
	projectBrokerSecret,
	projectRegistryPool,
} from "./registry";
import { checkedProjectSchema, projectOrigin, projectSlug } from "./validation";

type EngineOptions = Parameters<typeof createOwnedProjectEngine>[0];
type TrustedTransport = { kind: "direct" } | { kind: "hosted"; origin: string };
type Options = {
	database: Pool;
	project: Project;
	policy: AuthPolicy;
	env: AuthEnvironment;
	/** Routing has already verified the project and the hosted binding when present. */
	transport: TrustedTransport;
	signingSecret: string;
	credentialHashSecret: string;
	trustedIP: EngineOptions["trustedIP"];
	defer(work: () => Promise<void>): void;
	/** Only the isolated fixture supplies alternate egress. */
	fetchPasswordRange?: Parameters<typeof createOwnedProjectPasswordSafety>[0];
	encryptedSamlFixture?: ProjectEncryptedSamlFixtureAdmission;
	postBackchannelLogout?: NonNullable<
		EngineOptions["backchannelLogout"]
	>["post"];
};

const authAdmission = {
	"sign-up/email": [3, 10_000],
	"sign-in/magic-link": [5, 60_000],
	"magic-link/verify": [5, 60_000],
	"email-otp/send-verification-otp": [3, 60_000],
	"sign-in/email-otp": [3, 60_000],
	"request-password-reset": [3, 60_000],
	"send-verification-email": [3, 60_000],
} as const;

async function readSupportedProviders(
	options: Options,
	baseURL: string,
	customSamlTransport: ProjectCustomSamlTransport,
) {
	const { database, project, env } = options;
	const admission = options.encryptedSamlFixture;
	if (admission) {
		const databaseURL = new URL(setting(env, "DATABASE_URL"));
		if (
			process.env.NODE_ENV !== "test" ||
			!/^postgres(?:ql)?:$/.test(databaseURL.protocol) ||
			databaseURL.hostname !== "127.0.0.1" ||
			databaseURL.port !== "55445" ||
			!/^\/allauth_hosted_[a-f0-9]{32}$/.test(databaseURL.pathname) ||
			database.options.connectionString !== databaseURL.href ||
			database.options.options !== `-c search_path=${project.schemaName}` ||
			admission.projectId !== project.id ||
			admission.schemaName !== project.schemaName
		)
			throw new Error(
				"This development project has an invalid encrypted SAML fixture binding.",
			);
	}
	if (
		project.environment !== "development" ||
		!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(project.id) ||
		project.schemaName !== `allauth_project_${project.id.replaceAll("-", "")}`
	)
		throw new Error(
			"This development project's configuration requires adapters outside the candidate scope.",
		);
	const registered = await getProject(project.slug, env);
	if (
		registered.id !== project.id ||
		registered.schemaName !== project.schemaName ||
		registered.workspaceId !== project.workspaceId ||
		registered.environment !== "development"
	)
		throw new Error(
			"The selected development project does not match its registry binding.",
		);
	const microsoft = readProjectMicrosoftProvider(env, registered.slug);
	const apple = readProjectAppleProvider(env, registered.slug);
	const storedGoogle = await googleProviderRepository(database, env).read(
		registered.id,
	);
	const google = await googleProviderCredentials(
		storedGoogle,
		registered.id,
		env,
	);
	if (google) {
		const id = googleClientId.safeParse(google.clientId);
		const secret = googleClientSecret.safeParse(google.clientSecret);
		if (
			!id.success ||
			!id.data ||
			id.data !== google.clientId ||
			!secret.success ||
			!secret.data ||
			secret.data !== google.clientSecret
		)
			throw new Error(
				"This development project's Google provider configuration is invalid.",
			);
	}
	const schema = checkedProjectSchema(project.schemaName);
	const { rows: enterprise } = await database.query<{
		id: string;
		providerId: string;
		issuer: string;
		domain: string;
		organizationId: string | null;
		oidcConfig: string | null;
		samlConfig: string | null;
	}>(
		`SELECT id,"providerId",issuer,domain,"organizationId","oidcConfig","samlConfig" FROM "${schema}"."ssoProvider"`,
	);
	if (
		admission &&
		!enterprise.some(
			(row) => row.providerId === admission.providerId && row.samlConfig,
		)
	)
		throw new Error(
			"This development project has an invalid encrypted SAML fixture binding.",
		);
	const enterpriseProviderIds = await Promise.all(
		enterprise.map(async (entry) => {
			const providerId = ssoProviderId.parse(entry.providerId);
			if (entry.samlConfig || !entry.oidcConfig) {
				const samlConfig = readStoredSsoConfiguration(entry.samlConfig);
				try {
					if (entry.oidcConfig || !samlConfig) throw new Error();
					const encrypted = allowsEncryptedSamlFixtureProvider(
						admission,
						schema,
						{ ...entry, samlConfig },
					);
					await configureProjectSamlTransport(
						{ ...entry, samlConfig },
						projectSamlAcs(baseURL, providerId),
						{
							generatedSPOnly: true,
							allowEncrypted: encrypted,
							customTransport: customSamlTransport,
							validateAll: true,
						},
					);
				} catch {
					throw new Error(
						"This development project has a configured SAML provider outside the candidate scope.",
					);
				}
				return providerId;
			}
			checkProjectOidcConfiguration({
				issuer: entry.issuer,
				oidcConfig: JSON.parse(entry.oidcConfig),
			});
			return providerId;
		}),
	);
	const providers = [
		"credential",
		"allauth",
		"siwe",
		...(google ? ["google"] : []),
		...(microsoft ? ["microsoft"] : []),
		...(apple ? ["apple"] : []),
		...enterpriseProviderIds,
	];
	const {
		rows: [snapshot],
	} = await database.query<{ incompatible: boolean }>(
		`
		SELECT (
		 EXISTS (
		  SELECT 1 FROM "${schema}"."apikey" k WHERE
		   coalesce(nullif(k."configId",''),'default') <> 'default' OR
		   NOT EXISTS (SELECT 1 FROM "${schema}"."user" u WHERE u.id=k."referenceId") OR
		   k.key !~ '^[A-Za-z0-9_-]{43}$' OR
		   k.permissions IS DISTINCT FROM '{"identity":["read"]}' OR
		   (k.metadata IS NOT NULL AND k.metadata <> 'null') OR
		   k."refillInterval" IS NOT NULL OR k."refillAmount" IS NOT NULL OR
		   k."lastRefillAt" IS NOT NULL OR k.remaining IS NOT NULL OR
		   k."rateLimitEnabled" IS DISTINCT FROM TRUE OR
		   k."rateLimitTimeWindow" IS DISTINCT FROM 60000 OR
		   k."rateLimitMax" IS DISTINCT FROM 100
		 ) OR
		 EXISTS (SELECT 1 FROM "${schema}"."agentHost") OR
		 EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint") OR
		 (NOT $2::boolean AND EXISTS (SELECT 1 FROM "${schema}"."allauthAvatarAsset" WHERE state <> 'deleted')) OR
		 EXISTS (
		  SELECT 1 FROM "${schema}"."account" a JOIN "${schema}"."user" u ON u.id=a."userId"
		  CROSS JOIN LATERAL (SELECT u."privateMetadata"->'allauthClerkMigration' AS value) provenance
		  WHERE a."providerId" <> ALL($1::text[]) AND NOT COALESCE((
		   a."providerId" IN ('google','apple') AND a.password IS NULL AND a.scope IS NULL AND
		   a."accessToken" IS NULL AND a."refreshToken" IS NULL AND a."idToken" IS NULL AND
		   a."accessTokenExpiresAt" IS NULL AND a."refreshTokenExpiresAt" IS NULL AND
		   provenance.value->'version' = '1'::jsonb AND
		   jsonb_typeof(provenance.value->'sourceInstance') = 'string' AND
		   jsonb_typeof(provenance.value->'sourceUserId') = 'string' AND
		   jsonb_typeof(provenance.value->'fingerprint') = 'string' AND
		   provenance.value->>'sourceInstance' ~ '^[A-Za-z0-9_.:-]{1,160}$' AND
		   provenance.value->>'sourceUserId' ~ '^[A-Za-z0-9_.:-]{1,160}$' AND
		   provenance.value->>'fingerprint' ~ '^[a-f0-9]{64}$' AND
		   u.id = 'clerk_' || encode(sha256(convert_to('[' || to_json($3::text)::text || ',' ||
		    to_json(provenance.value->>'sourceInstance')::text || ',' ||
		    to_json(provenance.value->>'sourceUserId')::text || ']', 'UTF8')), 'hex') AND
		   a.id = 'clerk_social_' || encode(sha256(convert_to('[' || to_json(a."providerId")::text ||
		    ',' || to_json(a."accountId")::text || ']', 'UTF8')), 'hex')
		  ), FALSE)
		 ) OR
		 EXISTS (SELECT 1 FROM "${schema}"."oauthClient" WHERE "grantTypes" IS NOT NULL AND (
		  jsonb_typeof("grantTypes") <> 'array' OR NOT "grantTypes" <@ '["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]'::jsonb
		 ))
		) AS incompatible`,
		[providers, ownedAvatarSelected(env, project.id), project.id],
	);
	if (!snapshot || snapshot.incompatible)
		throw new Error(
			"This development project has stored features outside the candidate scope.",
		);
	return { google, microsoft, apple };
}

function projectSupport(options: Options, platformOrigin: string) {
	const { project, env } = options;
	async function currentBinding() {
		const current = await getProject(project.slug, env);
		return current.id === project.id &&
			current.schemaName === project.schemaName &&
			current.workspaceId === project.workspaceId
			? current
			: null;
	}

	return {
		projectId: project.id,
		workspaceId: project.workspaceId,
		platformOrigin,
		async configuration() {
			const current = await currentBinding();
			if (!current) return null;
			const { supportAccess } = (await readAuthPolicy(current.id, env)).policy;
			if (
				!supportAccess?.enabled ||
				!current.origins.includes(new URL(supportAccess.callbackUrl).origin)
			)
				return null;
			return {
				callbackUrl: supportAccess.callbackUrl,
				proxyVersion: current.proxyVersion,
				...(supportAccess.applicationInitiated && {
					applicationInitiated: {
						...supportAccess.applicationInitiated,
						primaryOrigin: current.primaryOrigin,
					},
				}),
			};
		},
		async authorizePlatformRequest(request) {
			const current = await currentBinding();
			if (!current || request.headers.has("authorization")) return null;
			const principal = await withAuthEngine((root) =>
				root.readPrincipal(request.headers),
			);
			return projectAdministrator(current, principal, env);
		},
		async authorizeStoredActor(principal) {
			const current = await currentBinding();
			return Boolean(
				current && (await projectAdministrator(current, principal, env)),
			);
		},
		async verifyProxy(request) {
			if (!request.headers.has("allauth-proxy-signature")) return null;
			const current = await currentBinding();
			if (!current) return null;
			const verified = await verifiedProjectRequest(request, current, env);
			const origin = verified.headers.get("allauth-proxy-origin");
			return origin ? { origin, proxyVersion: current.proxyVersion } : null;
		},
	} satisfies NonNullable<EngineOptions["support"]>;
}

/** Assemble an explicitly selected internal development realm. This function does not select a runtime. */
export async function createOwnedProjectRuntimeCandidate(options: Options) {
	const { database, project, env, policy, defer } = options;
	if (
		setting(
			env,
			projectEmailAliasVariable(projectSlug.parse(project.slug)),
		).trim()
	)
		throw new Error(
			"Configured project email aliases require the legacy writer.",
		);
	const { signingSecret, encryptionKeys } = readLegacyProjectKeyring(
		options.signingSecret,
		process.env.BETTER_AUTH_SECRETS,
	);
	const platform = authOrigin(env);
	const transport = options.transport;
	const hosted = transport.kind === "hosted";
	const origin =
		transport.kind === "hosted"
			? projectOrigin.parse(transport.origin)
			: platform;
	if (hosted && (!origin.startsWith("https://") || origin === platform))
		throw new Error("Invalid project hosted binding for the candidate.");
	const basePath = hosted ? "/api/auth" : `/api/projects/${project.slug}/auth`;
	const app = projectOrigin.parse(project.primaryOrigin);
	const browserOrigin = hosted ? origin : app;
	const trustedOrigins = [...new Set([platform, app, ...project.origins])];
	const customSamlTransport = createProjectCustomSamlTransport(
		project,
		platform,
		env,
	);
	const linkBase = hosted ? `${origin}${basePath}` : `${app}/api/allauth`;
	const mailEnvironment = projectEmailEnvironment(env, project.slug);
	if (!emailConfigured(mailEnvironment))
		throw new Error(
			"The development candidate requires an approved project mail transport.",
		);
	const { google, microsoft, apple } = await readSupportedProviders(
		options,
		`${origin}${basePath}`,
		customSamlTransport,
	);
	const callbacks = {
		primaryOrigin: app,
		publicOrigin: hosted ? origin : undefined,
		basePath,
	};
	const appleOAuth =
		apple &&
		(await (async () => {
			const redirectURI = appleCallbackURL(callbacks);
			const ids = new Set(
				[apple.clientId, apple.appBundleIdentifier].filter(
					(value) => value !== undefined,
				),
			);
			const secrets = new Map(
				await Promise.all(
					[...ids].map(
						async (clientId) =>
							[
								clientId,
								await generateAppleClientSecret({ ...apple, clientId }),
							] as const,
					),
				).catch(() => {
					throw new Error(
						"This development project's Apple signing key is invalid.",
					);
				}),
			);
			return {
				clientId: apple.clientId,
				appBundleIdentifier: apple.appBundleIdentifier,
				redirectURI,
				async clientSecret(clientId: string) {
					const secret = secrets.get(clientId);
					if (!secret)
						throw new Error("Apple client is unavailable in this project.");
					return secret;
				},
			};
		})());
	const readBranding = () => readApplicationBranding(project.id, env);
	const [branding, clientSecret] = await Promise.all([
		readBranding(),
		projectBrokerSecret(project, env),
	]);
	const brand = branding.name || project.name;
	const email = { environment: mailEnvironment, branding };
	const verification = createOwnedEmailVerification({
		database,
		schemaName: project.schemaName,
		signingSecret,
	});
	const store = createProjectEngineStore(database, project.schemaName);
	const checkPasswordSafety = createOwnedProjectPasswordSafety(
		options.fetchPasswordRange,
	);
	const trustedIP = (request: Request) =>
		canonicalIP(options.trustedIP(request));
	async function admit(request: Request, operation: string) {
		const [max, windowMs] = authAdmission[
			operation as keyof typeof authAdmission
		] ?? [100, 60_000];
		return (
			(await store.transaction((client) =>
				admitOwnedProjectNativeRoute(
					client,
					trustedIP(request),
					`/${operation}`,
					{ max, windowMs },
				),
			)) ?? { allowed: true, retryAfter: 0 }
		);
	}
	const accountURL = `${browserOrigin}/account`;
	const callbackURLs = [accountURL, `${browserOrigin}/`];
	const callbackPolicy = createOwnedProjectEmailCallbackPolicy({
		browserOrigin,
		publicLinkBaseURL: linkBase,
		signingSecret,
	});
	const mailFailure = () =>
		console.error("AllAuth project authentication email delivery failed.");
	const send = ({
		to,
		subject,
		...message
	}: {
		to: string;
		subject: string;
		title: string;
		description: string;
		url: string;
		actionLabel: string;
	}) =>
		sendAuthEmail(mailEnvironment, {
			to,
			fromName: brand,
			subject,
			react: authenticationEmail({ branding, ...message }),
		});
	const native = selectedNativePasskeys(
		env,
		project,
		hosted ? origin : undefined,
	);
	const relyingParty = realmPasskeyOptions(browserOrigin, project.name, native);
	const credentials = backendCredentialRepository(projectRegistryPool(env));
	const avatarScope = {
		projectId: project.id,
		workspaceId: project.workspaceId,
		applicationId: project.applicationId,
		schemaName: project.schemaName,
	};
	const avatarStorage: ProjectAvatarStorage | undefined = ownedAvatarSelected(
		env,
		project.id,
	)
		? {
				upload: (asset, userId) =>
					storeOwnedAvatar(asset, userId, avatarScope, database, env),
				ownershipAndDeletion: () =>
					ownedAvatarReady(database, avatarScope, env),
			}
		: brandingStorage(env).available
			? { upload: (asset) => storeBrandingAsset(asset, avatarScope, env) }
			: undefined;
	const revokeAppleGrants = createOwnedProjectAppleDeletion({
		database,
		schemaName: project.schemaName,
		keys: encryptionKeys,
		configured: apple,
	});
	const readWorkspacePrincipal = (headers: Headers) =>
		withAuthEngine((root) => root.readPrincipal(headers));
	const manageOrganizationConsole = createOwnedProjectOrganizationConsole({
		database,
		project,
		managementOrigin: platform,
		readWorkspacePrincipal,
		invitationDelivery: {
			email: mailEnvironment,
			inviteLink: (id) => `${app}/account?invitation=${encodeURIComponent(id)}`,
			readBranding,
		},
	});
	const manageUserConsole = createOwnedProjectUserConsole({
		database,
		project,
		managementOrigin: platform,
		readWorkspacePrincipal,
	});
	const manageSCIMConsole = createOwnedProjectSCIMConsole({
		database,
		env,
		project,
		connector: { kind: "project-path" },
		credentialHashSecret: options.credentialHashSecret,
		readWorkspacePrincipal,
		readProjectPrincipal: (headers) => engine.readPrincipal(headers),
	});
	const engine: AuthEngine = createOwnedProjectEngine({
		database,
		project,
		policy,
		baseURL: origin,
		basePath,
		signingSecret,
		mfaKeys: encryptionKeys,
		trustedOrigins,
		trustedIP,
		appName: project.name,
		openApi: true,
		analytics: true,
		sdk: {
			avatar: avatarStorage,
			personalApiKeys: true,
			getBranding: readBranding,
			nativePasskeys: nativePasskeyCapability(native),
		},
		passkeys: {
			id: new URL(browserOrigin).hostname,
			name: project.name,
			origins: native.enabled ? native.expectedOrigins : [browserOrigin],
			requireUserVerification: relyingParty.requireUserVerification === true,
		},
		issuer: { platformOrigin: platform, errorURL: `${platform}/auth-error` },
		sso: {
			defaultErrorURL: `${platform}/auth-error`,
			tokenKeys: encryptionKeys,
			saml: "generated-sp",
			customSamlTransport,
			encryptedSamlFixture: options.encryptedSamlFixture,
		},
		scim: { credentialHashSecret: options.credentialHashSecret },
		manageSCIMConsole,
		manageOrganizationConsole,
		manageUserConsole,
		backchannelLogout: { defer, post: options.postBackchannelLogout },
		support: projectSupport(options, platform),
		walletOrigin: browserOrigin,
		oauth: {
			tokenKeys: encryptionKeys,
			defaultErrorURL: `${platform}/auth-error`,
			...(google
				? { google: { ...google, redirectURI: googleCallbackURL(callbacks) } }
				: {}),
			...(microsoft
				? {
						microsoft: {
							...microsoft,
							redirectURI: microsoftCallbackURL(callbacks),
						},
					}
				: {}),
			...(appleOAuth ? { apple: appleOAuth } : {}),
			broker: {
				clientId: project.brokerClientId,
				clientSecret,
				issuer: platform,
				discoveryURL: `${platform}/.well-known/openid-configuration`,
				redirectURI: `${linkBase}/callback/allauth`,
				hintGoogle: authConfiguration(env).google,
			},
		},
		async brokerTwoFactor(request) {
			const current = await getProject(project.slug, env);
			if (
				current.id !== project.id ||
				current.schemaName !== project.schemaName ||
				current.workspaceId !== project.workspaceId
			)
				return null;
			const verified = await verifiedProjectRequest(request, current, env);
			return {
				request: verified,
				verify: (factor) =>
					withAuth((root) =>
						projectBrokerTwoFactor(verified, current, root, platform, factor),
					),
			};
		},
		security: {
			requireTrustedIP: true,
			management: true,
			newDevice: {
				defer,
				async notify(user, device) {
					await send({
						to: user.email,
						subject: `New sign-in to ${brand}`,
						title: "New device signed in",
						description: `Hello ${user.name}, a new device signed in to ${brand}.${device.ipAddress ? ` IP address: ${device.ipAddress}.` : ""} If this was unexpected, review your sessions and change your password.`,
						url: accountURL,
						actionLabel: "Review account security",
					});
				},
			},
		},
		signUp: {
			checkPasswordSafety,
			admit,
			verification: {
				callbackURLs,
				callbackPolicy,
				defer,
				onFailure: mailFailure,
				async send(user, callbackURL) {
					const link = new URL(`${linkBase}/verify-email`);
					link.searchParams.set("token", await verification.issue(user));
					link.searchParams.set("callbackURL", callbackURL);
					await send({
						to: user.email,
						subject: `Verify your ${brand} email`,
						title: "Verify your email",
						description: `Hello ${user.name}, confirm your email address for ${brand}.`,
						url: link.href,
						actionLabel: "Verify email",
					});
				},
			},
		},
		passwordChange: { checkPasswordSafety },
		recovery: {
			publicLinkBaseURL: linkBase,
			resetCallbackURLs: [`${browserOrigin}/reset-password`],
			verificationCallbackURLs: callbackURLs,
			callbackPolicy,
			email,
			checkPasswordSafety,
			admit,
			defer,
			onDeliveryFailure: mailFailure,
		},
		emailSignIn: {
			publicLinkBaseURL: linkBase,
			callbackURLs: [...callbackURLs, `${browserOrigin}/sign-in`],
			email,
			admit,
			defer,
			onDeliveryFailure: mailFailure,
		},
		accountLinks: {
			publicLinkBaseURL: linkBase,
			defer,
			emailChange: true,
			onDeliveryFailure: mailFailure,
			async deliver({ kind, user, url }) {
				const deletion = kind === "delete-account";
				const title = deletion
					? "Confirm account deletion"
					: "Confirm email change";
				await send({
					to: user.email,
					subject: deletion
						? `Confirm deleting your ${brand} account`
						: `Confirm your ${brand} email change`,
					title,
					description: deletion
						? `Follow this link to confirm permanently deleting your ${brand} account.`
						: `Confirm changing your ${brand} account email.`,
					url,
					actionLabel: title,
				});
			},
			async beforeDelete({ user }) {
				await eraseOwnedAvatarsBeforeDelete(
					user.id,
					avatarScope,
					database,
					env,
				);
				return revokeAppleGrants(user.id);
			},
		},
		adminDeletion: {
			id: project.id,
			workspaceId: project.workspaceId,
			platformOrigin: platform,
			readWorkspacePrincipal,
		},
		organization: {
			membershipLimit: async (client) =>
				(
					await readWorkspaceEntitlements(project.workspaceId, env, {
						database: client,
					})
				).organizationMemberLimit,
			invitationEmail: createOwnedProjectInvitationEmail({
				env,
				project,
				publicOrigin: hosted ? origin : undefined,
				readBranding,
			}),
		},
		serviceDirectory: {
			projectId: project.id,
			environment: project.environment,
			authorize: (headers) => credentials.authorize(project.id, headers),
		},
	});
	return {
		...engine,
		manageApplicationConsole: createOwnedProjectApplicationConsole({
			database,
			project,
			managementOrigin: platform,
			readWorkspacePrincipal,
		}),
		dispatch(request: Request) {
			const url = new URL(request.url);
			if (request.method === "GET" && url.origin === origin) {
				if (url.pathname === `${basePath}/.well-known/openid-configuration`)
					return engine.readIssuerMetadata("openid");
				if (
					url.pathname === `${basePath}/.well-known/oauth-authorization-server`
				)
					return engine.readIssuerMetadata("oauth");
			}
			return engine.dispatch(request);
		},
	};
}
