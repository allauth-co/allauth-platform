import type { Pool } from "pg";
import { withAuth } from "../auth";
import type { AuthPolicy } from "../auth-policy/policy";
import {
	eraseOwnedAvatarsBeforeDelete,
	ownedAvatarSelected,
} from "../avatars/lifecycle";
import { readWorkspaceEntitlements } from "../billing/entitlements";
import { readApplicationBranding } from "../branding/repository";
import { brandingStorage } from "../branding/validation";
import type { AuthEnvironment } from "../configuration";
import {
	authConfiguration,
	authOrigin,
	projectEmailEnvironment,
} from "../configuration";
import { canonicalIP } from "../control/security-policy";
import { authenticationEmail } from "../email/authentication";
import { emailConfigured, sendAuthEmail } from "../email/send";
import {
	nativePasskeyCapability,
	realmPasskeyOptions,
	selectedNativePasskeys,
} from "../project-native-passkeys";
import { readProjectAppleProvider } from "../project-providers/apple";
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
import { backendCredentialRepository } from "./backend-credentials";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import { createOwnedEmailVerification } from "./owned-email-verification";
import { createOwnedProjectAppleDeletion } from "./owned-project-apple-deletion";
import { createOwnedProjectEmailCallbackPolicy } from "./owned-project-email-callback";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import { createOwnedProjectInvitationEmail } from "./owned-project-organization-email";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";
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
	trustedIP: EngineOptions["trustedIP"];
	defer(work: () => Promise<void>): void;
	/** Only the isolated fixture supplies alternate egress. */
	fetchPasswordRange?: Parameters<typeof createOwnedProjectPasswordSafety>[0];
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

async function readSupportedProviders(options: Options) {
	const { database, project, policy, env } = options;
	if (
		project.environment !== "development" ||
		!/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(project.id) ||
		project.schemaName !==
			`allauth_project_${project.id.replaceAll("-", "")}` ||
		policy.supportAccess?.enabled ||
		ownedAvatarSelected(env, project.id) ||
		brandingStorage(env).available ||
		readProjectAppleProvider(env, project.slug)
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
	const providers = [
		"credential",
		"allauth",
		...(google ? ["google"] : []),
		...(microsoft ? ["microsoft"] : []),
	];
	const schema = checkedProjectSchema(project.schemaName);
	const {
		rows: [snapshot],
	} = await database.query<{ incompatible: boolean }>(
		`
		SELECT (
		 EXISTS (SELECT 1 FROM "${schema}"."ssoProvider") OR
		 EXISTS (SELECT 1 FROM "${schema}"."scimManagedConnection") OR
		 EXISTS (SELECT 1 FROM "${schema}"."scimConnectionBinding") OR
		 EXISTS (SELECT 1 FROM "${schema}"."allauthDirectory") OR
		 EXISTS (SELECT 1 FROM "${schema}"."apikey") OR
		 EXISTS (SELECT 1 FROM "${schema}"."walletAddress") OR
		 EXISTS (SELECT 1 FROM "${schema}"."agentHost") OR
		 EXISTS (SELECT 1 FROM "${schema}"."user" WHERE "isAnonymous" IS TRUE) OR
		 EXISTS (SELECT 1 FROM "${schema}"."session" WHERE "impersonatedBy" IS NOT NULL AND "expiresAt" > now()) OR
		 EXISTS (SELECT 1 FROM "${schema}"."allauthWebhookEndpoint") OR
		 EXISTS (SELECT 1 FROM "${schema}"."allauthAvatarAsset" WHERE state <> 'deleted') OR
		 EXISTS (SELECT 1 FROM "${schema}"."account" WHERE "providerId" <> ALL($1::text[])) OR
		 EXISTS (SELECT 1 FROM "${schema}"."oauthClient" WHERE "grantTypes" IS NOT NULL AND (
		  jsonb_typeof("grantTypes") <> 'array' OR NOT "grantTypes" <@ '["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]'::jsonb
		 ))
		) AS incompatible`,
		[providers],
	);
	if (!snapshot || snapshot.incompatible)
		throw new Error(
			"This development project has stored features outside the candidate scope.",
		);
	return { google, microsoft };
}

/** Assemble an explicitly selected internal development realm. This function does not select a runtime. */
export async function createOwnedProjectRuntimeCandidate(options: Options) {
	const { database, project, env, policy, signingSecret, defer } = options;
	projectSlug.parse(project.slug);
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
	const linkBase = hosted ? `${origin}${basePath}` : `${app}/api/allauth`;
	const mailEnvironment = projectEmailEnvironment(env, project.slug);
	if (!emailConfigured(mailEnvironment))
		throw new Error(
			"The development candidate requires an approved project mail transport.",
		);
	const { google, microsoft } = await readSupportedProviders(options);
	const callbacks = {
		primaryOrigin: app,
		publicOrigin: hosted ? origin : undefined,
		basePath,
	};
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
	const revokeAppleGrants = createOwnedProjectAppleDeletion({
		database,
		schemaName: project.schemaName,
		keys: { secret: signingSecret },
		configured: readProjectAppleProvider(env, project.slug),
	});
	const engine = createOwnedProjectEngine({
		database,
		project,
		policy,
		baseURL: origin,
		basePath,
		signingSecret,
		trustedOrigins,
		trustedIP,
		appName: project.name,
		sdk: {
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
		backchannelLogout: { defer, post: options.postBackchannelLogout },
		oauth: {
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
					{
						projectId: project.id,
						workspaceId: project.workspaceId,
						applicationId: project.applicationId,
						schemaName: project.schemaName,
					},
					database,
					env,
				);
				return revokeAppleGrants(user.id);
			},
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
