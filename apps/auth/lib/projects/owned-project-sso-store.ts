import { createHash, randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { DatabaseError } from "pg";
import * as z from "zod";
import { storedSamlProviderId as ssoProviderId } from "../../scripts/project-engine-saml-approval.mjs";
import { reservedProjectEmailError } from "../project-email-alias-config";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { sealLegacyMfaRecord } from "./legacy-mfa-record";
import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import { createProjectEngineStore } from "./owned-project-engine-store";
import { invalidateProjectMailboxProofs } from "./owned-project-mailbox-proofs";
import { projectOrganizations } from "./owned-project-organization-store";
import { ssoProfileRejected } from "./owned-project-sso-admission";
import { checkedProjectSchema } from "./validation";

const stateAge = 600;

export { ssoProviderId };
export const ssoReferenceSchema = z.object({
	providerId: ssoProviderId,
	source: z.object({
		type: z.literal("persisted"),
		recordId: z.string().min(1),
	}),
	authenticationConfigurationFingerprint: z
		.string()
		.regex(/^[A-Za-z0-9_-]{43}$/),
});
export const ssoStateSchema = z.object({
	callbackURL: z.string().max(2048),
	newUserURL: z.string().max(2048).optional(),
	errorURL: z.string().max(2048).optional(),
	codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
	oauthState: z.string().optional(),
	expiresAt: z.number().int(),
	idTokenNonce: z.string().min(1).max(128).optional(),
	requestSignUp: z.boolean().optional(),
	serverContext: z.object({
		ssoProviderReference: ssoReferenceSchema,
		allauthSamlRequestId: z.string().optional(),
	}),
});
export type SsoState = z.infer<typeof ssoStateSchema>;
type SsoProviderReference = z.infer<typeof ssoReferenceSchema>;

type ProviderRow = {
	id: string;
	providerId: string;
	issuer: string;
	domain: string;
	domainVerified: boolean | null;
	organizationId: string | null;
	oidcConfig: string | null;
	samlConfig: string | null;
};
export type SsoProvider = Omit<ProviderRow, "oidcConfig" | "samlConfig"> & {
	oidcConfig?: Record<string, unknown>;
	samlConfig?: Record<string, unknown>;
};
export type SsoIdentity = {
	subject: string;
	email: string;
	name: string;
	image?: string;
	accessToken?: string;
	refreshToken?: string;
	idToken?: string;
	accessTokenExpiresAt?: Date;
	refreshTokenExpiresAt?: Date;
	scope?: string;
};
type Directory = { organizationId: string; connectionId: string };

function object(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function provider(row: ProviderRow | undefined): SsoProvider | null {
	if (
		!row ||
		(!row.oidcConfig && !row.samlConfig) ||
		row.domainVerified !== true ||
		!ssoProviderId.safeParse(row.providerId).success
	)
		return null;
	try {
		const oidcConfig = row.oidcConfig
			? object(JSON.parse(row.oidcConfig))
			: undefined;
		const samlConfig = row.samlConfig
			? object(JSON.parse(row.samlConfig))
			: undefined;
		if ((row.oidcConfig && !oidcConfig) || (row.samlConfig && !samlConfig))
			return null;
		return { ...row, oidcConfig, samlConfig };
	} catch {
		return null;
	}
}

function canonical(value: unknown): string {
	if (Array.isArray(value))
		return `[${value.map((item) => canonical(item ?? null)).join(",")}]`;
	const record = object(value);
	if (!record) return JSON.stringify(value);
	return `{${Object.keys(record)
		.sort()
		.filter((key) => record[key] !== undefined)
		.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
		.join(",")}}`;
}

function withoutPrivateMetadata(data: unknown) {
	const record = object(data);
	return {
		...record,
		privateKey: undefined,
		privateKeyPass: undefined,
		encPrivateKey: undefined,
		encPrivateKeyPass: undefined,
	};
}

/** The pre-cutover fingerprint excludes rotating client credentials and private SAML keys. */
export function ssoProviderReference(
	provider: SsoProvider,
): SsoProviderReference {
	const saml = provider.samlConfig;
	const fingerprint = createHash("sha256")
		.update(
			canonical({
				domain: provider.domain,
				domainVerified: provider.domainVerified,
				issuer: provider.issuer,
				organizationId: provider.organizationId,
				oidcConfig: provider.oidcConfig
					? { ...provider.oidcConfig, clientSecret: undefined }
					: undefined,
				samlConfig: saml
					? {
							...saml,
							privateKey: undefined,
							idpMetadata: withoutPrivateMetadata(saml.idpMetadata),
							spMetadata: saml.spMetadata
								? withoutPrivateMetadata(saml.spMetadata)
								: undefined,
						}
					: undefined,
			}),
		)
		.digest("base64url");
	return {
		providerId: provider.providerId,
		source: { type: "persisted", recordId: provider.id },
		authenticationConfigurationFingerprint: fingerprint,
	};
}

export function sameSsoProvider(
	provider: SsoProvider,
	expected: SsoProviderReference,
) {
	const current = ssoProviderReference(provider);
	return (
		current.providerId === expected.providerId &&
		current.source.recordId === expected.source.recordId &&
		current.authenticationConfigurationFingerprint ===
			expected.authenticationConfigurationFingerprint
	);
}

function scopedKey(parts: string[]) {
	return createHash("sha256").update(JSON.stringify(parts)).digest("base64url");
}

export function matchesSsoDomain(input: string, config: string) {
	const domain = input.trim().toLowerCase();
	return config
		.split(",")
		.map((name) => name.trim().toLowerCase())
		.some(
			(candidate) =>
				/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(candidate) &&
				(domain === candidate || domain.endsWith(`.${candidate}`)),
		);
}

/** Scoped state, provider and SCIM authority queries over the existing realm schema. */
export function createProjectSsoStore(
	database: Pool,
	schemaName: string,
	keys: LegacyMfaKeys,
	emailAliases?: Pick<OwnedProjectEmailAliases, "reserved">,
) {
	const schema =
		schemaName === "public" ? "public" : checkedProjectSchema(schemaName);
	const engine = createProjectEngineStore(database, schema);
	const columns =
		'id, "providerId", issuer, domain, "domainVerified", "organizationId", "oidcConfig", "samlConfig"';

	async function getProvider(providerId: string, transaction?: PoolClient) {
		const result = await (transaction ?? database).query<ProviderRow>(
			`SELECT ${columns} FROM "${schema}"."ssoProvider" WHERE "providerId" = $1${transaction ? " FOR UPDATE" : ""}`,
			[providerId],
		);
		return provider(result.rows[0]);
	}

	async function selectProvider(selector: {
		providerId?: string;
		organizationSlug?: string;
		domain?: string;
	}) {
		if (selector.providerId) return getProvider(selector.providerId);
		if (selector.organizationSlug) {
			const org = await database.query<{ id: string }>(
				`SELECT id FROM "${schema}"."organization" WHERE slug = $1`,
				[selector.organizationSlug],
			);
			if (org.rows[0]) {
				const result = await database.query<ProviderRow>(
					`SELECT ${columns} FROM "${schema}"."ssoProvider" WHERE "organizationId" = $1 ORDER BY id LIMIT 2`,
					[org.rows[0].id],
				);
				return result.rows.length === 1 ? provider(result.rows[0]) : null;
			}
		}
		if (!selector.domain) return null;
		const result = await database.query<ProviderRow>(
			`SELECT ${columns} FROM "${schema}"."ssoProvider" ORDER BY id`,
		);
		const domain = selector.domain;
		const exact = result.rows.filter((row) => row.domain === domain);
		const matches = exact.length
			? exact
			: result.rows.filter((row) => matchesSsoDomain(domain, row.domain));
		return matches.length === 1 ? provider(matches[0]) : null;
	}

	async function issue(
		state: string,
		flow: Omit<SsoState, "expiresAt" | "oauthState">,
	) {
		await database.query(
			`INSERT INTO "${schema}"."verification" (id, identifier, value, "expiresAt")
			VALUES ($1, $2, $3, statement_timestamp() + $4::int * interval '1 second')`,
			[
				randomUUID(),
				`auth-state:${state}`,
				JSON.stringify({
					...flow,
					oauthState: state,
					expiresAt: Date.now() + stateAge * 1000,
				}),
				stateAge,
			],
		);
	}

	async function consume(state: string, providerId: string) {
		return engine.transaction(async (client) => {
			const found = await client.query<{ id: string; value: string }>(
				`SELECT id, value FROM "${schema}"."verification" WHERE identifier = $1 AND "expiresAt" > clock_timestamp() ORDER BY id LIMIT 2 FOR UPDATE`,
				[`auth-state:${state}`],
			);
			if (found.rows.length !== 1) return null;
			const row = found.rows[0]!;
			let raw: unknown;
			try {
				raw = JSON.parse(row.value);
			} catch {
				return null;
			}
			const flow = ssoStateSchema.safeParse(raw);
			if (
				!flow.success ||
				flow.data.expiresAt <= Date.now() ||
				flow.data.serverContext.allauthSamlRequestId !== undefined ||
				(flow.data.oauthState !== undefined &&
					flow.data.oauthState !== state) ||
				flow.data.serverContext.ssoProviderReference.providerId !== providerId
			)
				return null;
			const removed = await client.query(
				`DELETE FROM "${schema}"."verification" WHERE id = $1 AND "expiresAt" > clock_timestamp()`,
				[row.id],
			);
			return removed.rowCount === 1 ? flow.data : null;
		});
	}

	async function directoryOwner(
		client: PoolClient,
		binding: Directory,
		subject: string,
	) {
		const { connectionId, organizationId } = binding;
		const domain = `organization:${organizationId}`;
		const externalKey = scopedKey([
			"scim-user-external-id",
			connectionId,
			subject,
		]);
		const connectionKey = scopedKey(["scim-connection", connectionId]);
		// Retirement changes the managed record before reconciling source projections.
		const connection = await client.query(
			`SELECT id FROM "${schema}"."scimManagedConnection" WHERE "connectionId" = $1 AND "provisioningDomainId" = $2 AND status = 'active' FOR SHARE`,
			[connectionId, domain],
		);
		if (connection.rowCount !== 1) return null;
		const source = await client.query<{ id: string; userId: string }>(
			`SELECT id, "userId" FROM "${schema}"."scimUser"
			WHERE "connectionId" = $1 AND "provisioningDomainId" = $2 AND "externalIdKey" = $3 AND "externalId" = $4 AND active`,
			[connectionId, domain, externalKey, subject],
		);
		const selected = source.rows[0];
		if (!selected) return null;
		// The existing SCIM writer locks the subject before changing its sources or local user.
		const revision = await client.query(
			`UPDATE "${schema}"."scimSubject" SET revision = revision + 1, "updatedAt" = statement_timestamp() WHERE "userId" = $1`,
			[selected.userId],
		);
		if (revision.rowCount !== 1) return null;
		const current = await client.query(
			`SELECT 1 FROM "${schema}"."scimUser" source
			WHERE source.id = $1 AND source."userId" = $2 AND source."connectionId" = $3 AND source."provisioningDomainId" = $4
			AND source."externalIdKey" = $5 AND source."externalId" = $6 AND source.active
			AND NOT EXISTS (SELECT 1 FROM "${schema}"."scimIdentityTombstone" t WHERE t."connectionId" = $3 AND t."externalIdKey" = $5 AND t."externalId" = $6)`,
			[
				selected.id,
				selected.userId,
				connectionId,
				domain,
				externalKey,
				subject,
			],
		);
		if (current.rowCount !== 1) return null;
		const user = await engine.lockUser(client, selected.userId);
		if (!user || user.directoryDisabled || user.banned || user.isAnonymous)
			return null;
		const fence = await client.query(
			`UPDATE "${schema}"."scimConnectionBinding" SET "decommissionRevision" = "decommissionRevision" + 1
			WHERE "connectionId" = $1 AND "connectionKey" = $2 AND "provisioningDomainId" = $3 AND "decommissionStatus" = 'active'`,
			[connectionId, connectionKey, domain],
		);
		return fence.rowCount === 1 ? user : null;
	}

	async function bind(
		client: PoolClient,
		current: SsoProvider,
		identity: SsoIdentity,
		signUpEnabled: boolean,
		protocol: "oidc" | "saml" = "oidc",
		denyProfile?: (
			email: string,
			action: "existing" | "signup",
		) => Promise<boolean>,
	) {
		const providerId = current.providerId;
		// OAuth and OIDC provider accounts share the existing subject namespace.
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", // cspell:ignore xact
			[`${schema}\n${providerId}\n${identity.subject}`],
		);
		const bindings = await client.query<Directory>(
			`SELECT "organizationId", "connectionId" FROM "${schema}"."allauthDirectory" WHERE "providerId" = $1 FOR UPDATE`,
			[providerId],
		);
		const directory = bindings.rows[0];
		if (directory && directory.organizationId !== current.organizationId)
			return "directory_provider_mismatch" as const;
		const result = await client.query<{ id: string; userId: string }>(
			`SELECT id, "userId" FROM "${schema}"."account" WHERE "providerId" = $1 AND "accountId" = $2 ORDER BY id LIMIT 2`,
			[providerId, identity.subject],
		);
		if (result.rows.length > 1) return "account_not_linked" as const;
		const account = result.rows[0];
		let registered = false;
		let user = directory
			? await directoryOwner(client, directory, identity.subject)
			: null;
		if (directory) {
			if (!user) return "directory_identity_inactive" as const;
			if (account && account.userId !== user.id)
				return "account_ownership_conflict" as const;
		} else if (account) {
			user = await engine.lockUser(client, account.userId);
		} else {
			const trustedDomain = matchesSsoDomain(
				identity.email.split("@")[1] ?? "",
				current.domain,
			);
			const existing = await client.query<{ id: string }>(
				`SELECT id FROM "${schema}"."user" WHERE email = $1`,
				[identity.email],
			);
			const id = existing.rows[0]?.id;
			if (id) {
				user = await engine.lockUser(client, id);
				if (
					!trustedDomain ||
					!user?.emailVerified ||
					user.email !== identity.email
				)
					return "account_not_linked" as const;
			} else {
				if (!signUpEnabled || !trustedDomain)
					return "account_not_linked" as const;
				if (await denyProfile?.(identity.email, "signup"))
					return ssoProfileRejected;
				if (emailAliases?.reserved(identity.email))
					return reservedProjectEmailError.code;
				const created = await client.query<{ id: string }>(
					`INSERT INTO "${schema}"."user" (id,email,name,image,"emailVerified","isAnonymous","twoFactorEnabled")
					VALUES ($1,$2,$3,$4,FALSE,FALSE,FALSE) ON CONFLICT (email) DO NOTHING RETURNING id`,
					[randomUUID(), identity.email, identity.name, identity.image ?? null],
				);
				if (!created.rows[0]) return "account_not_linked" as const;
				user = await engine.lockUser(client, created.rows[0].id);
				registered = true;
			}
		}
		if (
			!user ||
			user.banned ||
			user.directoryDisabled ||
			user.isAnonymous ||
			(!directory && user.directoryManaged)
		)
			return "account_not_linked" as const;
		if (!registered && (await denyProfile?.(identity.email, "existing")))
			return ssoProfileRejected;
		const path =
			protocol === "saml"
				? `/sso/saml2/sp/acs/${providerId}`
				: `/sso/callback/${providerId}`;
		const access = identity.accessToken
			? sealLegacyMfaRecord(identity.accessToken, keys)
			: (identity.accessToken ?? null);
		const refresh = identity.refreshToken
			? sealLegacyMfaRecord(identity.refreshToken, keys)
			: (identity.refreshToken ?? null);
		if (account) {
			const updated = await client.query(
				`UPDATE "${schema}"."account" SET "accessToken" = COALESCE($1,"accessToken"), "refreshToken" = COALESCE($2,"refreshToken"), "idToken" = COALESCE($3,"idToken"),
				"accessTokenExpiresAt" = COALESCE($4,"accessTokenExpiresAt"), "refreshTokenExpiresAt" = COALESCE($5,"refreshTokenExpiresAt"), "updatedAt" = statement_timestamp()
				WHERE id = $6 AND "providerId" = $7 AND "accountId" = $8 AND "userId" = $9`,
				[
					access,
					refresh,
					identity.idToken ?? null,
					identity.accessTokenExpiresAt ?? null,
					identity.refreshTokenExpiresAt ?? null,
					account.id,
					providerId,
					identity.subject,
					user.id,
				],
			);
			if (updated.rowCount !== 1) return "account_not_linked" as const;
		} else {
			const id = randomUUID();
			await client.query(
				`INSERT INTO "${schema}"."account" (id,"providerId","accountId","userId","accessToken","refreshToken","idToken","accessTokenExpiresAt","refreshTokenExpiresAt",scope,"updatedAt")
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,statement_timestamp())`,
				[
					id,
					providerId,
					identity.subject,
					user.id,
					access,
					refresh,
					identity.idToken ?? null,
					identity.accessTokenExpiresAt ?? null,
					identity.refreshTokenExpiresAt ?? null,
					identity.scope ?? null,
				],
			);
			if (registered)
				await engine.record(
					client,
					"user.created",
					"success",
					path,
					user.id,
					user.id,
				);
			await engine.record(
				client,
				"account.linked",
				"success",
				path,
				user.id,
				id,
			);
		}
		if (
			protocol === "oidc" &&
			!directory &&
			!registered &&
			current.oidcConfig?.overrideUserInfo === true
		) {
			const emailChanged = user.email !== identity.email;
			if (emailChanged) {
				if (
					!current.domainVerified ||
					!matchesSsoDomain(identity.email.split("@")[1] ?? "", current.domain)
				)
					return "account_not_linked" as const;
				if (emailAliases?.reserved(identity.email))
					return reservedProjectEmailError.code;
			}
			try {
				await client.query(
					`UPDATE "${schema}"."user"
					 SET name=$2, image=COALESCE($3,image), email=$4,
					     "emailVerified"=CASE WHEN email=$4 THEN "emailVerified" ELSE FALSE END,
					     "updatedAt"=statement_timestamp()
					 WHERE id=$1`,
					[user.id, identity.name, identity.image ?? null, identity.email],
				);
			} catch (error) {
				if (
					error instanceof DatabaseError &&
					error.code === "23505" &&
					error.constraint === "user_email_key"
				)
					return "account_not_linked" as const;
				throw error;
			}
			if (emailChanged) await invalidateProjectMailboxProofs(client, user.id);
			user = await engine.lockUser(client, user.id);
			if (!user) return "account_not_linked" as const;
			await engine.record(
				client,
				"user.updated",
				"success",
				"/sso/callback/:providerId",
				user.id,
				user.id,
			);
		}
		if (!directory && current.organizationId) {
			const realm = projectOrganizations(client);
			const org = await realm.organization(
				current.organizationId,
				"id",
				"write",
			);
			if (org) {
				await realm.lockMemberBudget(org.id);
				const membership = await realm.member(user.id, org.id, true);
				if (!membership) {
					const pending = await client.query(
						`SELECT 1 FROM "invitation" WHERE "organizationId" = $1 AND email = $2
						 AND status = 'pending' AND "expiresAt" > statement_timestamp() LIMIT 1`,
						[org.id, user.email.toLowerCase()],
					);
					if (!pending.rowCount)
						await realm.insertMember(org.id, user.id, "member");
				}
			}
		}
		return { user, registered, managed: Boolean(directory) };
	}

	return {
		getProvider,
		selectProvider,
		issue,
		consume,
		bind,
		transaction: engine.transaction,
	};
}
