import { createHmac } from "node:crypto";

export const encryptedSamlApprovalSetting =
	"ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL";
export const encryptedSamlApprovalKind =
	"operator-verified-encrypted-saml-policy-v1";
export const maximumSamlApprovalAge = 7 * 24 * 60 * 60 * 1000;

/** @param {unknown} value @returns {unknown} */
function canonical(value) {
	if (Array.isArray(value)) return value.map(canonical);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => [key, canonical(item)]),
	);
}

/**
 * @param {string} secret
 * @param {string} projectId
 * @param {string} schemaName
 * @param {string} receiver
 * @param {{id:string,providerId:string,issuer:string,domain:string,domainVerified:boolean|null,organizationId:string|null,samlConfig?:Record<string,unknown>}} provider
 */
export function encryptedSamlConfigurationFingerprint(
	secret,
	projectId,
	schemaName,
	receiver,
	provider,
) {
	return createHmac("sha256", secret)
		.update("allauth:encrypted-saml-configuration:v1\n")
		.update(
			JSON.stringify([
				projectId,
				schemaName,
				receiver,
				provider.id,
				provider.providerId,
				provider.issuer,
				provider.domain,
				provider.domainVerified === true,
				provider.organizationId ?? null,
				canonical(provider.samlConfig),
			]),
		)
		.digest("base64url");
}

function approvalWindow(raw, projectId, schemaName, revision) {
	try {
		if (raw.length > 8192) throw new Error();
		const approval = JSON.parse(raw);
		const now = Date.now();
		const verified = Date.parse(approval.verifiedAt);
		const expires = Date.parse(approval.expiresAt);
		if (
			approval.kind === encryptedSamlApprovalKind &&
			approval.projectId === projectId &&
			approval.schemaName === schemaName &&
			approval.legacyWriterRevision === revision &&
			typeof approval.policyRevision === "string" &&
			/^[A-Za-z0-9._:/-]{1,128}$/.test(approval.policyRevision) &&
			Array.isArray(approval.profiles) &&
			approval.profiles.length > 0 &&
			approval.profiles.length <= 6 &&
			approval.profiles.every(
				({ cipher, signatures }) =>
					["aes128-gcm", "aes256-gcm"].includes(cipher) &&
					["assertion", "response", "both"].includes(signatures),
			) &&
			verified <= now &&
			now < expires &&
			expires - verified <= maximumSamlApprovalAge
		)
			return approval;
	} catch {
		// Keep private deployment inputs out of the operator error.
	}
	throw new Error(
		"The project encrypted SAML approval is outside its activation window.",
	);
}

function configuredEncryption(config) {
	if (!config || typeof config !== "object" || Array.isArray(config))
		throw new Error();
	return [config.idpMetadata, config.spMetadata].some(
		(metadata) =>
			metadata &&
			(metadata.isAssertionEncrypted ||
				metadata.encPrivateKey ||
				metadata.encPrivateKeyPass),
	);
}

async function verifyActivationReceiver(client, projectId, approval, env) {
	const receiver = new URL(approval.receiver);
	if (
		receiver.protocol !== "https:" ||
		receiver.href !== approval.receiver ||
		receiver.username ||
		receiver.password ||
		receiver.search ||
		receiver.hash
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const {
		rows: [project],
	} = await client.query(
		`SELECT slug FROM public."allauthProject" WHERE id=$1 FOR SHARE`,
		[projectId],
	);
	const path = `/sso/saml2/sp/acs/${encodeURIComponent(approval.providerId)}`;
	const currentOrigin = env.ALLAUTH_AUTH_URL;
	const legacyOrigin = env.BETTER_AUTH_URL;
	const platform = currentOrigin ?? legacyOrigin ?? "https://allauth.co";
	if (
		currentOrigin != null &&
		legacyOrigin != null &&
		currentOrigin !== legacyOrigin
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	if (
		project &&
		receiver.origin === new URL(platform).origin &&
		receiver.pathname === `/api/projects/${project.slug}/auth${path}`
	)
		return;
	if (
		!project ||
		receiver.port ||
		receiver.origin === new URL(platform).origin ||
		receiver.pathname !== `/api/auth${path}` ||
		env.CLOUDFLARE_SAAS_READY !== "true" ||
		(env.ALLAUTH_EDGE_SECRET?.length ?? 0) < 32
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const base = (env.ALLAUTH_HOSTING_BASE_DOMAIN || "allauth.co")
		.trim()
		.toLowerCase();
	if (receiver.hostname === `${project.slug}-accounts.${base}`) return;
	if (
		!/^[a-f0-9]{32}$/.test(env.CLOUDFLARE_SAAS_ZONE_ID ?? "") ||
		!env.CLOUDFLARE_SAAS_API_TOKEN ||
		!env.CLOUDFLARE_SAAS_CNAME_TARGET
	)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
	const { rowCount } = await client.query(
		`SELECT 1 FROM public."allauthCustomHostname" h
		 JOIN public."allauthDomainPair" d ON d.id=h."pairId" AND d."projectId"=h."projectId"
		 WHERE h.hostname=$1 AND h."projectId"=$2 AND h.kind='accounts' AND d.deleting=false
		 AND (SELECT count(*) FROM public."allauthCustomHostname" s WHERE s."pairId"=d.id
		   AND s."ownershipVerifiedAt" IS NOT NULL AND s."providerStatus"='active' AND s."sslStatus"='active'
		   AND s."routingVerifiedAt" IS NOT NULL AND s."lastIssue" IS NULL)=2 FOR SHARE OF h,d`,
		[receiver.hostname, projectId],
	);
	if (!rowCount)
		throw new Error("The approved encrypted SAML receiver is unavailable.");
}

/** Recheck the approved SAML row under the protected writer's exclusive admission lock. */
export async function verifyEncryptedSamlActivation(
	client,
	projectId,
	schemaName,
	revision,
	env,
) {
	if (
		!/^allauth_project_[a-f0-9]{32}$/.test(schemaName) ||
		schemaName !== `allauth_project_${projectId.replaceAll("-", "")}`
	)
		throw new Error("The protected encrypted SAML realm is unavailable.");
	const { rows } = await client.query(
		`SELECT id,"providerId",issuer,domain,"domainVerified","organizationId","oidcConfig","samlConfig"
		 FROM "${schemaName}"."ssoProvider" WHERE "samlConfig" IS NOT NULL FOR SHARE`,
	);
	let encrypted;
	try {
		encrypted = rows
			.map((row) => ({ ...row, samlConfig: JSON.parse(row.samlConfig) }))
			.filter((row) => configuredEncryption(row.samlConfig));
	} catch {
		throw new Error("The stored project SAML configuration is unavailable.");
	}
	const raw = env[encryptedSamlApprovalSetting]?.trim();
	if (!raw && !encrypted.length) return;
	if (!raw)
		throw new Error(
			"The stored encrypted SAML provider requires deployment approval.",
		);
	const approval = approvalWindow(raw, projectId, schemaName, revision);
	const [provider] = encrypted;
	const currentSecret = env.ALLAUTH_AUTH_SECRET;
	const legacySecret = env.BETTER_AUTH_SECRET;
	const secret = currentSecret ?? legacySecret;
	if (
		encrypted.length !== 1 ||
		!secret ||
		secret.length < 32 ||
		(currentSecret != null &&
			legacySecret != null &&
			currentSecret !== legacySecret) ||
		provider.id !== approval.providerRecordId ||
		provider.providerId !== approval.providerId ||
		!provider.domainVerified ||
		provider.oidcConfig ||
		provider.samlConfig.issuer !== provider.issuer ||
		provider.samlConfig.idpMetadata?.isAssertionEncrypted !== true ||
		typeof provider.samlConfig.spMetadata?.metadata !== "string" ||
		!provider.samlConfig.spMetadata?.encPrivateKey ||
		(provider.samlConfig.wantAssertionsSigned === true &&
			approval.profiles.some(({ signatures }) => signatures === "response")) ||
		typeof approval.receiver !== "string" ||
		encryptedSamlConfigurationFingerprint(
			secret,
			projectId,
			schemaName,
			approval.receiver,
			provider,
		) !== approval.configurationFingerprint
	)
		throw new Error(
			"The stored encrypted SAML provider does not match deployment approval.",
		);
	await verifyActivationReceiver(client, projectId, approval, env);
	approvalWindow(raw, projectId, schemaName, revision);
}
