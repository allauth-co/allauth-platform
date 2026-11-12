import * as z from "zod";
import {
	encryptedSamlApprovalKind,
	encryptedSamlApprovalSetting,
	encryptedSamlConfigurationFingerprint,
	maximumSamlApprovalAge,
} from "../../scripts/project-engine-saml-approval.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import type { SsoProvider } from "./owned-project-sso-store";
import { ssoProviderId } from "./owned-project-sso-store";

export { encryptedSamlConfigurationFingerprint };
const profile = z.strictObject({
	cipher: z.enum(["aes128-gcm", "aes256-gcm"]),
	signatures: z.enum(["assertion", "response", "both"]),
});
const approvalSchema = z.strictObject({
	kind: z.literal(encryptedSamlApprovalKind),
	projectId: z.uuid(),
	schemaName: z.string().regex(/^allauth_project_[a-f0-9]{32}$/),
	providerId: ssoProviderId,
	providerRecordId: z.string().min(1).max(256),
	receiver: z.url().max(2048),
	configurationFingerprint: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
	legacyWriterRevision: z.number().int().min(0).max(2_147_483_646),
	policyRevision: z.string().regex(/^[A-Za-z0-9._:/-]{1,128}$/),
	verifiedAt: z.iso.datetime(),
	expiresAt: z.iso.datetime(),
	profiles: z.array(profile).min(1).max(6),
});

function invalidApproval(): never {
	throw new Error("The project encrypted SAML approval is unavailable.");
}

/** Parse deployment authority for exactly one pending or already active fenced revision. */
export function readProjectEncryptedSamlApproval(
	env: AuthEnvironment,
	binding: { id: string; schemaName: string },
	writer: { revision: number; preparing: boolean },
	now = Date.now,
) {
	const raw = setting(env, encryptedSamlApprovalSetting).trim();
	if (!raw) return undefined;
	if (raw.length > 8192) invalidApproval();
	let approval: z.infer<typeof approvalSchema>;
	try {
		approval = approvalSchema.parse(JSON.parse(raw));
	} catch {
		return invalidApproval();
	}
	const secret = setting(env, "ALLAUTH_AUTH_SECRET");
	const receiver = new URL(approval.receiver);
	const approved = Date.parse(approval.verifiedAt);
	const expiry = Date.parse(approval.expiresAt);
	const profiles = new Set(
		approval.profiles.map(
			({ cipher, signatures }) => `${cipher}:${signatures}`,
		),
	);
	function verifyRevision() {
		if (approved > now() || (writer.preparing && expiry <= now()))
			invalidApproval();
	}
	if (
		secret.length < 32 ||
		approval.projectId !== binding.id ||
		approval.schemaName !== binding.schemaName ||
		approval.legacyWriterRevision + (writer.preparing ? 0 : 1) !==
			writer.revision ||
		!Number.isFinite(approved) ||
		!Number.isFinite(expiry) ||
		expiry <= approved ||
		expiry - approved > maximumSamlApprovalAge ||
		receiver.protocol !== "https:" ||
		receiver.username ||
		receiver.password ||
		receiver.search ||
		receiver.hash ||
		receiver.href !== approval.receiver ||
		profiles.size !== approval.profiles.length
	)
		invalidApproval();
	verifyRevision();
	return Object.freeze({
		providerId: approval.providerId,
		receiver: approval.receiver,
		allowsResponseOnly: approval.profiles.some(
			({ signatures }) => signatures === "response",
		),
		assertProvider(provider: SsoProvider) {
			verifyRevision();
			if (
				provider.providerId !== approval.providerId ||
				provider.id !== approval.providerRecordId ||
				!provider.samlConfig ||
				provider.oidcConfig ||
				provider.domainVerified !== true ||
				encryptedSamlConfigurationFingerprint(
					secret,
					binding.id,
					binding.schemaName,
					approval.receiver,
					provider,
				) !== approval.configurationFingerprint
			)
				invalidApproval();
		},
		acceptsProfile(wire: {
			cipher: string;
			envelopeSigned: boolean;
			assertionSigned: boolean;
		}) {
			const signatures = wire.envelopeSigned
				? wire.assertionSigned
					? "both"
					: "response"
				: wire.assertionSigned
					? "assertion"
					: "unsigned";
			return profiles.has(`${wire.cipher}:${signatures}`);
		},
	});
}

export type ProjectEncryptedSamlApproval = NonNullable<
	ReturnType<typeof readProjectEncryptedSamlApproval>
>;

/** Confirm the current stored custom metadata and verified receiver for this approval. */
export async function configureApprovedProjectSaml(
	approval: ProjectEncryptedSamlApproval,
	provider: SsoProvider & { samlConfig: Record<string, unknown> },
	transport: ProjectCustomSamlTransport | undefined,
	relayState?: string,
) {
	approval.assertProvider(provider);
	if (!transport) invalidApproval();
	const selected = await configureProjectSamlTransport(
		provider,
		approval.receiver,
		{
			allowEncrypted: true,
			customTransport: transport,
			validateAll: true,
			relayState,
		},
	);
	if (
		!selected.custom ||
		selected.acs !== approval.receiver ||
		(selected.configured.wantAssertion && approval.allowsResponseOnly)
	)
		invalidApproval();
	return selected;
}
