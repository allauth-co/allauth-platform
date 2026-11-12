import {
	encryptedSamlConfigurationFingerprint,
	parseProjectEncryptedSamlApproval,
	samlApprovalIsCurrent,
} from "../../scripts/project-engine-saml-approval.mjs";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import type { SsoProvider } from "./owned-project-sso-store";
import type { ProjectEngineBinding } from "./project-engine-binding";
import { projectSamlApprovalValue } from "./project-engine-binding";

export { encryptedSamlConfigurationFingerprint };
function invalidApproval(): never {
	throw new Error("The project encrypted SAML approval is unavailable.");
}

/** Parse deployment authority for exactly one pending or already active fenced revision. */
export function readProjectEncryptedSamlApproval(
	env: AuthEnvironment,
	binding: ProjectEngineBinding,
	writer: { revision: number; preparing: boolean },
	now = Date.now,
) {
	const raw = projectSamlApprovalValue(binding, env);
	if (!raw) return undefined;
	const parsed = parseProjectEncryptedSamlApproval(raw, binding, writer, now());
	const secret = setting(env, "ALLAUTH_AUTH_SECRET");
	if (!parsed || secret.length < 32) invalidApproval();
	const { approval, profiles, verified, expires } = parsed;
	function verifyRevision() {
		if (!samlApprovalIsCurrent({ verified, expires }, writer.preparing, now()))
			invalidApproval();
	}
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
