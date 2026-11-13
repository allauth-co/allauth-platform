import type { AuthEnvironment } from "../configuration";
import { resolveHostedBinding } from "../domains/hosting";
import type { ProjectCustomSamlTransport } from "./owned-project-sso-saml-eligibility";
import { projectSamlAcs } from "./owned-project-sso-saml-management";
import type { Project } from "./registry";

/** SP metadata can name the exact project callback or an independently verified accounts host. */
export function createProjectCustomSamlTransport(
	project: Project,
	platform: string,
	env: AuthEnvironment,
): ProjectCustomSamlTransport {
	const direct = `${platform}/api/projects/${project.slug}/auth`;
	async function verifyAccountsOrigin(origin: string) {
		const url = new URL(origin);
		if (
			url.origin !== origin ||
			url.protocol !== "https:" ||
			url.port ||
			origin === platform
		)
			return false;
		const binding = await resolveHostedBinding(url.hostname, env);
		return (
			binding?.kind === "accounts" &&
			binding.hostname === url.hostname &&
			binding.project.id === project.id &&
			binding.project.schemaName === project.schemaName &&
			binding.project.workspaceId === project.workspaceId &&
			binding.project.environment === project.environment
		);
	}
	return {
		async authorizeAcs(value, providerId) {
			if (value === projectSamlAcs(direct, providerId)) return true;
			const url = new URL(value);
			return (
				value === projectSamlAcs(`${url.origin}/api/auth`, providerId) &&
				(await verifyAccountsOrigin(url.origin))
			);
		},
	};
}
