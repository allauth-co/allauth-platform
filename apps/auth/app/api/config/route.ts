import { authConfiguration, authOrigin, projectEmailEnvironment } from "@/lib/configuration";
import { emailConfigured } from "@/lib/email/send";
import { json } from "@/lib/api";
import { withPortalRequest } from "@/lib/domains/hosting";
import { readPublicApplicationBranding } from "@/lib/branding/portal";
import { effectivePasswordPolicy } from "@/lib/auth-policy/password";

export async function GET(request: Request) {
	return withPortalRequest(request, async (instance, env, _bound, binding) => {
		const password = instance.options?.emailAndPassword;
		const social = instance.options.socialProviders;
		const appleEnabled = Boolean(social && "apple" in social && social.apple);
		const microsoftEnabled = Boolean(social?.microsoft);
		const configured = {
			...authConfiguration(env),
			apple: appleEnabled,
			appleProvider: appleEnabled ? "apple" : null,
			microsoft: microsoftEnabled,
			microsoftProvider: microsoftEnabled ? "microsoft" : null,
			email: emailConfigured(projectEmailEnvironment(env, binding?.project.slug)),
			emailPassword: password?.enabled !== false,
			signUpEnabled: password?.disableSignUp !== true,
			emailVerificationRequired: password?.requireEmailVerification !== false,
			passwordPolicy: effectivePasswordPolicy(instance.options),
		};
		if (!binding) return json({ ...configured, googleProvider: configured.google ? "google" : null });
		const branding = await readPublicApplicationBranding(binding.project.id, env);
		const directGoogle = Boolean(instance.options.socialProviders?.google);
		const googleProvider = directGoogle ? "google" : configured.google ? "allauth" : null;
		return json({ ...configured, google: Boolean(googleProvider), googleProvider, github: false, broker: !directGoogle, realmName: branding.name, branding, platformOrigin: authOrigin(env) });
	});
}
