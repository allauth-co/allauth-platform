import * as z from "zod";
import { json } from "@/lib/api";
import { withAuth } from "@/lib/auth";
import {
	effectivePasswordPolicy,
	passwordPolicySchema,
} from "@/lib/auth-policy/password";
import { readPublicApplicationBranding } from "@/lib/branding/portal";
import {
	authConfiguration,
	authOrigin,
	projectEmailEnvironment,
} from "@/lib/configuration";
import { withPortalAuthEngine } from "@/lib/domains/hosting";
import { emailConfigured } from "@/lib/email/send";
import { publicBranding } from "@/sdk/branding";

const projectCapabilities = z.object({
	apple: z.boolean(),
	microsoft: z.boolean(),
	googleProvider: z.enum(["google", "allauth"]).nullable(),
	emailPassword: z.boolean(),
	signUpEnabled: z.boolean(),
	emailVerificationRequired: z.boolean(),
	passwordPolicy: passwordPolicySchema,
	apiKeys: z.boolean().optional(),
	enterpriseSSO: z.boolean().optional(),
	scim: z.boolean().optional(),
	branding: z.unknown().optional(),
});

export function GET(request: Request) {
	return withPortalAuthEngine(request, async (engine, env, _bound, binding) => {
		const available = authConfiguration(env);
		if (!binding) {
			return withAuth(async (instance) => {
				const password = instance.options.emailAndPassword;
				const social = instance.options.socialProviders;
				const apple = Boolean(social && "apple" in social && social.apple);
				const microsoft = Boolean(social?.microsoft);
				return json({
					...available,
					apple,
					appleProvider: apple ? "apple" : null,
					microsoft,
					microsoftProvider: microsoft ? "microsoft" : null,
					email: emailConfigured(projectEmailEnvironment(env)),
					emailPassword: password?.enabled !== false,
					signUpEnabled: password?.disableSignUp !== true,
					emailVerificationRequired:
						password?.requireEmailVerification !== false,
					passwordPolicy: effectivePasswordPolicy(instance.options),
					googleProvider: available.google ? "google" : null,
				});
			});
		}

		const response = await engine.dispatch(
			new Request(`https://${binding.hostname}/api/auth/sdk/config`, {
				headers: { accept: "application/json" },
			}),
		);
		const parsed = projectCapabilities.safeParse(
			response.ok ? await response.json().catch(() => null) : null,
		);
		if (!parsed.success)
			return json(
				{ error: "Project configuration is temporarily unavailable." },
				503,
			);
		const capability = parsed.data;
		const directGoogle = capability.googleProvider === "google";
		const googleProvider = directGoogle
			? "google"
			: available.google
				? "allauth"
				: null;
		const branding =
			publicBranding(capability.branding) ??
			(await readPublicApplicationBranding(binding.project.id, env));
		return json({
			...available,
			apiKeys: capability.apiKeys ?? available.apiKeys,
			enterpriseSSO: capability.enterpriseSSO ?? available.enterpriseSSO,
			scim: capability.scim ?? available.scim,
			apple: capability.apple,
			appleProvider: capability.apple ? "apple" : null,
			microsoft: capability.microsoft,
			microsoftProvider: capability.microsoft ? "microsoft" : null,
			email: emailConfigured(
				projectEmailEnvironment(env, binding.project.slug),
			),
			emailPassword: capability.emailPassword,
			signUpEnabled: capability.signUpEnabled,
			emailVerificationRequired: capability.emailVerificationRequired,
			passwordPolicy: capability.passwordPolicy,
			google: Boolean(googleProvider),
			googleProvider,
			github: false,
			broker: !directGoogle,
			realmName: branding.name,
			branding,
			platformOrigin: authOrigin(env),
		});
	});
}
