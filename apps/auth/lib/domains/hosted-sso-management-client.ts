import * as z from "zod";
import { hostedAccountRequest } from "./hosted-account-transport";

const providers = z.object({
	providers: z.array(
		z.object({
			providerId: z.string(),
			type: z.enum(["oidc", "saml"]),
			issuer: z.string(),
			domain: z.string(),
			domainVerified: z.boolean(),
			organizationId: z.string().nullable(),
			spMetadataUrl: z.string(),
			samlConfig: z.object({ entryPoint: z.string().nullish() }).nullish(),
		}),
	),
});
const registration = z.object({
	domainVerificationToken: z.string().optional(),
});
const challenge = z.object({ domainVerificationToken: z.string() });

async function operation<T>(
	path: Parameters<typeof hostedAccountRequest>[0],
	schema: z.ZodType<T>,
	body?: object,
) {
	try {
		return {
			data: schema.parse(await hostedAccountRequest(path, body)),
			error: null,
		};
	} catch (error) {
		return {
			data: null,
			error: {
				message:
					error instanceof Error
						? error.message
						: "Unable to update the identity provider.",
			},
		};
	}
}

export const hostedSsoManagementClient = {
	providers: () => operation("sso/providers", providers),
	register: (body: object) => operation("sso/register", registration, body),
	updateProvider: (body: object) =>
		operation("sso/update-provider", z.unknown(), body),
	requestDomainVerification: (body: object) =>
		operation("sso/request-domain-verification", challenge, body),
	verifyDomain: (body: object) =>
		operation("sso/verify-domain", z.unknown(), body),
	deleteProvider: (body: object) =>
		operation("sso/delete-provider", z.unknown(), body),
};
