import { discoveryDocument } from "../discovery";
import { issuerAssertionAlgorithms } from "./owned-project-issuer-client";
import { issuerDpopAlgorithms } from "./owned-project-issuer-dpop";
import { projectOrigin, projectSlug } from "./validation";

const scopes = [
	"openid",
	"profile",
	"email",
	"offline_access",
	"organization:read",
];
const grantTypes = [
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:device_code",
];
const clientAuthMethods = [
	"client_secret_basic",
	"client_secret_post",
	"private_key_jwt",
];

/** Discovery for a project issuer with an origin already selected by the ingress. */
export function ownedProjectIssuerMetadata(options: {
	origin: string;
	basePath: string;
	slug: string;
}) {
	const origin = projectOrigin.parse(options.origin);
	const slug = projectSlug.parse(options.slug);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid project issuer path.");
	const issuer = origin + options.basePath;

	return discoveryDocument({
		issuer,
		authorization_endpoint: `${issuer}/oauth2/authorize`,
		token_endpoint: `${issuer}/oauth2/token`,
		introspection_endpoint: `${issuer}/oauth2/introspect`,
		revocation_endpoint: `${issuer}/oauth2/revoke`,
		userinfo_endpoint: `${issuer}/oauth2/userinfo`,
		end_session_endpoint: `${issuer}/oauth2/end-session`,
		device_authorization_endpoint: `${issuer}/device/code`,
		jwks_uri: `${issuer}/jwks`,
		scopes_supported: [...scopes],
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: [...grantTypes],
		token_endpoint_auth_methods_supported: [...clientAuthMethods],
		token_endpoint_auth_signing_alg_values_supported: [
			...issuerAssertionAlgorithms,
		],
		introspection_endpoint_auth_methods_supported: [...clientAuthMethods],
		introspection_endpoint_auth_signing_alg_values_supported: [
			...issuerAssertionAlgorithms,
		],
		revocation_endpoint_auth_methods_supported: [...clientAuthMethods],
		revocation_endpoint_auth_signing_alg_values_supported: [
			...issuerAssertionAlgorithms,
		],
		code_challenge_methods_supported: ["S256"],
		authorization_response_iss_parameter_supported: true,
		dpop_signing_alg_values_supported: [...issuerDpopAlgorithms],
		backchannel_logout_supported: true,
		backchannel_logout_session_supported: true,
		claims_supported: [
			"sub",
			"name",
			"email",
			"email_verified",
			"act",
			`${origin}/impersonated_by`,
			`${origin}/organization_id`,
			`${origin}/organization_role`,
		],
		claims_parameter_supported: true,
		subject_types_supported: ["public"],
		acr_values_supported: ["0"],
		id_token_signing_alg_values_supported: ["RS256"],
		request_parameter_supported: false,
		request_uri_parameter_supported: false,
		prompt_values_supported: [
			"login",
			"consent",
			"create",
			"select_account",
			"none",
		],
	});
}
