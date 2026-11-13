import type { AuthEnvironment } from "./configuration";
import { authOrigin } from "./configuration";
import { discoveryDocument, discoveryHeaders } from "./discovery";
import {
	issuerAssertionAlgorithms,
	issuerDpopAlgorithms,
} from "./issuer-algorithms";

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

/** Build discovery using the canonical origin and the route-selected issuer. */
export function allAuthIssuerMetadata(options: {
	origin: string;
	issuer: string;
	endpoints: string;
}) {
	const { origin, issuer, endpoints } = options;
	return discoveryDocument({
		issuer,
		authorization_endpoint: `${endpoints}/oauth2/authorize`,
		token_endpoint: `${endpoints}/oauth2/token`,
		introspection_endpoint: `${endpoints}/oauth2/introspect`,
		revocation_endpoint: `${endpoints}/oauth2/revoke`,
		userinfo_endpoint: `${endpoints}/oauth2/userinfo`,
		end_session_endpoint: `${endpoints}/oauth2/end-session`,
		device_authorization_endpoint: `${endpoints}/device/code`,
		jwks_uri: `${endpoints}/jwks`,
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

/** The platform publishes its bare configured origin as its issuer. */
export function readPlatformIssuerMetadata(env: AuthEnvironment): Response {
	const origin = authOrigin(env);
	return Response.json(
		allAuthIssuerMetadata({
			origin,
			issuer: origin,
			endpoints: `${origin}/api/auth`,
		}),
		{ headers: discoveryHeaders },
	);
}
