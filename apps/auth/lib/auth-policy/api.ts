// cspell:words authorisation
import { APIError } from "better-auth";
import { isPlatformAdmin } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import type { AuthPolicy, StoredAuthPolicy } from "./policy";
import { authPolicyUpdateSchema } from "./policy";

export interface ConfigurationScope {
	type: "platform" | "project";
	id: string;
	name: string;
	slug?: string;
	schemaName: string;
	origins?: string[];
	primaryOrigin?: string;
}
export interface ConfigurationProviders {
	apple?: boolean;
	google: boolean;
	github: boolean;
	microsoft: boolean;
	email: boolean;
}
export interface ConfigurationDependencies {
	origin: string;
	authorize: (
		headers: Headers,
		scope: ConfigurationScope,
	) => Promise<ControlPrincipal | null>;
	resolveScope: (project?: string) => Promise<ConfigurationScope>;
	read: (id: string) => Promise<StoredAuthPolicy>;
	update: (
		id: string,
		version: number,
		policy: AuthPolicy,
		actorId: string,
		scope: ConfigurationScope,
	) => Promise<StoredAuthPolicy>;
	providers: (
		scope: ConfigurationScope,
	) => ConfigurationProviders | Promise<ConfigurationProviders>;
	unenrolledUsers: (scope: ConfigurationScope) => Promise<number>;
	ownerCanLogin: (
		ownerId: string,
		policy: AuthPolicy,
		providers: ConfigurationProviders,
	) => Promise<boolean>;
	serializeWrite?: (
		scope: ConfigurationScope,
		actor: ControlPrincipal,
		work: (locked: ConfigurationDependencies) => Promise<Response>,
	) => Promise<Response>;
}
async function boundedBody(request: Request) {
	const declared = request.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > 4096))
		throw new APIError("PAYLOAD_TOO_LARGE");
	const reader = request.body?.getReader();
	if (!reader) throw new APIError("BAD_REQUEST");
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		for (;;) {
			const result = await reader.read();
			if (result.done) break;
			length += result.value.byteLength;
			if (length > 4096) {
				void reader.cancel().catch(() => {});
				throw new APIError("PAYLOAD_TOO_LARGE");
			}
			chunks.push(result.value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	try {
		return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
	} catch {
		throw new APIError("BAD_REQUEST", {
			message: "Provide a valid settings document.",
		});
	}
}
async function configurationResponse(
	request: Request,
	scope: ConfigurationScope,
	owner: ControlPrincipal,
	dependencies: ConfigurationDependencies,
): Promise<Response> {
	const providers = await dependencies.providers(scope);
	let stored: StoredAuthPolicy;
	if (request.method === "PATCH") {
		if (
			request.headers.get("origin") !== dependencies.origin ||
			request.headers.get("sec-fetch-site") === "cross-site"
		)
			throw new APIError("FORBIDDEN");
		const input = authPolicyUpdateSchema.parse(await boundedBody(request));
		if (
			input.policy.supportAccess &&
			(scope.type !== "project" ||
				!scope.origins?.includes(
					new URL(input.policy.supportAccess.callbackUrl).origin,
				))
		)
			throw new APIError("BAD_REQUEST", {
				message:
					"Connected support requires a callback on one of this application's registered origins.",
			});
		const support = input.policy.supportAccess;
		const application = support?.applicationInitiated;
		if (
			application &&
			(scope.type !== "project" ||
				new URL(application.authorizeUrl).origin !== scope.primaryOrigin ||
				new URL(application.returnUrl).origin !== scope.primaryOrigin ||
				new URL(support!.callbackUrl).hostname ===
					new URL(scope.primaryOrigin!).hostname ||
				(application.enabled && !support!.enabled))
		)
			throw new APIError("BAD_REQUEST", {
				message:
					"Application support requires the fixed primary-app authorisation and return URLs and a separate registered support hostname.",
			});
		if (
			!input.policy.emailAndPasswordEnabled &&
			!providers.google &&
			!providers.apple &&
			!providers.github &&
			!providers.microsoft
		)
			throw new APIError("BAD_REQUEST", {
				message: "Keep at least one configured sign-in method enabled.",
			});
		if (
			scope.type === "platform" &&
			!(await dependencies.ownerCanLogin(
				owner.user.id,
				input.policy,
				providers,
			))
		)
			throw new APIError("BAD_REQUEST", {
				message:
					"Keep a configured sign-in method linked to your administrator account.",
			});
		if (
			input.policy.mfaMode === "required" &&
			(await dependencies.unenrolledUsers(scope)) > 0
		)
			throw new APIError("BAD_REQUEST", {
				message:
					"Enroll every active account in MFA before requiring it. New public sign-ups must remain disabled.",
			});
		stored = await dependencies.update(
			scope.id,
			input.version,
			input.policy,
			owner.user.id,
			scope,
		);
	} else if (request.method === "GET")
		stored = await dependencies.read(scope.id);
	else throw new APIError("METHOD_NOT_ALLOWED");
	const { schemaName: _schemaName, origins: _origins, ...publicScope } = scope;
	return Response.json(
		{
			scope: publicScope,
			...stored,
			providers,
			capabilities: {
				passkeys: true,
				twoFactor: true,
				organizations: true,
				enterpriseSSO: true,
				sms: false,
				requiredMFA: true,
				requiredMFANeedsEnrollment: true,
				verificationPolicyAppliesTo: "sign-in",
				accountSecurityRequiresVerifiedEmail: true,
				organizationCreationRequiresVerifiedEmail: true,
				sessionExpiryAppliesTo: "new-and-refreshed-sessions",
				providerConfiguration: "environment",
			},
		},
		{ headers: { "cache-control": "no-store", pragma: "no-cache" } },
	);
}
/** Root cookie authority is freshly checked against the selected workspace; platform settings additionally require a platform administrator. */
export function configurationHandler(dependencies: ConfigurationDependencies) {
	return async (request: Request): Promise<Response> => {
		if (request.headers.has("authorization")) throw new APIError("FORBIDDEN");
		const scope = await dependencies.resolveScope(
			new URL(request.url).searchParams.get("project") || undefined,
		);
		const owner = await dependencies.authorize(request.headers, scope);
		if (!owner) throw new APIError("UNAUTHORIZED");
		if (
			!owner.user.emailVerified ||
			owner.user.banned ||
			owner.session.impersonatedBy ||
			(scope.type === "platform" && !isPlatformAdmin(owner.user, owner.session))
		)
			throw new APIError("FORBIDDEN");
		if (request.method === "PATCH" && dependencies.serializeWrite)
			return dependencies.serializeWrite(scope, owner, (locked) =>
				configurationResponse(request, scope, owner, locked),
			);
		return configurationResponse(request, scope, owner, dependencies);
	};
}
