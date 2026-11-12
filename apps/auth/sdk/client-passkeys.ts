import {
	startAuthentication,
	startRegistration,
	WebAuthnAbortService,
	WebAuthnError,
} from "@simplewebauthn/browser";
import type {
	AuthenticationResponseJSON,
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
	RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import type { ClientQueryOptions, ClientResult } from "./client-query";

type FetchOptions = Pick<ClientQueryOptions, "headers" | "signal">;
type PasskeyRequest = <T>(
	endpoint: string,
	options?: ClientQueryOptions & { body?: object },
) => Promise<ClientResult<T>>;
type PasskeyOptions = {
	extensions?: PublicKeyCredentialCreationOptionsJSON["extensions"];
	returnWebAuthnResponse?: boolean;
	fetchOptions?: FetchOptions;
};

export type AllAuthPasskey = {
	id: string;
	name?: string | null;
	publicKey: string;
	userId: string;
	credentialID: string;
	counter: number;
	deviceType: string;
	backedUp: boolean;
	transports?: string | null;
	createdAt?: string | null;
	aaguid?: string | null;
};

function passkeyResult<
	T,
	R extends AuthenticationResponseJSON | RegistrationResponseJSON,
>(
	result: ClientResult<T>,
	response: R,
	includeResponse?: boolean,
): ClientResult<T> & {
	webauthn?: {
		response: R;
		clientExtensionResults: R["clientExtensionResults"];
	};
} {
	return includeResponse
		? {
				...result,
				webauthn: {
					response,
					clientExtensionResults: response.clientExtensionResults,
				},
			}
		: result;
}

let activeCeremony: symbol | undefined;

async function runCeremony<T>(
	signal: AbortSignal | undefined,
	start: () => Promise<T>,
): Promise<T> {
	signal?.throwIfAborted();
	const ceremony = Symbol();
	activeCeremony = ceremony;
	const cancel = () => {
		if (activeCeremony === ceremony) WebAuthnAbortService.cancelCeremony();
	};
	signal?.addEventListener("abort", cancel, { once: true });
	try {
		const result = await start();
		signal?.throwIfAborted();
		return result;
	} finally {
		signal?.removeEventListener("abort", cancel);
		if (activeCeremony === ceremony) activeCeremony = undefined;
	}
}

function registrationError(
	cause: unknown,
	signal: AbortSignal | undefined,
): ClientResult<never> {
	if (signal?.aborted) {
		return {
			data: null,
			error: {
				code: "ERROR_CEREMONY_ABORTED",
				message: "Registration cancelled",
				status: 400,
				statusText: "BAD_REQUEST",
			},
		};
	}
	if (cause instanceof WebAuthnError) {
		const message =
			cause.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED"
				? "Previously registered"
				: cause.code === "ERROR_CEREMONY_ABORTED"
					? "Registration cancelled"
					: cause.message;
		return {
			data: null,
			error: {
				code: cause.code,
				message,
				status: 400,
				statusText: "BAD_REQUEST",
			},
		};
	}
	return {
		data: null,
		error: {
			code: "UNKNOWN_ERROR",
			message: cause instanceof Error ? cause.message : "Unknown error",
			status: 500,
			statusText: "INTERNAL_SERVER_ERROR",
		},
	};
}

export function createPasskeyActions<Session>(request: PasskeyRequest) {
	return {
		signInPasskey: async (
			options?: PasskeyOptions & { autoFill?: boolean },
			fetchOptions?: FetchOptions,
		) => {
			const requestOptions = { ...options?.fetchOptions, ...fetchOptions };
			const challenge = await request<PublicKeyCredentialRequestOptionsJSON>(
				"passkey/generate-authenticate-options",
				requestOptions,
			);
			if (!challenge.data) return { data: null, error: challenge.error };
			const optionsJSON = challenge.data;
			let assertion: AuthenticationResponseJSON;
			try {
				assertion = await runCeremony(requestOptions.signal, () =>
					startAuthentication({
						optionsJSON: {
							...optionsJSON,
							extensions:
								optionsJSON.extensions || options?.extensions
									? { ...optionsJSON.extensions, ...options?.extensions }
									: undefined,
						},
						useBrowserAutofill: options?.autoFill,
					}),
				);
			} catch (cause) {
				return {
					data: null,
					error: {
						code:
							!requestOptions.signal?.aborted && cause instanceof WebAuthnError
								? cause.code
								: "AUTH_CANCELLED",
						message: "Auth cancelled",
						status: 400,
						statusText: "BAD_REQUEST",
					},
				};
			}
			const { clientExtensionResults: _extensionResults, ...response } =
				assertion;
			const result = await request<Session>("passkey/verify-authentication", {
				...requestOptions,
				body: { response },
			});
			return passkeyResult(result, assertion, options?.returnWebAuthnResponse);
		},
		addPasskey: async (
			options?: PasskeyOptions & {
				name?: string;
				authenticatorAttachment?: "platform" | "cross-platform";
				context?: string | null;
				createSession?: boolean;
				useAutoRegister?: boolean;
			},
			fetchOptions?: FetchOptions,
		) => {
			const requestOptions = { ...options?.fetchOptions, ...fetchOptions };
			const challenge = await request<PublicKeyCredentialCreationOptionsJSON>(
				"passkey/generate-register-options",
				{
					...requestOptions,
					query: {
						authenticatorAttachment: options?.authenticatorAttachment,
						name: options?.name || undefined,
						context: options?.context || undefined,
					},
				},
			);
			if (!challenge.data) return { data: null, error: challenge.error };
			const optionsJSON = challenge.data;
			try {
				const attestation = await runCeremony(requestOptions.signal, () =>
					startRegistration({
						optionsJSON: {
							...optionsJSON,
							extensions:
								optionsJSON.extensions || options?.extensions
									? { ...optionsJSON.extensions, ...options?.extensions }
									: undefined,
						},
						useAutoRegister: options?.useAutoRegister,
					}),
				);
				const { clientExtensionResults: _extensionResults, ...response } =
					attestation;
				const result = await request<AllAuthPasskey & Partial<Session>>(
					"passkey/verify-registration",
					{
						...requestOptions,
						body: {
							response,
							name: options?.name,
							...(options?.createSession && { createSession: true }),
						},
					},
				);
				return result.data
					? passkeyResult(result, attestation, options?.returnWebAuthnResponse)
					: result;
			} catch (cause) {
				return registrationError(cause, requestOptions.signal);
			}
		},
	};
}
